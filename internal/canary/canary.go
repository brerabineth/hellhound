// Package canary generates and manages decoy files with high-value-looking
// names and plausible binary signatures. The value of a decoy is in its name,
// its location and its metadata; ransomware enumerates by pattern, not by
// parsing documents. Every decoy embeds a unique token so any later leak,
// ransom note or sample can be attributed back to the exact machine and file.
package canary

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Kind identifies a decoy class.
type Kind string

const (
	KindDoc    Kind = "doc"
	KindSheet  Kind = "sheet"
	KindDB     Kind = "db"
	KindWallet Kind = "wallet"
	KindKdbx   Kind = "kdbx"
	KindEnv    Kind = "env"
	KindKey    Kind = "key"
	KindSeed   Kind = "seed"
)

// AllKinds is the full set of decoy classes hellhound knows how to generate.
var AllKinds = []Kind{KindDoc, KindSheet, KindDB, KindWallet, KindKdbx, KindEnv, KindKey, KindSeed}

// Canary describes one planted decoy.
type Canary struct {
	Path    string
	Kind    Kind
	Profile string
	Token   string
	SHA256  string
	Size    int64
}

var (
	docNames    = []string{"Invoice", "Contract", "Statement", "Purchase_Order", "Receipt", "Wire_Transfer"}
	sheetNames  = []string{"payroll", "budget_2026", "q4_forecast", "headcount", "commissions"}
	dbNames     = []string{"customers", "users_prod", "payments", "inventory", "sessions"}
	walletNames = []string{"wallet", "wallet_old", "btc_wallet", "cold_storage"}
	kdbxNames   = []string{"passwords", "vault", "credentials", "ops_passwords"}
	seedWords   = []string{
		"abandon", "ability", "absurd", "access", "acid", "across", "action", "admit",
		"adult", "advance", "agent", "album", "alert", "alien", "alpha", "amber",
		"ancient", "angle", "animal", "answer", "apple", "arctic", "armor", "arrow",
		"aspect", "assign", "athlete", "atom", "audit", "august", "author", "autumn",
		"avocado", "axis", "bacon", "badge", "balcony", "bamboo", "banner", "barrel",
	}
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("canary: entropy unavailable: " + err.Error())
	}
	return b
}

func token() string {
	b := randBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

func pick(list []string) string { return list[randInt(len(list))] }

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	b := randBytes(2)
	return (int(b[0])<<8 | int(b[1])) % n
}

// Filename returns a realistic file name for the given decoy class.
func Filename(k Kind) string {
	stamp := time.Now().AddDate(0, 0, -randInt(21)).Format("2006-01-02")
	serial := fmt.Sprintf("%04d", randInt(10000))
	switch k {
	case KindDoc:
		return fmt.Sprintf("%s_%s_%s.doc", pick(docNames), stamp, serial)
	case KindSheet:
		return fmt.Sprintf("%s_%s.xlsx", pick(sheetNames), stamp)
	case KindDB:
		return fmt.Sprintf("%s_dump_%s.sql.db", pick(dbNames), serial)
	case KindWallet:
		return fmt.Sprintf("%s.dat", pick(walletNames))
	case KindKdbx:
		return fmt.Sprintf("%s_%s.kdbx", pick(kdbxNames), serial)
	case KindEnv:
		return ".env"
	case KindKey:
		return "id_rsa_backup"
	case KindSeed:
		return "recovery_seed.txt"
	}
	return "decoy.bin"
}

// header is the plaintext marker embedded in text-based decoys.
func header(k Kind, tok string) string {
	return fmt.Sprintf("HELLHOUND-CANARY v1 kind=%s token=%s\ntime=%s\n",
		k, tok, time.Now().UTC().Format(time.RFC3339))
}

// Content builds the decoy payload. Binary classes carry correct magic bytes
// so they survive casual inspection with file(1) or a hexdump.
func Content(k Kind, tok string) []byte {
	tokBytes := []byte("hellhound:" + tok)
	switch k {
	case KindDoc: // OLE2 compound document magic
		var b []byte
		b = append(b, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
		b = append(b, tokBytes...)
		b = append(b, randBytes(4096+randInt(2048))...)
		return b
	case KindSheet: // ZIP local file header (xlsx container family)
		var b []byte
		b = append(b, 'P', 'K', 0x03, 0x04)
		b = append(b, tokBytes...)
		b = append(b, randBytes(3072+randInt(1024))...)
		return b
	case KindDB: // SQLite 3 header
		var b []byte
		b = append(b, []byte("SQLite format 3\x00")...)
		b = append(b, tokBytes...)
		b = append(b, randBytes(8192+randInt(4096))...)
		return b
	case KindWallet:
		var b []byte
		b = append(b, randBytes(16)...)
		b = append(b, tokBytes...)
		b = append(b, randBytes(512)...)
		return b
	case KindKdbx: // KeePass 2.x signature
		var b []byte
		b = append(b, 0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0x5B, 0x03, 0x00, 0x01, 0x00)
		b = append(b, tokBytes...)
		b = append(b, randBytes(2048+randInt(1024))...)
		return b
	case KindEnv:
		var sb strings.Builder
		sb.WriteString(header(k, tok))
		sb.WriteString("# production environment - do not commit\n")
		sb.WriteString("DB_HOST=10." + itoa(randInt(254)) + "." + itoa(randInt(254)) + ".11\n")
		sb.WriteString("DB_USER=svc_app\n")
		sb.WriteString("DB_PASS='" + hex.EncodeToString(randBytes(12)) + "'\n")
		sb.WriteString("REDIS_URL=redis://cache.internal:6379/0\n")
		sb.WriteString("STRIPE_SECRET_KEY=sk_live_" + hex.EncodeToString(randBytes(16)) + "\n")
		sb.WriteString("SMTP_PASS=" + hex.EncodeToString(randBytes(10)) + "\n")
		return []byte(sb.String())
	case KindKey:
		var sb strings.Builder
		sb.WriteString(header(k, tok))
		sb.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
		body := hex.EncodeToString(randBytes(48))
		for i := 0; i < len(body); i += 64 {
			end := i + 64
			if end > len(body) {
				end = len(body)
			}
			sb.WriteString(body[i:end] + "\n")
		}
		sb.WriteString("-----END OPENSSH PRIVATE KEY-----\n")
		return []byte(sb.String())
	case KindSeed:
		var sb strings.Builder
		sb.WriteString(header(k, tok))
		words := make([]string, 24)
		for i := range words {
			words[i] = pick(seedWords)
		}
		for i := 0; i < 24; i += 6 {
			sb.WriteString(strings.Join(words[i:i+6], " ") + "\n")
		}
		return []byte(sb.String())
	}
	return randBytes(1024)
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// Mode returns the unix permission a real file of this class would carry.
func Mode(k Kind) os.FileMode {
	switch k {
	case KindEnv, KindKey:
		return 0600
	}
	return 0644
}

// Plant writes one decoy under dir and returns it. Existing files are never
// overwritten: hellhound refuses to touch anything it did not plant itself.
func Plant(dir string, k Kind, profile string) (*Canary, error) {
	tok := token()
	name := Filename(k)
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		// name collision: append a short random suffix and retry once
		ext := filepath.Ext(name)
		base := strings.TrimSuffix(name, ext)
		path = filepath.Join(dir, fmt.Sprintf("%s_%s%s", base, hex.EncodeToString(randBytes(2)), ext))
	}
	content := Content(k, tok)
	if err := os.WriteFile(path, content, Mode(k)); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	return &Canary{
		Path:    path,
		Kind:    k,
		Profile: profile,
		Token:   tok,
		SHA256:  hex.EncodeToString(sum[:]),
		Size:    int64(len(content)),
	}, nil
}
