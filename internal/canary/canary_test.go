package canary

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContentMagicBytes(t *testing.T) {
	cases := map[Kind][]byte{
		KindDoc:   {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
		KindSheet: {'P', 'K', 0x03, 0x04},
		KindDB:    []byte("SQLite format 3\x00"),
		KindKdbx:  {0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0x5B},
	}
	for kind, magic := range cases {
		tok := token()
		got := Content(kind, tok)
		if !bytes.HasPrefix(got, magic) {
			t.Errorf("%s: content lacks magic header", kind)
		}
		if !bytes.Contains(got[:64], []byte(tok)) {
			t.Errorf("%s: token not embedded in first 64 bytes", kind)
		}
	}
}

func TestContentUniqueness(t *testing.T) {
	a := Content(KindEnv, token())
	b := Content(KindEnv, token())
	if bytes.Equal(a, b) {
		t.Fatal("two env decoys identical: token uniqueness broken")
	}
}

func TestFilenameRealism(t *testing.T) {
	if !strings.HasPrefix(Filename(KindEnv), ".env") {
		t.Fatal("env decoy must be named .env")
	}
	if !strings.HasSuffix(Filename(KindKdbx), ".kdbx") {
		t.Fatal("kdbx decoy must end in .kdbx")
	}
}

func TestPlantRefusesToOverwriteDifferentKinds(t *testing.T) {
	dir := t.TempDir()
	c1, err := Plant(dir, KindEnv, "secrets")
	if err != nil {
		t.Fatal(err)
	}
	// .env always collides; second plant must keep the original bytes intact
	orig, err := os.ReadFile(c1.Path)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Plant(dir, KindEnv, "secrets")
	if err != nil {
		t.Fatal(err)
	}
	if c2.Path == c1.Path {
		t.Fatal("plant did not avoid collision")
	}
	again, _ := os.ReadFile(c1.Path)
	if !bytes.Equal(orig, again) {
		t.Fatal("original decoy was overwritten")
	}
}

func TestMode(t *testing.T) {
	if Mode(KindEnv) != 0600 || Mode(KindKey) != 0600 {
		t.Fatal("secret decoys must be 0600")
	}
	if Mode(KindDoc) != 0644 {
		t.Fatal("document decoys must be 0644")
	}
}

func TestSeedHas24Words(t *testing.T) {
	c := Content(KindSeed, token())
	lines := strings.Split(strings.TrimSpace(string(c)), "\n")
	// header 2 lines + 4 word lines
	if len(lines) != 6 {
		t.Fatalf("seed layout changed: %d lines", len(lines))
	}
}

func TestPlantWritesUnderDir(t *testing.T) {
	dir := t.TempDir()
	for _, k := range AllKinds {
		c, err := Plant(dir, k, "documents")
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if filepath.Dir(c.Path) != dir {
			t.Fatalf("%s: planted outside target dir: %s", k, c.Path)
		}
		fi, err := os.Stat(c.Path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() != c.Size {
			t.Fatalf("%s: size mismatch on disk", k)
		}
	}
}
