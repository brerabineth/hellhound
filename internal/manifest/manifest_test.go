package manifest

import (
        "crypto/sha256"
        "encoding/hex"
        "fmt"
        "os"
        "path/filepath"
        "runtime"
        "testing"
        "time"
)

func sha(t *testing.T, path string) string {
        t.Helper()
        data, err := os.ReadFile(path)
        if err != nil {
                t.Fatal(err)
        }
        sum := sha256.Sum256(data)
        return hex.EncodeToString(sum[:])
}

var seedSeq int

func seedEntry(t *testing.T, dir string, body []byte) Entry {
        t.Helper()
        seedSeq++
        path := filepath.Join(dir, fmt.Sprintf("decoy_%d.txt", seedSeq))
        if err := os.WriteFile(path, body, 0644); err != nil {
                t.Fatal(err)
        }
        return Entry{
                Path:    path,
                Kind:    "doc",
                Profile: "documents",
                Token:   "t-1234",
                SHA256:  sha(t, path),
                Size:    int64(len(body)),
                Planted: time.Now().UTC(),
        }
}

func TestAddIsIdempotentByPath(t *testing.T) {
        m := &Manifest{}
        e := Entry{Path: "/x/a.doc"}
        if !m.Add(e) {
                t.Fatal("first add must succeed")
        }
        if m.Add(e) {
                t.Fatal("duplicate path must be rejected")
        }
        if m.Count() != 1 {
                t.Fatalf("count = %d, want 1", m.Count())
        }
}

func TestSaveLoadRoundtripAndPerms(t *testing.T) {
        dir := t.TempDir()
        path := filepath.Join(dir, "manifest.json")
        m := &Manifest{Version: 1, Planted: time.Now().UTC()}
        m.Add(Entry{Path: "/x/a.doc", SHA256: "abc", Kind: "doc"})
        if err := m.Save(path); err != nil {
                t.Fatal(err)
        }
        fi, err := os.Stat(path)
        if err != nil {
                t.Fatal(err)
        }
        // windows has no posix perms; go synthesizes the mode bits there
        if runtime.GOOS != "windows" && fi.Mode().Perm() != 0600 {
                t.Fatalf("manifest perms = %v, want 0600", fi.Mode().Perm())
        }
        loaded, err := Load(path)
        if err != nil {
                t.Fatal(err)
        }
        if loaded.Count() != 1 || loaded.Entries[0].SHA256 != "abc" {
                t.Fatal("roundtrip lost data")
        }
}

func TestLoadMissingFile(t *testing.T) {
        if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err != ErrNoManifest {
                t.Fatalf("want ErrNoManifest, got %v", err)
        }
}

func TestAuditDetectsModificationAndMissing(t *testing.T) {
        dir := t.TempDir()
        body := []byte("intact decoy payload")
        e1 := seedEntry(t, dir, body)
        e2 := seedEntry(t, dir, []byte("another decoy"))

        m := &Manifest{Version: 1}
        m.Add(e1)
        m.Add(e2)

        if got := len(m.Audit()); got != 0 {
                t.Fatalf("clean baseline reported %d findings", got)
        }

        // tamper e1 in place
        if err := os.WriteFile(e1.Path, []byte("tampered"), 0644); err != nil {
                t.Fatal(err)
        }
        // destroy e2
        if err := os.Remove(e2.Path); err != nil {
                t.Fatal(err)
        }

        findings := m.Audit()
        if len(findings) != 2 {
                t.Fatalf("got %d findings, want 2", len(findings))
        }
        byPath := map[string]Status{}
        for _, f := range findings {
                byPath[f.Entry.Path] = f.Status
        }
        if byPath[e1.Path] != StatusModified {
                t.Fatalf("e1: want modified, got %v", byPath[e1.Path])
        }
        if byPath[e2.Path] != StatusMissing {
                t.Fatalf("e2: want missing, got %v", byPath[e2.Path])
        }
}

func TestDirsUnique(t *testing.T) {
        m := &Manifest{}
        m.Add(Entry{Path: "/a/one.doc"})
        m.Add(Entry{Path: "/a/two.doc"})
        m.Add(Entry{Path: "/b/three.doc"})
        dirs := m.Dirs()
        if len(dirs) != 2 {
                t.Fatalf("dirs = %v, want 2 unique", dirs)
        }
}
