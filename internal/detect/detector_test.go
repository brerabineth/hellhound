package detect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/brerabineth/hellhound/internal/alert"
	"github.com/brerabineth/hellhound/internal/config"
	"github.com/brerabineth/hellhound/internal/manifest"
)

func buildFixture(t *testing.T) (*config.Config, *manifest.Manifest, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.ScanIntervalSec = 1
	body := []byte("decoy payload for tripwire test")
	path := filepath.Join(dir, "Invoice_2026-10-01_0001.doc")
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	man := &manifest.Manifest{Version: 1}
	man.Add(manifest.Entry{
		Path:    path,
		Kind:    "doc",
		Profile: "documents",
		Token:   "t-test",
		SHA256:  hex.EncodeToString(sum[:]),
		Size:    int64(len(body)),
		Planted: time.Now().UTC(),
	})
	return cfg, man, path
}

func TestCleanBaselineYieldsNothing(t *testing.T) {
	cfg, man, _ := buildFixture(t)
	d := New(cfg, man, alert.New(false, false, "", false, ""))
	d.SetQuiet(true)
	n, err := d.Run(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("clean baseline produced %d incidents", n)
	}
}

func TestAuditSweepCatchesTamper(t *testing.T) {
	cfg, man, path := buildFixture(t)
	d := New(cfg, man, alert.New(false, false, "", false, ""))
	d.SetQuiet(true)
	if _, err := d.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered payload"), 0644); err != nil {
		t.Fatal(err)
	}
	n, err := d.Run(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("tamper produced %d incidents, want 1", n)
	}
}

func TestLiveWatchFiresOnWrite(t *testing.T) {
	cfg, man, path := buildFixture(t)
	d := New(cfg, man, alert.New(false, false, "", false, ""))
	d.SetQuiet(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(path, []byte("tampered live"), 0644)
	}()
	n, err := d.Run(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("live watch never reported the write")
	}
}
