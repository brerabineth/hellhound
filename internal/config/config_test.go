package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsSystemPaths(t *testing.T) {
	c := Default()
	c.Profiles = map[string][]string{"bad": {"/etc", "/usr/local"}}
	if err := c.Validate(); err == nil {
		t.Fatal("system paths must be rejected")
	}
}

func TestValidateAcceptsUserPaths(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestValidateRejectsUnknownKind(t *testing.T) {
	c := Default()
	c.Kinds = []string{"doc", "cryptominer"}
	if err := c.Validate(); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
}

func TestExpandPathTilde(t *testing.T) {
	home, _ := os.UserHomeDir()
	got := ExpandPath("~/Documents")
	if got != filepath.Join(home, "Documents") {
		t.Fatalf("expand = %s", got)
	}
}

func TestSaveDefaultRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hellhound.yaml")
	if err := SaveDefault(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("default config must parse: %v", err)
	}
	if len(cfg.Profiles) == 0 {
		t.Fatal("default config has no profiles")
	}
	if cfg.ScanIntervalSec <= 0 {
		t.Fatal("scan interval must be positive")
	}
	// second write must refuse: never clobber a tuned config
	if err := SaveDefault(path); err == nil {
		t.Fatal("SaveDefault must refuse to overwrite")
	}
}

func TestDefaultConfigTextHasNoPlaceholders(t *testing.T) {
	c := Default()
	var b strings.Builder
	for p, dirs := range c.Profiles {
		b.WriteString(p + ": " + strings.Join(dirs, ",") + "\n")
	}
	if strings.Contains(b.String(), "TODO") || strings.Contains(b.String(), "CHANGEME") {
		t.Fatal("defaults ship with placeholder text")
	}
}
