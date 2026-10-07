// Package config loads hellhound's YAML configuration and resolves state
// paths. Defaults are deliberately conservative: decoys go where users keep
// real work, nowhere near system directories.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Alerts selects the incident notification channels.
type Alerts struct {
	Console bool   `yaml:"console"`
	JSONL   bool   `yaml:"jsonl"`
	Syslog  bool   `yaml:"syslog"`
	Webhook string `yaml:"webhook"`
}

// Config is the on-disk configuration.
type Config struct {
	Profiles        map[string][]string `yaml:"profiles"`
	Kinds           []string            `yaml:"kinds"`
	CreateDirs      bool                `yaml:"create_dirs"`
	ScanIntervalSec int                 `yaml:"scan_interval"`
	Alerts          Alerts              `yaml:"alerts"`
}

// Default returns the built-in configuration.
func Default() *Config {
	return &Config{
		Profiles: map[string][]string{
			"documents": {"~/Documents", "~/Desktop"},
			"secrets":   {"~/.ssh", "~/.aws", "~/.config"},
			"data":      {"~/backups", "~/Projects"},
		},
		Kinds:           []string{"doc", "sheet", "db", "wallet", "kdbx", "env", "key", "seed"},
		CreateDirs:      true,
		ScanIntervalSec: 30,
		Alerts: Alerts{
			Console: true,
			JSONL:   true,
			Syslog:  false,
			Webhook: "",
		},
	}
}

// StateDir is where hellhound keeps its manifest, config and incident log.
func StateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".hellhound"
	}
	return filepath.Join(home, ".hellhound")
}

// ConfigPath is the default configuration location.
func ConfigPath() string { return filepath.Join(StateDir(), "hellhound.yaml") }

// ManifestPath is the default inventory location.
func ManifestPath() string { return filepath.Join(StateDir(), "manifest.json") }

// IncidentsPath is the JSONL incident log.
func IncidentsPath() string { return filepath.Join(StateDir(), "incidents.jsonl") }

// EnsureStateDir creates the state directory with restrictive permissions.
func EnsureStateDir() error {
	return os.MkdirAll(StateDir(), 0700)
}

// Load reads and validates the configuration at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) normalize() {
	if c.ScanIntervalSec <= 0 {
		c.ScanIntervalSec = 30
	}
	if len(c.Kinds) == 0 {
		c.Kinds = []string{"doc", "sheet", "db", "wallet", "kdbx", "env", "key", "seed"}
	}
}

// Validate rejects configurations that would plant decoys in system paths or
// reference unknown decoy classes.
func (c *Config) Validate() error {
	known := map[string]bool{}
	for _, k := range c.Kinds {
		known[k] = true
	}
	validKinds := map[string]bool{"doc": true, "sheet": true, "db": true, "wallet": true,
		"kdbx": true, "env": true, "key": true, "seed": true}
	for k := range known {
		if !validKinds[k] {
			return fmt.Errorf("config: unknown canary kind %q", k)
		}
	}
	for profile, dirs := range c.Profiles {
		if len(dirs) == 0 {
			return fmt.Errorf("config: profile %q has no paths", profile)
		}
		for _, d := range dirs {
			abs := ExpandPath(d)
			for _, sys := range []string{"/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc", "/dev", "C:\\Windows"} {
				if abs == sys || strings.HasPrefix(abs, sys+string(os.PathSeparator)) {
					return fmt.Errorf("config: profile %q: refusing system path %s", profile, d)
				}
			}
		}
	}
	return nil
}

// ExpandPath resolves ~ and environment variables in a path.
func ExpandPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return os.ExpandEnv(p)
}

// SaveDefault writes the commented default configuration.
func SaveDefault(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config: %s already exists", path)
	}
	defaults := `# hellhound - canary tripwire configuration
# decoys are planted per profile; every path is watched after ` + "`plant`" + `.

profiles:
  documents:
    - ~/Documents
    - ~/Desktop
  secrets:
    - ~/.ssh
    - ~/.aws
    - ~/.config
  data:
    - ~/backups
    - ~/Projects

# decoy classes: doc sheet db wallet kdbx env key seed
kinds: [doc, sheet, db, wallet, kdbx, env, key, seed]

# create planted directories if they do not exist yet
create_dirs: true

# seconds between full integrity re-hashes of every decoy
scan_interval: 30

alerts:
  console: true          # loud stderr banner
  jsonl: true            # ~/.hellhound/incidents.jsonl
  syslog: false          # best effort via /dev/log
  webhook: ""            # POST JSON incident to this URL, empty = off
`
	return os.WriteFile(path, []byte(defaults), 0600)
}
