// Package manifest persists the decoy inventory and audits the filesystem
// against it. The manifest is the trust anchor: hash baseline, planted paths,
// and the attribution token for every decoy.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Entry is one planted decoy.
type Entry struct {
	Path    string    `json:"path"`
	Kind    string    `json:"kind"`
	Profile string    `json:"profile"`
	Token   string    `json:"token"`
	SHA256  string    `json:"sha256"`
	Size    int64     `json:"size"`
	Mode    uint32    `json:"mode"`
	Planted time.Time `json:"planted"`
}

// Manifest is the full inventory.
type Manifest struct {
	Version int       `json:"version"`
	Planted time.Time `json:"planted"`
	Entries []Entry   `json:"entries"`
}

// ErrNoManifest is returned when no inventory exists yet.
var ErrNoManifest = errors.New("no manifest: run `hellhound plant` first")

// Status is the audit result for a single entry.
type Status int

const (
	StatusOK Status = iota
	StatusModified
	StatusMissing
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusModified:
		return "modified"
	default:
		return "missing"
	}
}

// Finding is one audit result.
type Finding struct {
	Entry      Entry
	Status     Status
	ActualSHA  string
	ActualSize int64
}

// Load reads the manifest at path. Missing file yields ErrNoManifest.
func Load(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoManifest
		}
		return nil, err
	}
	defer f.Close()
	var m Manifest
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Save atomically writes the manifest (tmp file + rename, 0600).
func (m *Manifest) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Add inserts an entry if the path is not already tracked.
func (m *Manifest) Add(e Entry) bool {
	for _, ex := range m.Entries {
		if ex.Path == e.Path {
			return false
		}
	}
	m.Entries = append(m.Entries, e)
	return true
}

// ByPath returns the entry for path, if tracked.
func (m *Manifest) ByPath(path string) (Entry, bool) {
	for _, e := range m.Entries {
		if e.Path == path {
			return e, true
		}
	}
	return Entry{}, false
}

// Dirs returns the unique parent directories of all planted decoys.
func (m *Manifest) Dirs() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range m.Entries {
		d := filepath.Dir(e.Path)
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// Count returns the number of tracked decoys.
func (m *Manifest) Count() int { return len(m.Entries) }

// Audit re-hashes every decoy and reports deviations from the baseline.
func (m *Manifest) Audit() []Finding {
	var out []Finding
	for _, e := range m.Entries {
		f := Finding{Entry: e, Status: StatusOK}
		fi, err := os.Stat(e.Path)
		if err != nil {
			f.Status = StatusMissing
			out = append(out, f)
			continue
		}
		f.ActualSize = fi.Size()
		if h, err := hashFile(e.Path); err == nil {
			f.ActualSHA = h
			if h != e.SHA256 {
				f.Status = StatusModified
			}
		} else {
			f.Status = StatusModified
		}
		if f.Status != StatusOK {
			out = append(out, f)
		}
	}
	return out
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
