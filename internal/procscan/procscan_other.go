//go:build !linux

// Package procscan is a no-op on non-Linux platforms: walking another
// OS's process/fd tables needs platform-specific APIs. Incidents still
// fire; writer identification stays empty.
package procscan

// Proc is one candidate writer (unused off-Linux).
type Proc struct {
	PID     int
	Comm    string
	Cmdline string
}

// FindWriters returns nil on this platform.
func FindWriters(path string) []Proc { return nil }
