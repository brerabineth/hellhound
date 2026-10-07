//go:build linux

// Package procscan performs best-effort identification of the process that
// currently holds an open descriptor on a given path, by walking /proc.
// It is a triage aid, not a forensic guarantee: the writer may have closed
// the descriptor before the scan lands.
package procscan

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Proc is one candidate writer.
type Proc struct {
	PID     int
	Comm    string
	Cmdline string
}

// FindWriters returns visible processes holding path open. Deleted-file
// handles are matched too ("path (deleted)" links).
func FindWriters(path string) []Proc {
	var out []Proc
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // permission denied or process gone
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			link = strings.TrimSuffix(link, " (deleted)")
			if link == path {
				out = append(out, Proc{
					PID:     pid,
					Comm:    readFirstLine(filepath.Join("/proc", e.Name(), "comm")),
					Cmdline: strings.Join(readNullSep(filepath.Join("/proc", e.Name(), "cmdline")), " "),
				})
				break
			}
		}
	}
	return out
}

func readFirstLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readNullSep(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	if len(parts) == 1 && parts[0] == "" {
		return nil
	}
	return parts
}
