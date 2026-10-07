// Package detect wires filesystem watching and periodic integrity auditing
// into one loop. Two independent tripwires run in parallel:
//
//  1. fsnotify events on every planted directory: any write, create, rename
//     or removal touching a decoy fires immediately.
//  2. a full re-hash sweep of the manifest every scan_interval: catches
//     in-place edits that bypass directory events, deletes of whole trees
//     and anything the watcher missed while paused.
package detect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/brerabineth/hellhound/internal/alert"
	"github.com/brerabineth/hellhound/internal/config"
	"github.com/brerabineth/hellhound/internal/manifest"
	"github.com/brerabineth/hellhound/internal/procscan"
)

// Detector owns the watch loop.
type Detector struct {
	cfg    *config.Config
	man    *manifest.Manifest
	router *alert.Router
	mu     sync.Mutex
	seen   map[string]time.Time // debounce: path -> last incident
	quiet  bool
}

// New builds a detector.
func New(cfg *config.Config, man *manifest.Manifest, router *alert.Router) *Detector {
	return &Detector{cfg: cfg, man: man, router: router, seen: map[string]time.Time{}}
}

// SetQuiet suppresses the console banner (used by tests and --once probes).
func (d *Detector) SetQuiet(q bool) { d.quiet = q }

// Run blocks until ctx is cancelled or a fatal watcher error occurs.
// If once is true, exactly one audit sweep runs and Run returns
// the number of incidents found.
func (d *Detector) Run(ctx context.Context, once bool) (int, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return 0, fmt.Errorf("detect: %w", err)
	}
	defer watcher.Close()

	var watchErrs []string
	for _, dir := range d.man.Dirs() {
		if err := watcher.Add(dir); err != nil {
			watchErrs = append(watchErrs, fmt.Sprintf("%s: %v", dir, err))
		}
	}
	if !d.quiet && len(watchErrs) > 0 {
		for _, e := range watchErrs {
			fmt.Fprintf(os.Stderr, "hellhound: watch failed: %s\n", e)
		}
	}

	if !d.quiet {
		fmt.Printf("hellhound: watching %d directories, %d decoys, re-hash every %ds\n",
			len(d.man.Dirs()), d.man.Count(), d.cfg.ScanIntervalSec)
		fmt.Printf("hellhound: pid %d - kill -INT to stop\n", os.Getpid())
	}

	ticker := time.NewTicker(time.Duration(d.cfg.ScanIntervalSec) * time.Second)
	defer ticker.Stop()

	incidents := 0
	d.auditSweep(&incidents, true)

	for {
		if once {
			return incidents, nil
		}
		select {
		case <-ctx.Done():
			return incidents, nil
		case ev, ok := <-watcher.Events:
			if !ok {
				return incidents, errors.New("detect: watcher closed")
			}
			d.handleEvent(ev, &incidents)
		case err, ok := <-watcher.Errors:
			if !ok {
				return incidents, nil
			}
			fmt.Fprintf(os.Stderr, "hellhound: watcher error: %v\n", err)
		case <-ticker.C:
			d.auditSweep(&incidents, false)
		}
	}
}

// handleEvent reacts to a directory event only if a decoy was touched.
func (d *Detector) handleEvent(ev fsnotify.Event, incidents *int) {
	entry, ok := d.man.ByPath(ev.Name)
	if !ok {
		return // real user file in a planted directory: not our business
	}
	if ev.Op.Has(fsnotify.Chmod) && !ev.Op.Has(fsnotify.Write) {
		return // permission bits alone are noise
	}
	d.fire(incidents, alert.Incident{
		Time:    time.Now(),
		Source:  "fsnotify",
		Path:    entry.Path,
		Profile: entry.Profile,
		Kind:    entry.Kind,
		Token:   entry.Token,
		Detail:  fmt.Sprintf("event=%s", ev.Op),
	})
}

// auditSweep re-hashes the manifest and reports every deviation once.
func (d *Detector) auditSweep(incidents *int, startup bool) {
	findings := d.man.Audit()
	for _, f := range findings {
		detail := fmt.Sprintf("audit=%s", f.Status)
		if f.Status == manifest.StatusModified {
			detail += fmt.Sprintf(" expected=%s actual=%s size=%d",
				short(f.Entry.SHA256), short(f.ActualSHA), f.ActualSize)
		}
		d.fire(incidents, alert.Incident{
			Time:    time.Now(),
			Source:  "integrity",
			Path:    f.Entry.Path,
			Profile: f.Entry.Profile,
			Kind:    f.Entry.Kind,
			Token:   f.Entry.Token,
			Detail:  detail,
		})
	}
	if !startup && len(findings) == 0 && !d.quiet {
		fmt.Printf("hellhound: sweep clean (%d decoys verified)\n", d.man.Count())
	}
}

// fire debounces per path and routes the incident.
func (d *Detector) fire(incidents *int, inc alert.Incident) {
	d.mu.Lock()
	if last, ok := d.seen[inc.Path+inc.Detail]; ok && time.Since(last) < 2*time.Second {
		d.mu.Unlock()
		return
	}
	d.seen[inc.Path+inc.Detail] = time.Now()
	d.mu.Unlock()

	// Best-effort writer identification: who holds this file open right now.
	if procs := procscan.FindWriters(inc.Path); len(procs) > 0 {
		inc.PID = procs[0].PID
		inc.Proc = procs[0].Comm
		if inc.Proc == "" {
			inc.Proc = fmt.Sprintf("pid %d", procs[0].PID)
		}
	}

	if d.quiet {
		// still emit to non-console channels
		console := d.router.Console
		d.router.Console = false
		d.router.Emit(inc)
		d.router.Console = console
	} else {
		d.router.Emit(inc)
	}
	*incidents++
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
