// Package cli implements hellhound's subcommands.
package cli

import (
        "context"
        "encoding/json"
        "flag"
        "fmt"
        "os"
        "os/signal"
        "sort"
        "syscall"
        "time"

        "github.com/brerabineth/hellhound/internal/alert"
        "github.com/brerabineth/hellhound/internal/canary"
        "github.com/brerabineth/hellhound/internal/config"
        "github.com/brerabineth/hellhound/internal/detect"
        "github.com/brerabineth/hellhound/internal/manifest"
)

// Version is set at build time via -ldflags.
var Version = "0.1.0"

var banner = "  ,-.       hellhound v" + Version + "\n" +
        " ( O >      decoy tripwire for ransomware ops\n" +
        "  '-,       %d decoys under watch - re-hash every %ds"

// Main dispatches os.Args and returns the process exit code.
func Main(args []string) int {
        if len(args) < 1 {
                usage()
                return 2
        }
        switch args[0] {
        case "init":
                return cmdInit()
        case "plant":
                return cmdPlant(args[1:])
        case "check":
                return cmdCheck(args[1:])
        case "watch":
                return cmdWatch(args[1:])
        case "status":
                return cmdStatus()
        case "version", "-v", "--version":
                fmt.Println("hellhound " + Version)
                return 0
        case "help", "-h", "--help":
                usage()
                return 0
        default:
                fmt.Fprintf(os.Stderr, "hellhound: unknown command %q\n", args[0])
                usage()
                return 2
        }
}

func usage() {
        fmt.Print(`hellhound - canary tripwire for ransomware operations

usage: hellhound <command> [flags]

  init      write default config and state directory
  plant     generate decoys and record the integrity baseline
  check     one-shot audit of every decoy (exit 1 on compromise)
  watch     live watch loop: fsnotify + periodic re-hash
  status    inventory summary and recent incidents
  version   print version

planted decoys are ordinary files with hostile-to-lose names.
anything that touches them gets reported. that is the whole idea.
`)
}

func cmdInit() int {
        if err := config.EnsureStateDir(); err != nil {
                fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
                return 1
        }
        if err := config.SaveDefault(config.ConfigPath()); err != nil {
                if os.IsExist(err) {
                        fmt.Printf("config already present: %s\n", config.ConfigPath())
                        return 0
                }
                fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
                return 1
        }
        fmt.Printf("state dir:  %s\n", config.StateDir())
        fmt.Printf("config:     %s (edit profiles before planting)\n", config.ConfigPath())
        fmt.Printf("next: review the config, then run `hellhound plant`\n")
        return 0
}

func loadAll() (*config.Config, *manifest.Manifest, error) {
        cfg, err := config.Load(config.ConfigPath())
        if err != nil {
                return nil, nil, fmt.Errorf("load config: %w", err)
        }
        man, err := manifest.Load(config.ManifestPath())
        if err != nil {
                return nil, nil, err
        }
        return cfg, man, nil
}

func cmdPlant(argv []string) int {
        fs := flag.NewFlagSet("plant", flag.ExitOnError)
        printJSON := fs.Bool("json", false, "print planted inventory as JSON")
        fs.Parse(argv)

        cfg, err := config.Load(config.ConfigPath())
        if err != nil {
                fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
                return 1
        }
        man, err := manifest.Load(config.ManifestPath())
        if err != nil {
                if err != manifest.ErrNoManifest {
                        fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
                        return 1
                }
                man = &manifest.Manifest{Version: 1, Planted: time.Now().UTC()}
        }

        kindSet := map[string]bool{}
        for _, k := range cfg.Kinds {
                kindSet[k] = true
        }

        planted, skipped := 0, 0
        var profiles []string
        for p := range cfg.Profiles {
                profiles = append(profiles, p)
        }
        sort.Strings(profiles)

        for _, profile := range profiles {
                for _, rawDir := range cfg.Profiles[profile] {
                        dir := config.ExpandPath(rawDir)
                        if _, err := os.Stat(dir); err != nil {
                                if !cfg.CreateDirs {
                                        fmt.Fprintf(os.Stderr, "hellhound: skip %s: %v\n", dir, err)
                                        skipped++
                                        continue
                                }
                                if err := os.MkdirAll(dir, 0755); err != nil {
                                        fmt.Fprintf(os.Stderr, "hellhound: skip %s: %v\n", dir, err)
                                        skipped++
                                        continue
                                }
                        }
                        for _, kindName := range canary.AllKinds {
                                if !kindSet[string(kindName)] {
                                        continue
                                }
                                c, err := canary.Plant(dir, kindName, profile)
                                if err != nil {
                                        fmt.Fprintf(os.Stderr, "hellhound: %s: %v\n", dir, err)
                                        skipped++
                                        continue
                                }
                                mode := uint32(0644)
                                if fi, statErr := os.Stat(c.Path); statErr == nil {
                                        mode = uint32(fi.Mode().Perm())
                                }
                                man.Add(manifest.Entry{
                                        Path:    c.Path,
                                        Kind:    string(c.Kind),
                                        Profile: c.Profile,
                                        Token:   c.Token,
                                        SHA256:  c.SHA256,
                                        Size:    c.Size,
                                        Mode:    mode,
                                        Planted: time.Now().UTC(),
                                })
                                planted++
                        }
                }
        }

        man.Planted = time.Now().UTC()
        if err := man.Save(config.ManifestPath()); err != nil {
                fmt.Fprintf(os.Stderr, "hellhound: save manifest: %v\n", err)
                return 1
        }

        if *printJSON {
                out, _ := json.MarshalIndent(man.Entries, "", "  ")
                fmt.Println(string(out))
        } else {
                fmt.Printf("planted %d decoys across %d profiles (%d skipped)\n", planted, len(profiles), skipped)
                fmt.Printf("baseline: %s\n", config.ManifestPath())
                fmt.Printf("next: run `hellhound check`, then keep `hellhound watch` alive\n")
        }

        if planted == 0 {
                fmt.Fprintf(os.Stderr, "hellhound: nothing planted - check profiles and kinds in %s\n", config.ConfigPath())
                return 1
        }
        return 0
}

func cmdCheck(argv []string) int {
        fs := flag.NewFlagSet("check", flag.ExitOnError)
        quiet := fs.Bool("q", false, "exit code only, no output")
        fs.Parse(argv)

        _, man, err := loadAll()
        if err != nil {
                fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
                return 2
        }
        findings := man.Audit()
        if len(findings) == 0 {
                if !*quiet {
                        fmt.Printf("\033[0;32mclean: %d decoys intact\033[0m\n", man.Count())
                }
                return 0
        }
        if !*quiet {
                for _, f := range findings {
                        status := "modified"
                        if f.Status == manifest.StatusMissing {
                                status = "missing"
                        }
                        fmt.Printf("\033[1;31mBITE:\033[0m %-8s %s (%s)\n", status, f.Entry.Path, f.Entry.Profile)
                        if f.Status == manifest.StatusModified && len(f.ActualSHA) >= 12 {
                                fmt.Printf("      baseline %s... now %s...\n", f.Entry.SHA256[:12], f.ActualSHA[:12])
                        }
                }
                fmt.Printf("\n%d of %d decoys compromised - treat as active intrusion\n", len(findings), man.Count())
        }
        return 1
}

func cmdWatch(argv []string) int {
        fs := flag.NewFlagSet("watch", flag.ExitOnError)
        once := fs.Bool("once", false, "run one audit sweep and exit (for CI and smoke tests)")
        interval := fs.Int("interval", 0, "override scan_interval seconds")
        fs.Parse(argv)

        cfg, man, err := loadAll()
        if err != nil {
                fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
                return 2
        }
        if *interval > 0 {
                cfg.ScanIntervalSec = *interval
        }
        router := alert.New(cfg.Alerts.Console, cfg.Alerts.JSONL, config.IncidentsPath(),
                cfg.Alerts.Syslog, cfg.Alerts.Webhook)

        ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
        defer stop()

        if !*once {
                fmt.Printf(banner+"\n", man.Count(), cfg.ScanIntervalSec)
        }
        d := detect.New(cfg, man, router)
        n, err := d.Run(ctx, *once)
        if err != nil {
                fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
                return 2
        }
        if *once {
                if n > 0 {
                        fmt.Printf("watch --once: %d incident(s)\n", n)
                        return 1
                }
                fmt.Printf("watch --once: no incidents\n")
        }
        return 0
}

func cmdStatus() int {
        _, man, err := loadAll()
        if err != nil {
                fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
                return 2
        }
        byProfile := map[string]int{}
        byKind := map[string]int{}
        for _, e := range man.Entries {
                byProfile[e.Profile]++
                byKind[e.Kind]++
        }
        fmt.Printf("decoys: %d   baseline: %s\n", man.Count(), man.Planted.Format("2006-01-02 15:04"))
        for _, p := range sortedKeys(byProfile) {
                fmt.Printf("  %-10s %d\n", p, byProfile[p])
        }
        for _, k := range sortedKeys(byKind) {
                fmt.Printf("  kind %-6s %d\n", k, byKind[k])
        }
        if data, err := os.ReadFile(config.IncidentsPath()); err == nil && len(data) > 0 {
                lines := splitLines(data)
                fmt.Printf("incidents: %d total, last few:\n", len(lines))
                start := 0
                if len(lines) > 5 {
                        start = len(lines) - 5
                }
                for _, line := range lines[start:] {
                        var inc alert.Incident
                        if json.Unmarshal([]byte(line), &inc) == nil {
                                fmt.Printf("  %s\n", alert.Summarize(inc))
                        }
                }
        } else {
                fmt.Printf("incidents: none\n")
        }
        return 0
}

func sortedKeys(m map[string]int) []string {
        keys := make([]string, 0, len(m))
        for k := range m {
                keys = append(keys, k)
        }
        sort.Strings(keys)
        return keys
}

func splitLines(data []byte) []string {
        var out []string
        cur := ""
        for _, r := range string(data) {
                if r == '\n' {
                        if cur != "" {
                                out = append(out, cur)
                        }
                        cur = ""
                        continue
                }
                cur += string(r)
        }
        if cur != "" {
                out = append(out, cur)
        }
        return out
}
