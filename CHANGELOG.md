# 0.1.0 - 2026-10-07

first cut. the whole tripwire, nothing more.

- decoy generator: 8 classes (doc, sheet, db, wallet, kdbx, env, key, seed)
  with correct magic bytes and per-file attribution tokens
- profiles and kinds driven by ~/.hellhound/hellhound.yaml
- manifest with SHA-256 baseline, atomic writes, 0600
- watch loop: fsnotify on planted dirs + periodic full re-hash
- alerts: console banner, JSONL incident log, syslog (best effort), webhook
- writer identification via /proc on linux (best effort)
- `check` exit codes for cron and shell integration
- cross builds: linux amd64/arm64, darwin amd64/arm64, windows amd64
