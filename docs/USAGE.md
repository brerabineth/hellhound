# hellhound manual

## state layout

```
~/.hellhound/
  hellhound.yaml     configuration (0600)
  manifest.json      decoy inventory + SHA-256 baseline (0600)
  incidents.jsonl    append-only incident log (0600)
```

Everything hellhound writes lives in that directory. Delete it and the tool
forgets everything; decoy files on disk become ordinary junk you can remove
by hand.

## commands

### init

Creates the state directory and writes the default config if none exists.
Never overwrites an existing config.

### plant

Generates decoys for every configured profile and kind, writes them to disk
and records the baseline. Refuses to overwrite existing files: if a decoy
name collides, a random suffix is appended instead. Idempotent — running it
again adds new decoys, never duplicates.

flags:

- `-json` — print the planted inventory as JSON instead of the summary

### check

One-shot audit: re-hash every decoy, compare against the baseline. Exit code
0 = clean, 1 = compromise detected, 2 = operational error (no manifest, bad
config). Designed for cron:

```
*/10 * * * * /usr/local/bin/hellhound check -q || \
    /usr/local/bin/alert-something "canary bite on $(hostname)"
```

flags:

- `-q` — suppress output, exit code only

### watch

Long-running loop. Adds an fsnotify watch on every planted directory and
re-hashes the full manifest every `scan_interval` seconds. On any incident
it routes an alert (see channels below). Identifies the process currently
holding the decoy open via `/proc` — best effort on Linux, empty elsewhere.

flags:

- `-once` — run one sweep and exit; exit 1 if incidents were found (used by
  CI and smoke tests)
- `-interval N` — override `scan_interval` for this run

systemd unit for a workstation:

```
[Unit]
Description=hellhound canary tripwire
After=local-fs.target

[Service]
ExecStart=/usr/local/bin/hellhound watch
Restart=on-failure
RestartSec=5
# harden: the tool needs no privileges beyond your user
NoNewPrivileges=yes
ProtectSystem=full

[Install]
WantedBy=default.target
```

### status

Prints decoy counts per profile and kind, plus the last incidents from the
JSONL log.

### version

Prints the build version.

## configuration

```yaml
profiles:
  documents:            # profile name is free-form
    - ~/Documents
    - ~/Desktop
  secrets:
    - ~/.ssh
    - ~/.aws
    - ~/.config
  data:
    - ~/backups
    - ~/Projects

kinds: [doc, sheet, db, wallet, kdbx, env, key, seed]

create_dirs: true       # create planted dirs if missing
scan_interval: 30       # seconds between full re-hashes

alerts:
  console: true
  jsonl: true
  syslog: false         # needs a local syslog socket
  webhook: ""           # empty = disabled
```

Rules the loader enforces:

- unknown `kinds` values are rejected
- no profile may point into system directories (`/etc`, `/usr`, `/bin`,
  `/sbin`, `/boot`, `/sys`, `/proc`, `/dev`, `C:\Windows`)
- `scan_interval` below 1 falls back to 30

Paths support `~` and `$ENV` expansion.

## incident JSON

```json
{
  "time": "2026-10-07T12:31:04.912Z",
  "source": "fsnotify",
  "path": "/home/you/Documents/Invoice_2026-09-28_2210.doc",
  "profile": "documents",
  "kind": "doc",
  "token": "9d3a94a2-1c4e-4f30-9d08-52e5ad9071c2",
  "detail": "event=WRITE",
  "pid": 4471,
  "proc": "python3"
}
```

`source` is `fsnotify` for live events or `integrity` for sweep findings.
`detail` carries the event op, or for sweeps: `audit=modified` with expected
vs. actual hash prefixes.

## validating your deployment

```
test/attack_sim.sh <decoy> [<decoy> ...]
```

The simulator only touches paths you hand it, refuses system directories,
and runs three stages: silent overwrite (dropper behavior), rename
(pre-encryption staging), destroy (wiper behavior). After it runs, `check`
must exit 1 and `status` must list the bites. If it does not, your watch
loop is not actually running — fix that before trusting anything else.

## notes for windows

- fsnotify uses ReadDirectoryChangesW; planted directories on network
  shares may not deliver events. The integrity sweep still works.
- `/proc` writer identification is Linux-only; on Windows `pid` stays empty.
- Decoy modes (0600/0644) are Unix semantics; Windows ignores them.

## notes for macos

- First run of `watch` may need the terminal granted Full Disk Access to
  watch folders like `~/Desktop` reliably.
- `~/.aws` is uncommon on macOS; trim the `secrets` profile to taste.
