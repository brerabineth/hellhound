#!/usr/bin/env bash
# e2e_local.sh - full lifecycle test of hellhound in an isolated fake HOME.
# Proves: init -> plant -> status -> watch (live detection) -> attack_sim -> check -> status
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
FAKEHOME="$(mktemp -d "${TMPDIR:-/tmp}/hellhound-e2e.XXXXXX")"
BIN=$REPO/hellhound

command -v go >/dev/null 2>&1 || { echo "e2e: go not in PATH"; exit 1; }
cd "$REPO" || exit 1
go build -trimpath -ldflags '-s -w' -o hellhound . || exit 1

trap 'rm -rf "$FAKEHOME"' EXIT
export HOME="$FAKEHOME"

fail=0
say() { echo; echo "=== $* ==="; }

say "1. init"
./hellhound init || fail=1

say "2. plant"
./hellhound plant || fail=1

say "3. status (pre-attack)"
./hellhound status || fail=1

say "4. check (must be clean, exit 0)"
./hellhound check || fail=1
[ $? -eq 0 ] && echo "e2e: check exit 0 OK" || { echo "e2e: check exit nonzero on clean state"; fail=1; }

say "5. watch loop + attack"
./hellhound watch -interval 2 > "$FAKEHOME/watch.log" 2>&1 &
WATCH_PID=$!
sleep 1.5

DECOY_DOC=$(ls "$FAKEHOME"/Documents/*.doc | head -1)
DECOY_ENV="$FAKEHOME/secrets_env_probe"
DECOY_ENV=$(ls -a "$FAKEHOME/.ssh"/id_rsa_backup 2>/dev/null | head -1)

bash test/attack_sim.sh "$DECOY_DOC" "$DECOY_ENV" || fail=1
sleep 4
kill -INT "$WATCH_PID" 2>/dev/null
sleep 1

say "6. watch.log (live detection output)"
cat "$FAKEHOME/watch.log"

say "7. check (must exit 1 now)"
set +e
./hellhound check
CHECK_RC=$?
set -e
[ "$CHECK_RC" -eq 1 ] && echo "e2e: check exit 1 OK (compromise detected)" || { echo "e2e: check rc=$CHECK_RC expected 1"; fail=1; }

say "8. status (post-attack, incidents listed)"
./hellhound status || fail=1

say "9. incident JSONL tail"
tail -2 "$FAKEHOME/.hellhound/incidents.jsonl"

say "10. watch --once after compromise (must exit 1)"
set +e
./hellhound watch --once > /dev/null 2>&1
ONCE_RC=$?
set -e
[ "$ONCE_RC" -eq 1 ] && echo "e2e: watch --once exit 1 OK" || { echo "e2e: once rc=$ONCE_RC expected 1"; fail=1; }

say "RESULT"
if [ "$fail" -eq 0 ]; then
  echo "E2E: ALL PASS"
else
  echo "E2E: FAILURES PRESENT"
fi
exit "$fail"
