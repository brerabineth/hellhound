#!/usr/bin/env bash
# attack_sim.sh - safe validation harness for your own hellhound deployment.
#
# It touches ONLY the decoy paths you explicitly pass as arguments, and it
# refuses system directories. Purpose: prove your watch loop actually fires
# before you rely on it. Do not point it at files you care about; targets
# get overwritten by design.
#
# usage: attack_sim.sh <decoy> [<decoy> ...]

set -u

if [ $# -lt 1 ]; then
    echo "usage: attack_sim.sh <decoy> [<decoy> ...]" >&2
    exit 2
fi

for f in "$@"; do
    case "$f" in
        /etc/*|/usr/*|/bin/*|/sbin/*|/boot/*|/sys/*|/proc/*|/dev/*|/var/*)
            echo "attack_sim: refusing system path: $f" >&2
            exit 2
            ;;
    esac
    if [ ! -f "$f" ]; then
        echo "attack_sim: not a file: $f" >&2
        exit 2
    fi
done

# stage 1: silent in-place overwrite of the first target
# (simulates targeted tampering, e.g. a dropper rewriting config)
head -c 4096 /dev/urandom > "$1"
echo "[sim] overwrote  $1"

# stage 2: rename the second target, if given
# (simulates staging before bulk encryption)
if [ $# -ge 2 ]; then
    mv "$2" "$2.locked"
    echo "[sim] renamed    $2 -> $2.locked"
fi

# stage 3: rename the third target and delete it, if given
# (simulates rotate-delete behavior seen in wiper-style runs)
if [ $# -ge 3 ]; then
    mv "$3" "$3.tmp0" && rm -f "$3.tmp0"
    echo "[sim] destroyed  $3"
fi

echo "[sim] done - run 'hellhound check' to confirm the bites were recorded"
