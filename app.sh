#!/bin/sh
# HOST3R — point d'entrée
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    echo "Usage: $0 -d <domain> [-o <output>] [-v] [-e] [-6]"
    exit 1
}

[ "$#" -ge 2 ] || usage

exec python3 "$SCRIPT_DIR/app/host3r.py" "$@"
