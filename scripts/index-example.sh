#!/usr/bin/env bash
set -euo pipefail

THEZOO_PATH="${1:-/opt/theZoo}"
DB_PATH="${2:-zoo-indexer.sqlite3}"

python3 main.py --db "${DB_PATH}" index "${THEZOO_PATH}"
python3 main.py --db "${DB_PATH}" search --type ransomware
