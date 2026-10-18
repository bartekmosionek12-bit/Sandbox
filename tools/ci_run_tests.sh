#!/usr/bin/env bash
# Run by CI inside the network block: prove the block works, then run the suite
# with the interpreter of the venv that holds the installed wheels.
set -euo pipefail
BIN="$1"
"$BIN/python" tools/assert_offline.py
"$BIN/python" -m pytest -q -p no:cacheprovider
