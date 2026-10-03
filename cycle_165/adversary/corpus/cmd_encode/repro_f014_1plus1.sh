#!/bin/bash
# F-014 reproducer: cmd_encode literal_eval uncaught exception
# Run from repo root: bash cycle_165/adversary/corpus/cmd_encode/repro_f014_1plus1.sh
set -e
PYTHONPATH=src python3 -m rfc9741pure.cli encode json '1+1' 2>&1 | head -5
echo "EXIT=$?"
