#!/bin/bash
# F-014 reproducer: cmd_encode literal_eval rejects 'import os' (good) but uncaught traceback (bad)
set -e
PYTHONPATH=src python3 -m rfc9741pure.cli encode printf 'import os' 2>&1 | head -5
echo "EXIT=$?"
