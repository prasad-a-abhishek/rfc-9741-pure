#!/bin/bash
# F-016 reproducer: cmd_encode base10 int(' ') uncaught exception
set -e
PYTHONPATH=src python3 -m rfc9741pure.cli encode base10 ' ' 2>&1 | head -5
echo "EXIT=$?"
