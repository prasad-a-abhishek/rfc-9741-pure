#!/bin/bash
# F-003 regression: RCE payload must be REJECTED (no /tmp/pwn_test_*.txt created)
set -e
rm -f /tmp/pwn_test_*.txt
PYTHONPATH=src python3 -m rfc9741pure.cli encode json "__import__('os').system('echo PWNED > /tmp/pwn_test_rce.txt')" 2>&1 | head -3
echo "EXIT=$?"
echo "Checking for RCE side-effect file:"
ls -la /tmp/pwn_test_*.txt 2>&1 || echo "OK: no RCE file created (F-003 fix verified)"
