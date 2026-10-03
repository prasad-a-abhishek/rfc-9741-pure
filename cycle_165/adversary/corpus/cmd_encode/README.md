# corpus/cmd_encode — F-014/F-016/F-003 reproducer scripts

These shell scripts reproduce the F-014 (literal_eval uncaught),
F-016 (int() uncaught for base10), and F-003 (RCE blocked)
findings from the T3 fuzz campaign. Each script exits with the
exact exit code the fuzz harness observed.

Run from the repo root:

    bash cycle_165/adversary/corpus/cmd_encode/repro_f014_1plus1.sh
    bash cycle_165/adversary/corpus/cmd_encode/repro_f014_importos.sh
    bash cycle_165/adversary/corpus/cmd_encode/repro_f016_base10_empty.sh
    bash cycle_165/adversary/corpus/cmd_encode/repro_f016_base10_space.sh
    bash cycle_165/adversary/corpus/cmd_encode/repro_f003_rce_blocked.sh

Expected (post-T3 campaign):
- F-014: traceback to stderr, EXIT=1 (uncaught literal_eval exception)
- F-016: traceback to stderr, EXIT=1 (uncaught int() exception)
- F-003: traceback to stderr, EXIT=1, no /tmp/pwn_test_*.txt created
