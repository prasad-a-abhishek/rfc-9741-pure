# corpus/cli_main — no dedicated reproducers

The cli_main harness reuses the cmd_encode reproducer scripts (the
underlying `cmd_encode` function is the same; cli_main just adds
the `validate` command and `decode` command paths on top). The
findings surfaced by cli_main (F-014, F-017 NUL bytes) are
documented in cycle_165/adversary/findings.jsonl and
cycle_165/adversary/CORPUS_RUN.md §5.
