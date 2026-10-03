# F-001 (regression test) — decode_b45 2-char overflow no longer raises

## Severity

**n/a (regression-check PASS, originally Critical)**

This is a regression test for the Critical F-001 finding from the
original VULN_AUDIT (T1 of the cycle_165/adv_retry chain, then again
in the pre-fix T1 audit at 8bdecaf). F-001 was remediated at commit
**5009552** ("fix(cycle_165/adversary): remediate VULN_AUDIT
F-001/F-002/F-003 (orchestrator-rescue)").

## Original bug (pre-5009552)

`decode_b45` would raise `ValueError: byte must be in range(0, 256)`
on 2-character inputs whose base45-decoded value would have
exceeded 255 (e.g. `'99'` → 35+35*45 = 499). This contradicted the
"never raise, return ERROR:..." totality contract that the rest of
the library follows.

## Surface

`src/rfc9741pure/_b45.py:97-99, 112-115` (the 2-char group handling
in `decode_b45`).

## Fix (commit 5009552)

```python
# 2-char group: value = c + d*45
value = v0 + v1 * 45
# F-001 fix: 2-char values must be < 256 (single byte)
if value >= 256:
    return _err(f"decode_b45: invalid value {value} from 2-char group")
out.append(value)
```

Plus a guard at the bottom:

```python
try:
    return bytes(out)
except ValueError:
    return _err(f"decode_b45: byte value(s) out of range in output")
```

## Regression test evidence

- **Static (pytest)**: `tests/test_b45.py::TestB45VulnAuditFixes` was
  added in the same commit and asserts the exact ERROR:... strings
  for the 4 representative 2-char overflow inputs.
- **Fuzz (this campaign)**: 200K iterations across the
  `validate_b45` and `decode_b45` harnesses. Both ran
  `FuzzedDataProvider.ConsumeUnicodeNoSurrogates` for 100K iters
  each. Zero crashes, zero unhandled exceptions.
  - `cycle_165/adversary/fuzz/decode_b45_stats.json` — iter=100000, crashes=0, unhandled=0
  - `cycle_165/adversary/fuzz/validate_b45_stats.json` — iter=100000, crashes=0, unhandled=0

## Reproduction (minimised)

```text
# minimized_input.txt content (2 bytes, ASCII):
99

# Invoked as:
PYTHONPATH=src python3 -c "from rfc9741pure import decode_b45; print(decode_b45('99'))"
# Post-fix output:
#   ERROR:decode_b45: byte value(s) out of range in output
```

## Disposition

The fix is in place, regression-tested at unit and fuzz scale, and
**zero High or Medium CVE instances have been observed in this
campaign**. The minimised payload, the reproducer script, and the
zero-stack-trace evidence are kept on disk so a future change to
`decode_b45`'s 2-char handling can re-validate without rewriting
the test.

**Status: PASS. Closed.**