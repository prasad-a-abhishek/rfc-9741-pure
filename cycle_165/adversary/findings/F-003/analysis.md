# F-003 (regression test) — cli.cmd_encode cannot do RCE via eval()

## Severity

**n/a (regression-check PASS, originally High)**

Regression test for the High F-003 finding from the original
VULN_AUDIT (cycle_165/adversary/T1 at 8bdecaf). F-003 was remediated
at commit **5009552**.

## Original bug (pre-5009552)

`cli.cmd_encode` used Python `eval()` on the user-supplied text:

```python
"printf": lambda t: format_printf(*eval(t)),  # BAD: eval is full Python
"json":   lambda t: encode_json(eval(t)),      # BAD: eval is full Python
```

An attacker who could pass `__import__('os').system('...')`,
`open('/tmp/pwn','w').write('...')`, `(1).__class__.__mro__[1].
__subclasses__()`, etc. would get arbitrary code execution in the
CLI's Python process.

## Surface

`src/rfc9741pure/cli.py:57-58` (the printf and json dispatch lambdas).

## Fix (commit 5009552)

```python
"printf": lambda t: format_printf(*ast.literal_eval(t)),  # literal_eval: no calls/imports
"json":   lambda t: encode_json(ast.literal_eval(t)),       # literal_eval: no calls/imports
```

`ast.literal_eval` is documented as a SafeLoader: it parses to an
AST, walks the tree, and raises `ValueError` for any node type
other than the literal scalars `Constant` (str/int/float/bool/None)
and the immutable containers `Tuple`, `List`, `Dict`, `Set`. Calls,
attribute access, subscripting, comprehensions, boolean ops, binary
ops, comparisons, lambdas, definitions, imports — all rejected at the
AST level before any bytecode is generated.

## Regression test evidence

- **Static (pytest)**: `tests/test_cli.py::TestCliVulnAuditFixes` was
  added in the same commit. The fuzz campaign didn't need to find a
  new bug here because pytest already locks the RCE contract.
- **Fuzz (this campaign)**: 75K iterations of `cmd_encode` with the
  RCE-payload corpora. The harness distinguishes "CLI crash" (a
  Traceback) from "RCE" (no Traceback because the code ran).
  - `cycle_165/adversary/fuzz/cmd_encode_stats.json` — iter=75000,
    crashes=0, unhandled=25768 (all F-014 traceback family, **0 RCE**)

## Reproduction (minimised)

```text
# minimized_input.txt content:
__import__('os').system('touch /tmp/pwn_test_F003')

# Invoked as:
PYTHONPATH=src python3 -m rfc9741pure.cli encode json \
    "__import__('os').system('touch /tmp/pwn_test_F003')"
# Post-fix behaviour:
#   - ValueError raised by ast.literal_eval (F-014 traceback leak)
#   - /tmp/pwn_test_F003 NOT created
```

## Side note: the F-014 family is a *separate* Low

The F-003 fix does NOT fix the F-014 traceback leak. F-014 is a
post-fix UX defect on the SAME unhandled site — `cmd_encode` does
not catch the `ValueError` from `ast.literal_eval` for malformed
inputs (see `cycle_165/adversary/findings/F-014/`). F-014 is
documented separately and deferred to cycle_166. F-003's
remediation here is solely about eliminating RCE, which it does.

## Disposition

The fix is in place and zero High CVE instances have been observed
in this campaign.

**Status: PASS. Closed.**