# F-016 — `cli.cmd_encode` base10 path uncaught `int()` ValueError

## Severity

**Low** (UX bug, parallel to F-014)

Same class of defect as F-014 (uncaught exception leaks a Python
traceback to stderr in `cmd_encode`) but on a different unhandled
site. No security implication.

## Surface

`cli.cmd_encode(base, text)` in `src/rfc9741pure/cli.py:56`:

```python
"base10": lambda t: encode_base10(int(t)),
```

This dispatch lambda calls `int(t)` directly on user-supplied `text`
without any try/except. The library function `decode_base10` IS
robust (it has `_BASE10_RE.match(target)` guarding the conversion and
returns `"ERROR:decode_base10: invalid format '...'"` for malformed
input — see `_base10.py:47-61`), but `cmd_encode` never calls
`decode_base10` for the encode direction; it goes via `int(t)` →
`encode_base10(int)`.

## Root cause

`cli.py:56` bypasses the library's own `_base10.py` validation by
calling `int()` directly inside the dispatch lambda. The lambda has
no try/except, so `int(' ')`, `int('')`, `int('abc')`, `int('\\n')`,
`int('{...}')`, `int(<non-numeric unicode>)` all raise
`ValueError` and the exception escapes the caller.

## Reproduction (minimised)

```text
# minimized_input.txt content (1 byte, ASCII space):
<SPACE>

# Invoked as:
PYTHONPATH=src python3 -m rfc9741pure.cli encode base10 ' '
```

Full stack trace in `stack_trace.txt`. Other F-016 inputs that
reproduce on the same `int(t)` site (cmd_encode_000015_05,
_000026_08, _000024_07, _000032_09, _000051_13, _000071_18,
_000069_17, _000057_15 in
`cycle_165/adversary/crashes/cmd_encode/`): `''`, `'\\n'`,
`'\\U0010ba17\\U0010976b...'`,
`'娼瓥儷㊤ꤩ\\uf110...'`,
`"{'a': 1, 'b': 2}"`,
`"<unicode noise>"`, etc.

## Security assessment

- **No RCE.** `int()` is a builtin that takes exactly one string and
  returns one int. The set of inputs that raise `ValueError` is the
  same set that the library's `_BASE10_RE` would have rejected;
  there is no `__int__` dunder trick available because the input is
  already a `str` from `sys.argv[3]`.
- **No info leak.** Same argument as F-014: traceback only exposes
  `cli.py:56 <lambda>` and the `int()` builtin, both of which are
  already public knowledge about the CLI's surface.
- **No DoS.** `int()` raises immediately on the first non-digit; the
  harness's 5-second timeout was never tripped on F-016.

## Why F-014 docs didn't catch this

The T1 re-audit's `VULN_AUDIT.md` documented F-014 as
"`cmd_encode` literal_eval path doesn't catch ValueError/SyntaxError".
That audit only inspected the printf and json lambdas (which both
wrap `ast.literal_eval`). It did not flag the base10 lambda's
unprotected `int(t)`. F-016 is the same defect discovered on a
parallel dispatch branch.

## Fix recommendation

The same fix as F-014 covers this:

```python
try:
    result = fn(text)
except (ValueError, SyntaxError, UnicodeError) as e:
    print(f"ERROR:invalid input for base '{base}': {type(e).__name__}",
          file=sys.stderr)
    return 1
```

A library-side alternative: call the existing robust `decode_base10`
in the cmd_encode base10 branch (since the user is asking to encode
the decimal representation of some value, the value is whatever
`decode_base10(text)` returns, then `encode_base10(...)` re-emits it
in canonical form — and `decode_base10` already returns
"ERROR:..." on invalid input). But the simpler try/except around the
whole dispatch table covers F-014 + F-016 + F-017 family in 4 lines.

## Disposition

Discovered NEW by this fuzz campaign (T3). Same fix as F-014;
defer to the same cycle_166 workstream.

**Status: ANALYSED. Deferred to cycle_166 (Low-priority CLI polish).**