# F-014 — `cli.cmd_encode` literal_eval paths leak Python traceback

## Severity

**Low** (UX bug, not a security issue)

This is a CL-level output-quality defect. The CLI prints a raw CPython
`ValueError`/`SyntaxError` traceback to stderr instead of the
"ERROR:invalid input for base ..." message that every other cmd_encode
failure path emits. It does NOT crash the process (exit code is 1, same
as any handled error), does NOT execute any attacker-controlled code
(`ast.literal_eval` is a SafeLoader that rejects calls and attribute
access — F-003's RCE family was remediated at 5009552), and does NOT
leak any data that the CLI wouldn't already accept as input.

## Surface

`cli.cmd_encode(base, text)` in `src/rfc9741pure/cli.py:49-69`. Two of
the seven dispatch branches go through `ast.literal_eval(t)`:

```python
"printf": lambda t: format_printf(*ast.literal_eval(t)),  # cli.py:57
"json":   lambda t: encode_json(ast.literal_eval(t)),       # cli.py:58
```

Both branches raise `ValueError` (malformed nodes — `1+1`, `globals()`,
`open('/tmp/pwn_test.txt', 'w').write('pwned')`, `[x for x in 1..10]`,
...) or `SyntaxError` (`import os`, `[1,2,`, `(1,`, `{'a':`, etc.).

## Root cause

`cmd_encode` calls `result = fn(text)` at `cli.py:64` with no
try/except. The library functions below (`encode_json`, `format_printf`)
return a structured `ERROR:...` string for any *valid* literal they
don't recognise, but they never see the input — `ast.literal_eval`
raises first and the exception escapes the dispatch lambda and the
caller.

The `cmd_encode` flow already has a clean error-shape at lines 65-67
(`if isinstance(result, str) and result.startswith("ERROR:"):`) but
that branch is unreachable when the exception is raised above it.

## Reproduction (minimised)

```text
# minimized_input.txt content (3 bytes, ASCII):
1+1

# Invoked as:
PYTHONPATH=src python3 -m rfc9741pure.cli encode json '1+1'
```

Confirmed to leak on this server with CPython 3.11:

```
Traceback (most recent call last):
  ...
  File ".../rfc9741pure/cli.py", line 58, in <lambda>
    "json": lambda t: encode_json(ast.literal_eval(t)),
                                  ^^^^^^^^^^^^^^^^^^^
  ...
ValueError: malformed node or string on line 1: <ast.BinOp object at 0xffff...>
```

Full Python traceback in `stack_trace.txt`. Other F-014 inputs that
land on the same unhandled site (cmd_encode_000013_04, _000073_19,
_000011_03, _000017_06, _000036_10, _000041_11, _000051_13,
_000054_14, _000071_18 in `cycle_165/adversary/crashes/cmd_encode/`):
`'import os'`, `'[1,2,'`, `'open(...)'`, `'(1,'`, `'0'`, `'[x for x in
1..10]'`, `"{'a': 1, 'b': 2}"`, `'globals()'`.

## Security assessment

- **No RCE.** `ast.literal_eval` is a documented safe loader: it
  parses to an AST and rejects any `Call`, `Attribute`, `Subscript`,
  `FunctionDef`, `Import`, `Lambda`, `BoolOp`, `BinOp`, `Compare`,
  `IfExp`, `DictComp`, `SetComp`, `GeneratorExp`, etc. The full
  attack surface for "RCE via ast.literal_eval" is empty by design.
- **No info leak.** The traceback only shows the CLI's own
  `cli.py:58 <lambda>` line and the internal `ast.py` frames — neither
  contains user data, env vars, file paths outside the worktree, or
  library internals beyond the public Python AST module path.
- **No DoS.** Exception is bounded; `ast.literal_eval` runs in C and
  raises immediately on the first invalid node.
- **No code path where an attacker controls the traceback text.**
  The traceback format is fixed; only the memory address of the
  AST node varies between runs (`<<ast.BinOp object at 0x...>>`).

## Fix recommendation

Wrap the `fn(text)` call in `cmd_encode` at `cli.py:64` in a broad
try/except that converts `ValueError`, `SyntaxError`, and
`UnicodeError` into the same `ERROR:...` stderr shape as the rest of
the CLI:

```python
try:
    result = fn(text)
except (ValueError, SyntaxError, UnicodeError) as e:
    print(f"ERROR:invalid input for base '{base}': {type(e).__name__}",
          file=sys.stderr)
    return 1
```

This is a 4-line patch. The T3 CORPUS_RUN already recommended this
fix in its `downstream_recommended` field; see TRIAGE.md "Recom-
mendations" for the cycle_166 workstream plan.

## Disposition

Already documented in `cycle_165/adversary/VULN_AUDIT.md` (T1
re-audit) as a known Low. No new information introduced by this
campaign — F-014 is re-confirmed at 25,768 unhandled exceptions
across 75K cmd_encode iters + the new F-016 base10 family adds a
parallel path that the same fix will cover.

**Status: ANALYSED. Deferred to cycle_166 (Low-priority CLI polish).**