# F-017 — Harness-only NUL-byte subprocess guard noise

## Severity

**Info (instrumentation noise, NOT a library bug)**

## Surface

`cycle_165/adversary/fuzz/{cmd_encode,cli_main}.py` — the harness
itself, not any library code.

The two CLI harnesses shell out to the rfc9741pure CLI via
`subprocess.run([sys.executable, "-m", "rfc9741pure.cli", ...,
text])`. When `atheris.FuzzedDataProvider.ConsumeUnicodeNoSurrogates`
happens to produce a `str` containing an embedded `'\x00'`,
`subprocess.run` rejects the argv list before fork() with
`ValueError: embedded null byte`. The harness catches this in its
"subprocess runner failed" branch and records an
`AssertionError("subprocess runner failed: SUBPROCESS_ERROR:
ValueError: embedded null byte")` event in the stats.json's
`exceptions_caught` list.

This is exactly the behaviour the harness's error reporter was
designed to handle, but it inflates the `unhandled_exceptions` count
on the affected runs.

## Root cause

`subprocess.run` enforces a POSIX argument-termination guard
(`subprocess.py:_execute_child` raises `ValueError("embedded null
byte")` if any argv element contains `'\x00'`). This is a Python
language design decision and is identical across Linux/macOS/BSD.

This guard exists because C-level `execvp` terminates string
arguments at the first NUL, so passing `'\x00'` through `argv` would
be ambiguous and a known source of argument-injection CVEs. The
guard is in CPython, not in our harness or library.

## Reproduction (minimised)

```text
# minimized_input.txt content (3 bytes):
a\x00b   # (literal bytes 0x61 0x00 0x62)

# Harness call (simulating what FuzzedDataProvider produced):
subprocess.run([sys.executable, "-m", "rfc9741pure.cli",
                "encode", "base10", text])
# raises ValueError: embedded null byte
```

Full traceback in `stack_trace.txt`.

## Why this is NOT a library finding

The rfc9741pure library itself handles NUL bytes correctly across
all surfaces:

```python
>>> decode_b45(chr(0))
"ERROR:decode_b45: invalid character '\\x00'"
>>> validate_b45('AB', b'a\x00')
False
>>> encode_b45(b'a\x00b')
'$BC82'
```

If the library DID mishandle NUL bytes, we would expect to see
crashes in the in-Python harnesses (`validate_b45`, `decode_b45`,
`encode_b45`, `invariant21`) — which collectively ran 400K
iterations with FDP-generated inputs. None of those harnesses
reported any unhandled exception, including on NUT-byte-containing
inputs.

## Why this is NOT a security finding in the CLI

The CLI is invoked as a *subprocess* by the harness. A real user
typing `rfc9741pure encode base10 $USER_INPUT` at a shell prompt is
subject to the same NUL-guard at the shell level (most shells pass
NUL as a string-termination sentinel before exec). The CLI itself is
never invoked with a NUL byte, so there is no input-validation
defect to fix.

## Fix recommendation

Harness-side, not library-side. In the next cycle's fuzz campaign:

```python
def _safe_text(s: str) -> str:
    """Strip NUL bytes before passing to subprocess.run."""
    return s.replace("\x00", "")
```

Add this to `cycle_166/adversary/fuzz/{cmd_encode,cli_main}.py`
before the `subprocess.run(...)` call.

## Evidence trail

- cmd_encode_000000_00.stack: iter 0, embedded NUL
- cli_main_000003_00.stack, _000006_01.stack, _000012_03.stack,
  _000014_05.stack, _000017_06.stack, _000031_12.stack,
  _000056_14.stack, _000059_15.stack, _000068_19.stack: 9 NUL
  failures on cli_main harness
- Total: 10 NUL failures across both harnesses (1 + 9).

## Disposition

Info-only; not a defect. Recorded for future-campaign hygiene.

**Status: ANALYSED. Closed — no library remediation needed.**