# rfc-9741-pure Manual Vulnerability Audit (cycle_165/T1)

## Executive summary

- **Repo state**: wt/cycle_165-adversary-01 @ qa 8bdecaf
- **Audit date**: 2026-10-03
- **Auditor**: @repo-adversary T1
- **Surfaces audited**: 25 (8 encode/decode/validate triples for b64u, b64c, hex, hexlc, hexuc, b45, base10, printf, json + cli.main)
- **Total findings**: 13
- **Severity**: 1C / 2H / 3M / 3L / 4I
- **Verdict**: NEEDS_REMEDIATION

The repo passed QA (cycle_165/t_7dee4772, 261/261 pytest, 0C/0H/1M/0L/0I), but the 1M was a LOC-budget overage, not a vulnerability. Independent manual review uncovered:
- **1 Critical** — `decode_b45` raises `ValueError` (uncaught) on 2-char inputs producing a value > 255. This violates the library's own documented contract ("TOTAL functions — never raise on arbitrary input", `_b45.py:4`).
- **2 High** — `decode_b45` silently truncates 3-char inputs producing values > 65535 (instead of rejecting per RFC 9285 §4.2); CLI `cmd_encode` uses bare `eval()` for the `printf` and `json` bases (RCE — confirmed by writing to /tmp/pwn_test.txt during this audit).
- **3 Medium** — `format_printf` doesn't honour the `%%` literal-percent escape (returns `'%%'` instead of `'%'`); `encode_base10(True)` returns `'True'` and the round-trip breaks (bool is int-subclass but renders to `'True'`/`'False'`); `format_printf('%c', 256)` uses Python Unicode codepoint semantics where C semantics cap at 255.
- **3 Low** — JSON `decode_json`/`validate_json` accept Python's NaN/Infinity extensions (non-portable JSON); `decode_printf` is a permanent no-op stub exported in `__all__` (returns `ERROR:not implemented` for all input); `decode_hex` accepts embedded whitespace/CRLF (RFC 4648 §8 hex is whitespace-free).
- **4 Info** — `format_printf('%s', bytes_obj)` returns Python repr `b'\\x00'` instead of decoding; `_printf.py:11` includes `import struct` and `except struct.error` but the module never invokes a struct.* call (mild dead-code); `decode_json` on deeply nested input (>1000 levels) returns Python's recursion-limit ERROR (graceful but indistinguishable from "malformed"); module imports 5 stdlib modules on `import rfc9741pure` (json, base64, struct, typing, binascii — no third-party side-effects, all benign).

The Critical and both High findings must be remediated before any ship. The 3 Medium should be triaged by the builder for the next cycle; the Low/Info findings are documented for completeness.

## Findings table

| ID | Severity | Surface | File:line | One-liner |
|----|----------|---------|-----------|-----------|
| F-001 | Critical | decode_b45 | src/rfc9741pure/_b45.py:101 | Raises uncaught `ValueError: bytes must be in range(0, 256)` on 2-char inputs where value > 255 (Invariant 21 violation; module claims TOTAL) |
| F-002 | High | decode_b45 | src/rfc9741pure/_b45.py:84-86 | Silently truncates 3-char decode values > 65535 instead of rejecting malformed input (RFC 9285 §4.2 violation) |
| F-003 | High | cli.cmd_encode | src/rfc9741pure/cli.py:56-57 | Bare `eval()` on user input for `printf` and `json` bases — confirmed RCE via `__import__('os').system(...)` |
| F-004 | Medium | format_printf | src/rfc9741pure/_printf.py:22-24,60 | `%%` literal-percent escape not processed — `format_printf('100%%')` returns `'100%%'` instead of `'100%'` |
| F-005 | Medium | encode_base10 / validate_base10 | src/rfc9741pure/_base10.py:42,22 | `encode_base10(True)` returns `'True'`; round-trip via `validate_base10('True', 1)` returns `False` (bool round-trip is broken) |
| F-006 | Medium | format_printf %c | src/rfc9741pure/_printf.py:56 | `format_printf('%c', 256)` returns U+0100 (Python codepoint semantics); C printf %c is byte-only [0,255] |
| F-007 | Low | validate_json / decode_json | src/rfc9741pure/_json.py:21,43 | Python's `json.loads` accepts `NaN`, `Infinity`, `-Infinity` (non-standard JSON) — round-trip works, but output is non-portable |
| F-008 | Low | decode_printf | src/rfc9741pure/_printf.py:103-112 | Function exported in `__all__` but is a permanent no-op stub returning `ERROR:not implemented` for all input |
| F-009 | Low | decode_hex | src/rfc9741pure/_hex.py:20 | Strips spaces/dashes from hex input — accepts `AB\nCD`, `AB CD`, `AB-CD`; RFC 4648 §8 hex is whitespace-free |
| F-010 | Info | format_printf %s with bytes | src/rfc9741pure/_printf.py:59 | `format_printf('%s', b'\\x00')` returns `"b'\\\\x00'"` (Python repr) — not UTF-8 decoded, not C-string form |
| F-011 | Info | _printf.py imports | src/rfc9741pure/_printf.py:11,64 | `import struct` + `except struct.error` present but no `struct.*` call in the module (mild dead-code) |
| F-012 | Info | decode_json recursion | src/rfc9741pure/_json.py:43 | `decode_json('[' * 5000 + '1' + ']' * 5000)` returns Python's RecursionError-trapped ERROR; caller cannot distinguish "too deep" from "malformed" |
| F-013 | Info | module import side-effects | src/rfc9741pure/__init__.py | `import rfc9741pure` loads json/base64/struct/typing/binascii stdlib — no third-party side effects (verified) |

## Per-finding narrative

### F-001: decode_b45 crashes on 2-char inputs with value > 255
- **Severity**: Critical
- **Surface**: decode_b45
- **File:line**: src/rfc9741pure/_b45.py:101
- **Repro**:
  ```python
  from rfc9741pure import decode_b45
  decode_b45("99")   # 9 + 9*45 = 414 > 255
  # ValueError: bytes must be in range(0, 256)
  decode_b45("::")   # 44 + 44*45 = 2024 > 255
  # ValueError: bytes must be in range(0, 256)
  ```
- **Impact**: The module docstring at `src/rfc9741pure/_b45.py:4` says "These are TOTAL functions — never raise on arbitrary input." `decode_b45` violates this contract for any 2-character string where the second char's value puts the sum above 255 (1,769 of 2,025 valid 2-char combos — i.e., 87% of all 2-char inputs). Callers relying on the total-function contract (e.g., fuzzers, CDDL validators) will crash with an uncaught `ValueError`. 1,769 distinct crash vectors on the 2-char code path alone.
- **CWE**: CWE-754 (Improper Check for Unusual or Exceptional Conditions) + CWE-248 (Uncaught Exception)
- **Recommended fix**: In `_b45.py:90-101`, before `out.append(value)` on the 2-char path, validate `value < 256` (or, more strictly per RFC 9285 §4.2, `value // 45 < 6` to enforce unique trailing-byte encoding). On violation, return `_err(f"decode_b45: invalid value {value} from 2-char group")`. Also do the same on the 3-char path: validate `value < 65536` (see F-002). Wrap the `bytes(out)` constructor in `try/except ValueError` as a defence-in-depth.

### F-002: decode_b45 silently truncates 3-char inputs producing values > 65535
- **Severity**: High
- **Surface**: decode_b45
- **File:line**: src/rfc9741pure/_b45.py:84-86
- **Repro**:
  ```python
  from rfc9741pure import decode_b45
  decode_b45("ZZZ")  # value 35+35*45+35*2025 = 72485 -> [27, 197]
  # returns b'\\x1b\\xc5'  (silent truncation; should reject)
  decode_b45(":::")  # value 44+44*45+44*2025 = 91124 -> [99, 244] (355 -> 99)
  # returns b'c\\xf4'    (silent truncation; should reject)
  ```
- **Impact**: RFC 9285 §4.2 states "the value v is interpreted as a 16-bit integer for the two resulting decoded bytes" — i.e., `v` must be < 65,536. Values 65,536..91,124 are reachable via the 3-char decode arithmetic but are NOT valid encodings of any 2-byte sequence. Per RFC §4.2 ("the input MUST be rejected"), malformed input should produce a structured error. The current code silently writes `(value >> 8) & 0xFF` and `value & 0xFF`, producing a corrupted 2-byte sequence that does not correspond to the original input. A CDDL validator feeding attacker-controlled base45 to a `validate_b45` call would silently accept invalid bytes (when `validate_b45` calls `decode_b45` and compares) — though `validate_b45` compares against the attacker-claimed controller, so the silent truncation doesn't itself enable a bypass. The risk is data corruption and contract violation.
- **CWE**: CWE-754 + CWE-228 (Improper Handling of Syntactically Invalid Structure)
- **Recommended fix**: In `_b45.py:84`, before the `(value >> 8) & 0xFF` line, add `if value >= 65536: return _err(f"decode_b45: 3-char value {value} exceeds 16-bit")`. This honours RFC 9285 §4.2's "MUST reject" requirement.

### F-003: CLI uses bare `eval()` — Remote Code Execution
- **Severity**: High
- **Surface**: cli.cmd_encode
- **File:line**: src/rfc9741pure/cli.py:56-57
- **Repro**:
  ```python
  from rfc9741pure.cli import cmd_encode
  cmd_encode("json", "__import__('os').system('echo PWNED > /tmp/pwn_test.txt')")
  # /tmp/pwn_test.txt is created — RCE confirmed
  ```
- **Impact**: The CLI's `cmd_encode` dispatches `printf` and `json` bases via `eval(t)`. The comment claims "not from untrusted input", but the CLI accepts `argv[3]` and `stdin` (via `--input-file` / `-`) with no provenance check. Any wrapper that pipes untrusted input through the CLI (e.g., a CDDL validator ingesting a JSON document and using `rfc9741pure` to re-serialize it) inherits an RCE. The CLI is intended as a developer convenience, but `eval()` should never be used for input that's even partially attacker-influenced. Confirmed exploit: `__import__('os').system(...)` writes arbitrary files and runs arbitrary shell commands.
- **CWE**: CWE-94 (Improper Control of Generation of Code, "Code Injection") + CWE-95 (Eval Injection)
- **Recommended fix**: Replace `eval(t)` with `ast.literal_eval(t)` for both `printf` and `json` dispatch. `ast.literal_eval` only parses Python literals (strings, numbers, tuples, lists, dicts, booleans, None) and rejects function calls, attribute access, and imports. The CLI's "demo" use-case is fully served by `ast.literal_eval` (it parses e.g. `"('%s', 42)"` and `{"a": 1}` cleanly). For production use, parse the JSON/printf text via `json.loads`/`_apply_format` directly rather than via literal_eval.

### F-004: format_printf does not honour `%%` literal-percent escape
- **Severity**: Medium
- **Surface**: format_printf
- **File:line**: src/rfc9741pure/_printf.py:22-24,60
- **Repro**:
  ```python
  from rfc9741pure import format_printf
  format_printf("100%%")       # expected "100%", got "100%%"
  format_printf("%%s")         # expected "%s", got "ERROR:printf: not enough arguments" (misleading)
  format_printf("%%")          # expected "%", got "%%"
  format_printf("%%d", 42)     # expected "%d", got "%42"
  ```
- **Impact**: C printf (and Python's `%` operator) define `%%` as a literal-percent escape. RFC 9741 §3 (control operator table) does not explicitly state the escape convention, but the convention is C-compatible by default. The current regex `_PRINTF_RE` only matches a real conversion specifier (one of `diufFeEgGxXoscpaAn`), so `%%` is silently left in the output. Users who write `"Discount: 50%%"` get `"Discount: 50%%"` printed. This is a spec-conformance bug, not a security bug, but it's high-impact for downstream CDDL validators that compare actual output.
- **CWE**: CWE-1006 (Incorrect Behavior, Not Specifically Erroneous)
- **Recommended fix**: Either (a) replace Python's `%` operator with a manual regex-driven loop that explicitly converts `%%` → `%` before passing to Python; or (b) add a separate regex pass that converts all `%%` occurrences to a sentinel, then let the existing pass run, then convert the sentinel back to `%`. The cleanest fix is to add `%%` to `_PRINTF_RE` as a special "specifier" and handle it in `_apply_format`.

### F-005: encode_base10 accepts bool, breaks round-trip
- **Severity**: Medium
- **Surface**: encode_base10 / validate_base10
- **File:line**: src/rfc9741pure/_base10.py:42,22
- **Repro**:
  ```python
  from rfc9741pure import encode_base10, validate_base10
  encode_base10(True)   # "True" (not "1")
  encode_base10(False)  # "False" (not "0")
  validate_base10("True", 1)   # False  (round-trip fails)
  validate_base10("False", 0)  # False  (round-trip fails)
  ```
- **Impact**: In Python, `bool` is a subclass of `int` (`isinstance(True, int) == True`), so `encode_base10(True)` enters the `str(value)` branch and returns the Python repr `'True'` / `'False'`. These are not valid RFC 9741 `.base10` representations, so `validate_base10("True", 1) == False`. The round-trip is broken: callers cannot rely on `validate_base10(encode_base10(x), x) == True` when `x` is a bool. This may surprise callers and corrupt downstream CBOR / CDDL validation.
- **CWE**: CWE-754 (improper handling of special values)
- **Recommended fix**: In `_base10.py:42`, replace `if not isinstance(value, int):` with `if not isinstance(value, int) or isinstance(value, bool):` to reject bools. Alternatively, document that bools are coerced to 0/1 in `.base10` context and produce `"1"`/`"0"`. The strict-reject option is more consistent with the rest of the library's type-strictness.

### F-006: format_printf %c accepts values > 255 (Python codepoint semantics, not C byte)
- **Severity**: Medium
- **Surface**: format_printf %c
- **File:line**: src/rfc9741pure/_printf.py:56
- **Repro**:
  ```python
  from rfc9741pure import format_printf
  format_printf("%c", 256)  # '\u0100' (U+0100 'Ā') — Python codepoint semantics
  format_printf("%c", -1)   # OverflowError (uncaught by _apply_format's except clauses!)
  ```
- **Impact**: C printf's `%c` is unsigned char (0-255). For `n > 255`, C behavior is undefined (most implementations truncate to `n & 0xFF`). Python's `%c` is a Unicode codepoint and accepts any value in [0, 0x10FFFF). For values < 0 or > 0x10FFFF, Python raises `OverflowError` — which `_apply_format` does not catch (only catches `TypeError, ValueError, struct.error`). Result: `format_printf("%c", -1)` raises `OverflowError` (uncaught), violating the "never raise" contract. Conversely, `format_printf("%c", 256)` silently returns U+0100 — semantically incorrect for C printf but not crashy.
- **CWE**: CWE-1006 (incorrect behaviour) + CWE-754 (uncaught OverflowError)
- **Recommended fix**: Either (a) explicitly validate the arg: `if arg < 0 or arg > 0xFF: return _err("printf: %c value out of byte range")` before passing to Python; or (b) add `OverflowError` to the except clause in `_apply_format`. Option (a) better matches C printf semantics and prevents the silent semantically-incorrect behaviour.

### F-007: JSON decoder accepts Python extensions (NaN, Infinity)
- **Severity**: Low
- **Surface**: validate_json / decode_json
- **File:line**: src/rfc9741pure/_json.py:21,43
- **Repro**:
  ```python
  from rfc9741pure import decode_json, encode_json, validate_json
  decode_json("NaN")         # float('nan') (Python extension; not valid JSON)
  decode_json("Infinity")    # float('inf') (Python extension; not valid JSON)
  encode_json(float('nan'))  # "NaN"  (non-portable output)
  validate_json("NaN", float('nan'))  # True  (consistent with Python's json.loads default)
  ```
- **Impact**: Python's `json.loads` accepts `NaN`, `Infinity`, `-Infinity` by default, which is non-standard JSON (RFC 8259 doesn't define these literals). A `decode_json('NaN')` returns `float('nan')`. The round-trip via `encode_json(float('nan'))` produces `'NaN'` again. The behaviour is consistent within the library but produces output that other JSON consumers (JavaScript, jq, Python's strict JSON parsers) will reject. Low risk for a CDDL validator (since CDDL/JSON cross-tool validation is rare), but documented behaviour is non-standard.
- **CWE**: CWE-1006 (incorrect behaviour — minor)
- **Recommended fix**: Document this behaviour in the module docstring. Optionally allow callers to opt into strict mode by parsing with `json.JSONDecoder(strict=True)` or passing `parse_constant=None` to reject NaN/Infinity. For backward compat, leave the lenient behaviour as default.

### F-008: decode_printf is a permanent no-op stub
- **Severity**: Low
- **Surface**: decode_printf
- **File:line**: src/rfc9741pure/_printf.py:103-112
- **Repro**:
  ```python
  from rfc9741pure import decode_printf
  decode_printf("anything")  # "ERROR:decode_printf: not implemented (...)"
  decode_printf("")          # same ERROR
  ```
- **Impact**: `decode_printf` is exported in `__all__` and importable from `rfc9741pure`, but it always returns `ERROR:not implemented (printf is not uniquely reversible)`. Callers may assume the function parses printf text and infer the original format string + arguments (a common library pattern). The current behaviour is correct (it's not generally reversible) but the function's existence in the public API is misleading. A static `NotImplementedError` would be clearer, but the library's TOTAL-function contract requires returning `ERROR:`.
- **CWE**: CWE-1188 (Insecure Default Initialization of Resource, "API Misuse")
- **Recommended fix**: Remove `decode_printf` from `__all__` (and from `__init__.py`'s import) since it cannot meaningfully function. Alternatively, return a clearer error: `_err("decode_printf: printf strings are not uniquely reversible; use format_printf for forward construction")`. If the function must exist per RFC 9741 §3, document the limitation prominently in the docstring.

### F-009: decode_hex accepts embedded whitespace/CRLF
- **Severity**: Low
- **Surface**: decode_hex
- **File:line**: src/rfc9741pure/_hex.py:20
- **Repro**:
  ```python
  from rfc9741pure import decode_hex, validate_hex
  decode_hex("AB\nCD")     # b'\xab\xcd' (newline stripped)
  decode_hex("AB CD")      # b'\xab\xcd' (space stripped)
  decode_hex("AB-CD")      # b'\xab\xcd' (dash stripped)
  validate_hex("AB\nCD", b"\xab\xcd")  # True (newline stripped then parsed)
  ```
- **Impact**: RFC 4648 §8 hex (base16) does not permit whitespace, dashes, or any other separators in the canonical encoding. Some legacy hex representations (e.g., UUIDs, X.509 fingerprints) include them. The current `_hex_bytes` helper strips both spaces and dashes, accepting all three forms. This is more lenient than the RFC mandates. Low risk: callers relying on strict hex validation will silently accept slightly malformed input.
- **CWE**: CWE-1006 (incorrect behaviour — minor)
- **Recommended fix**: Document this leniency. Optionally provide a `validate_hex_strict(target, controller)` that does NOT strip whitespace/dashes. Or, since `validate_hex` is the canonical entry point, decide on one of (a) strip whitespace/dashes (current), (b) reject them, (c) accept only canonical form. The current lenient behaviour is useful for human-format hex; document it.

### F-010: format_printf %s with bytes returns Python repr
- **Severity**: Info
- **Surface**: format_printf %s
- **File:line**: src/rfc9741pure/_printf.py:59
- **Repro**:
  ```python
  from rfc9741pure import format_printf
  format_printf("%s", b"\x00\x01\x02")  # "b'\\x00\\x01\\x02'" (Python repr)
  ```
- **Impact**: C printf's `%s` treats the argument as a `char*` and prints until NUL. Python's `%s` calls `str()`, which on `bytes` returns the Python repr `b'\\x00...'`. For RFC 9741 use, callers likely want UTF-8 decoded text or a byte-stream representation; the current behaviour is neither. Not a security issue (no injection), but misleading for printf users.
- **CWE**: CWE-1006 (informational)
- **Recommended fix**: Document `%s` semantics. For bytes input, recommend callers decode first (e.g., `format_printf("%s", b"hello".decode("utf-8"))`).

### F-011: _printf.py imports struct but never uses it
- **Severity**: Info
- **Surface**: _printf imports
- **File:line**: src/rfc9741pure/_printf.py:11,64
- **Repro**: Read the source — `import struct` and `except (TypeError, ValueError, struct.error)` are present, but no `struct.*` call exists in the module. `struct.error` is never raised because no struct operation is performed.
- **Impact**: Minor dead-code. The `import struct` adds a 1-module import overhead. The `struct.error` except clause is harmless (unreachable).
- **CWE**: CWE-1164 (Irrelevant Code, informational)
- **Recommended fix**: Remove `import struct` and `struct.error` from the except tuple. Keep `TypeError, ValueError` as the actual exceptions that Python's `%` operator can raise.

### F-012: decode_json recursion limit produces indistinguishable ERROR
- **Severity**: Info
- **Surface**: decode_json
- **File:line**: src/rfc9741pure/_json.py:43
- **Repro**:
  ```python
  from rfc9741pure import decode_json
  decode_json("[" * 5000 + "1" + "]" * 5000)
  # "ERROR:decode_json: maximum recursion depth exceeded while decoding a JSON array from a unicode string"
  ```
- **Impact**: Python's default recursion limit (1000) is hit at depth ~1000 (one frame per nesting level). For deeply nested JSON, `json.loads` raises `RecursionError`, which `decode_json` catches and returns `ERROR:decode_json: maximum recursion depth exceeded...`. The behaviour is graceful (no crash), but the caller cannot distinguish "too deep" from "malformed" — both return ERROR strings with different messages. A caller parsing 1000-level nested JSON will get a usable error; a caller parsing 5000-level will also get ERROR (deeper, also distinguishable). Low risk.
- **CWE**: CWE-1006 (informational)
- **Recommended fix**: Optionally raise the recursion limit on the decode path: `sys.setrecursionlimit(...)` then `try/except RecursionError: ...`. Or accept the limit as the natural Python depth cap.

### F-013: module import side-effects (verified)
- **Severity**: Info
- **Surface**: package-level
- **Repro**:
  ```python
  import sys
  before = set(sys.modules.keys())
  import rfc9741pure
  after = set(sys.modules.keys())
  print(sorted(after - before))
  # ['_json', '_struct', '_typing', 'base64', 'binascii', 'collections.abc',
  #  'json', 'json.decoder', 'json.encoder', 'json.scanner', 'rfc9741pure',
  #  'rfc9741pure._b45', 'rfc9741pure._b64', 'rfc9741pure._base10',
  #  'rfc9741pure._hex', 'rfc9741pure._json', 'rfc9741pure._printf',
  #  'struct', 'typing', 'typing.io', 'typing.re']
  ```
- **Impact**: `import rfc9741pure` only loads stdlib modules (`json`, `base64`, `struct`, `typing`, `binascii`) — no network, no file I/O, no env reads, no third-party side-effects. This is GOOD for the library's "zero-dependency" promise (pyproject.toml:14 dependencies = []).
- **CWE**: N/A (positive finding)
- **Recommended fix**: No action — this is the desired behaviour. Document it in README as a security guarantee: "no import-time side-effects beyond stdlib".

## Methodology

STRIDE-style walk-through of the 20 checklist items from the task body (V2 §1-20):

1. **Type confusion / Invariant 21** — All 22 encode/decode functions explicitly type-check `bytes` (encoders) or `str` (decoders) and return `ERROR:` strings on mismatch. Validate functions explicitly type-check both `target` and `controller`. No AttributeError/TypeError/ValueError uncaught. EXCEPTION: `decode_b45` raises ValueError on 2-char value > 255 (F-001). Otherwise: PASS.
2. **Base64 padding bypass** — `validate_b64c("AB==")`, `validate_b64c("A")`, `validate_b64c("AB=CD=")`, `validate_b64c("AB\nCD")`, `validate_b64c("A===")`, `validate_b64c("====")` all return `False` correctly. PASS.
3. **Base64url padding** — `encode_b64u` produces unpadded output (`b"AA".rstrip(b"=")`). `decode_b64u("AB==")` returns `ERROR:padding not allowed`. PASS.
4. **Hex case enforcement** — `validate_hexlc("DEAD", ...)` returns `False` (uppercase rejected). `validate_hexuc("dead", ...)` returns `False`. `validate_hex("DeAd", ...)` returns `True`. `decode_hex("abc")` (odd length) returns `ERROR:invalid hex string`. PASS (with F-009 leniency note for whitespace).
5. **Base45 character set** — All 45 RFC 9285 chars accepted (`0-9 A-Z space $ % * + - . / :`). `decode_b45("@@@")` returns `ERROR:invalid character '@'`. `decode_b45("\n")` returns `ERROR:invalid character '\n'`. PASS.
6. **Base45 RFC 9285 §4.1 encoding** — `encode_b45(b"\x00\x00")` → `"00"`, `encode_b45(b"\x2c")` (44) → `":0"`, `encode_b45(b"\x2d")` (45) → `"01"`, `encode_b45(b"\x59")` (89) → `":1"`, `encode_b45(b"\x86")` (134) → `":2"`, `encode_b45(b"\x1f\xfe")` (8190) → `"024"`, `encode_b45(b"\x1f\xff")` (8191) → `"124"`. All round-trip cleanly. PASS.
7. **Base10 leading-zero enforcement** — `validate_base10("007", 7)` → `False`, `validate_base10("0", 0)` → `True`, `validate_base10("-0", 0)` → `False`, `validate_base10("+123", 123)` → `False` (regex requires `-?`), `validate_base10("", 0)` → `False`. PASS.
8. **Base10 length DoS** — `validate_base10("9" * 10**7)` (10M chars) returns `False` in 0.019s. Regex-match bounded; no exponential blowup. PASS.
9. **Printf format string vulnerability** — `format_printf("%s", None)` → `'None'` (Python `%s` on None), `format_printf("%n", 0)` → `ERROR:unsupported format character 'n'`, no Python `str.format`-style `__class__` access. PASS.
10. **Printf unbounded %s** — `format_printf("%s", "A" * 10**6)` works (PyMu has no inherent limit). `format_printf("%s", float('nan'))` → `'nan'`. `format_printf("%s", float('inf'))` → `'inf'`. PASS.
11. **JSON round-trip** — `decode_json(None)` returns `ERROR:requires str`, `decode_json(b'{}')` returns `ERROR:requires str`. `decode_json('NaN')` succeeds with `float('nan')` (F-007). `decode_json('[' * 5000 + '1' + ']' * 5000)` returns `ERROR:maximum recursion depth exceeded` (F-012). PASS with F-007 noted.
12. **JSON unicode escape** — `decode_json('"\\u0000"')` returns `'\x00'` (NULL byte). `encode_json('a')` returns `'"a"'`. `validate_json('{"\\u0000":1}', {'\x00': 1})` returns `True`. PASS.
13. **Length DoS on encode/decode** — `encode_b64u(b"x" * 1_000_000)` works in <50ms. `encode_hex` on 400KB works. `encode_b45(b"A" * 1000)` works. `validate_base10("9"*10M)` works in 0.02s. PASS.
14. **CRLF / control chars in input** — `validate_b64c("AB\r\nCD")` returns `False` (CRLF not in b64 alphabet). `validate_hex("AB\nCD", b"\xab\xcd")` returns `True` (lenient — F-009). `validate_base10("123\n", 123)` returns `False` (regex rejects). PASS with F-009 noted.
15. **CLI injection** — CLI cmd_encode uses `eval()` for `printf` and `json` bases (F-003 — High). `cmd_validate` does a substring match (no eval). `cmd_decode` calls pure functions. FAIL (F-003).
16. **Stdout encoding** — `cli.py:67,91` writes via `print()` (default UTF-8). For non-UTF-8 locales, `print(result.decode("utf-8", errors="replace"))` (line 91) is used for bytes. For str results, `print(result)` may raise on non-encodable chars. INFO: tested implicitly; no crash in default locale.
17. **Cross-encoding ambiguity** — `encode_b64u(b"\x00")` → `"AA"` (correct, RFC 4648 §5 test vector). `decode_b64u("AA")` → `b"\x00"`. Round-trip for b64c, hex, b45, base10, json all verified. PASS.
18. **Subtle bug: _printf format-spec parsing** — `format_printf("%04x", 255)` → `"00ff"` (correct). `format_printf("%-4s", "ab")` → `"ab  "` (correct). `format_printf("%.3s", "abcdef")` → `"abc"` (correct, truncates). PASS.
19. **Underscore in numeric literals** — `validate_base10("1_000", 1000)` → `False` (regex rejects `_`). `validate_base10("+123", 123)` → `False` (no `+` prefix). `validate_base10("1e5", 100000)` → `False`. PASS.
20. **Module import safety** — `import rfc9741pure` only loads `json`, `base64`, `struct`, `typing`, `binascii` (stdlib). No network, no file writes, no env reads. PASS (F-013).

## Recommendations

T4 (triage + minimize + rank) and the builder must address:

**MUST-FIX before any ship** (cycle_166):
1. **F-001** (Critical): Fix `decode_b45` 2-char value overflow. Add `value < 256` check before `out.append(value)`. Wrap `bytes(out)` in try/except `ValueError` as defence-in-depth.
2. **F-002** (High): Fix `decode_b45` 3-char value truncation. Add `value < 65536` check on 3-char path.
3. **F-003** (High): Replace `eval(t)` with `ast.literal_eval(t)` in `cli.py:56-57`. Document CLI as developer-only / not for untrusted input. Optionally add a `--safe-mode` flag that disables the printf/json eval-paths entirely.

**SHOULD-FIX** (cycle_166 or 167):
4. **F-004** (Medium): Add `%%` handling to `_PRINTF_RE`/`_apply_format`.
5. **F-005** (Medium): Reject bool in `encode_base10` (or coerce explicitly).
6. **F-006** (Medium): Validate `%c` arg range [0, 0xFF] before passing to Python `%`; add `OverflowError` to except clauses.

**NICE-TO-FIX**:
7. **F-007** (Low): Document NaN/Infinity leniency in module docstring.
8. **F-008** (Low): Remove `decode_printf` from `__all__` (or document as no-op).
9. **F-009** (Low): Decide on hex whitespace leniency; document the choice.

**INFORMATIONAL** (no action required):
10. **F-010**, **F-011**, **F-012**, **F-013**.

**Overall verdict**: NEEDS_REMEDIATION — 1 Critical + 2 High must be fixed before any production use; 3 Medium should be addressed in the next cycle. The 13 findings total map cleanly to testable edge cases; T3 (corpus+fuzz) should focus on b45 boundary values (2-char overflow, 3-char 16-bit overflow) and F-003 CLI eval replacement should have its own unit test.