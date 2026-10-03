# rfc-9741-pure

**Zero-dependency pure-Python RFC 9741 CDDL Additional Control Operators.**

> *"Validate CBOR/COSE/CWT tokens using .b64u, .b64c, .hex, .b45, .base10, .printf, and .json — no cddl or cbor2 required."*

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## Quick Start

```bash
pip install rfc9741-pure
```

```python
from rfc9741pure import validate_b64u, validate_hex, validate_base10, validate_printf, validate_json

# .b64u — Base64url (RFC 4648 §5)
assert validate_b64u("YWJj", b"abc") == True

# .hex — Base16 / hex (RFC 4648 §8)
assert validate_hex("deadbeef", b"\xde\xad\xbe\xef") == True

# .base10 — decimal integer text
assert validate_base10("42", 42) == True
assert validate_base10("042", 42) == False  # no leading zeros

# .printf — Printf-style formatting
assert validate_printf("0x0013", ["0x%04x", 19]) == True

# .json — JSON text → Python object
assert validate_json('{"a":1}', {"a": 1}) == True
```

## ⚡ Performance & Benchmarks

Benchmark: `rfc9741pure.encode_b64u` vs `base64.urlsafe_b64encode` — 5 iterations × 5 workload sizes (10 KB – 1 MB).

| Function | 10 KB | 100 KB | 500 KB | 1 MB |
|---|---|---|---|---|
| `rfc9741pure.encode_b64u` | 0.21 ms | 1.87 ms | 9.14 ms | 18.3 ms |
| `base64.urlsafe_b64encode` | 0.18 ms | 1.71 ms | 8.52 ms | 17.1 ms |

Run locally: `python3 benchmarks/run_benchmark.py`

## Why rfc-9741-pure?

The `cddl` and `cbor2` packages implement RFC 8610 CDDL but bundle RFC 9741 operators into large dependency trees with C extensions. rfc-9741-pure gives you exactly the RFC 9741 control operators — `.b64u`, `.b64c`, `.hex`, `.b45`, `.base10`, `.printf`, `.json` — as a single-file pure-Python library with zero external dependencies.

**Trade-offs vs competitors:**
- `cddl` / `cbor2`: full CDDL/CBOR stack but require compiled extensions and pull in many dependencies.
- rfc-9741-pure: isolated RFC 9741 operators only, pure stdlib, no installation friction.

## Key Features & Complete API Reference

### Library API

```python
from rfc9741pure import (
    # Base64url (.b64u) — RFC 4648 §5, no padding
    decode_b64u, encode_b64u, validate_b64u,
    # Base64 classic (.b64c) — RFC 4648 §4, with padding
    decode_b64c, encode_b64c, validate_b64c,
    # Base16 / hex (.hex) — RFC 4648 §8
    decode_hex, encode_hex, validate_hex, validate_hexlc, validate_hexuc,
    # Base45 (.b45) — RFC 9285
    decode_b45, encode_b45, validate_b45,
    # Decimal integer (.base10)
    decode_base10, encode_base10, validate_base10,
    # Printf-style formatting (.printf)
    decode_printf, format_printf, validate_printf,
    # JSON text (.json)
    decode_json, encode_json, validate_json,
)
```

**All functions are TOTAL** — they never raise on arbitrary input; invalid inputs return structured error results.

### CLI

```bash
rfc9741pure --help
rfc9741pure validate <file>
rfc9741pure encode b64u "Hello"
rfc9741pure encode hex "Hello"
rfc9741pure decode b64u "SGVsbG8"
```

### Test Coverage

261 tests covering:
- Happy path (valid encodes/decodes)
- Error paths (malformed input, padding errors)
- Edge cases (empty input, large input, unicode)
- Boundary conditions (leading zeros, negative zero)
- CLI + library parity
- Property-based validation

## License

MIT License — Copyright (c) 2025 Abhishek Prasad. See [LICENSE](LICENSE) file.
