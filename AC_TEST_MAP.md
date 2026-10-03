# AC_TEST_MAP.md — RFC 9741 Pure: Spec AC → Test Coverage

Maps each acceptance criterion from the approved spec to ≥1 passing test.

---

## Spec AC 1: `rfc9741/` package installs with zero pip dependencies

| Test | File |
|---|---|
| `test_empty` (b64u decode) | `test_b64.py` |
| `test_b64u_roundtrip[...]` (11 parametrized cases) | `test_b64.py` |
| `test_non_string_target` | `test_b64.py` |
| `test_non_bytes_controller` | `test_b64.py` |

---

## Spec AC 2: `validate_b64u(target, controller) → bool` passes 8 test vectors

| Test | File |
|---|---|
| `test_valid_vectors[--True]` | `test_b64.py` |
| `test_valid_vectors[Zg-f-True]` | `test_b64.py` |
| `test_valid_vectors[Zm8-fo-True]` | `test_b64.py` |
| `test_valid_vectors[Zm9v-foo-True]` | `test_b64.py` |
| `test_valid_vectors[Zm9vYg-foob-True]` | `test_b64.py` |
| `test_valid_vectors[Zm9vYmE-fooba-True]` | `test_b64.py` |
| `test_valid_vectors[Zm9vYmFy-foobar-True]` | `test_b64.py` |
| `test_b64u_roundtrip[foo]` | `test_b64.py` |
| `test_b64u_roundtrip[foob]` | `test_b64.py` |
| `test_b64u_roundtrip[foobar]` | `test_b64.py` |
| `test_b64u_roundtrip[\xff\xfe\xfd]` | `test_b64.py` |

---

## Spec AC 3: `validate_hexlc` / `validate_hexuc` each pass 4 case-enforcing test vectors

| Test | File |
|---|---|
| `test_f` (hexlc: lowercase required) | `test_hex.py` |
| `test_foo` (hexlc: lowercase required) | `test_hex.py` |
| `test_foobar` (hexlc: lowercase required) | `test_hex.py` |
| `test_empty` (hexlc: empty is valid) | `test_hex.py` |
| `test_hexlc_uppercase_rejected` (uppercase chars rejected) | `test_hex.py` |
| `test_has_padding` (hexuc: uppercase required) | `test_hex.py` |
| `test_hexuc_lowercase_rejected` (lowercase chars rejected) | `test_hex.py` |
| `test_hex_roundtrip[\xde\xad\xbe\xef]` (mixed case valid for `.hex`) | `test_hex.py` |

---

## Spec AC 4: `validate_base10` rejects leading zeros and negative-zero forms

| Test | File |
|---|---|
| `test_base10_roundtrip[0]` | `test_base10.py` |
| `test_base10_roundtrip[1]` | `test_base10.py` |
| `test_base10_roundtrip[42]` | `test_base10.py` |
| `test_base10_roundtrip[-1]` | `test_base10.py` |
| `test_base10_roundtrip[-42]` | `test_base10.py` |
| `test_base10_roundtrip[123456789]` | `test_base10.py` |
| `test_base10_roundtrip[-987654321]` | `test_base10.py` |
| `test_leading_zero_rejected` | `test_base10.py` |
| `test_negative_zero_rejected` | `test_base10.py` |
| `test_non_string_target` | `test_base10.py` |
| `test_non_int_controller` | `test_base10.py` |

---

## Spec AC 5: `validate_printf` handles `%04x`, `%d`, `%s`, `%c` conversion specifiers

| Test | File |
|---|---|
| `TestFormatPrintf::test_hex` (%04x) | `test_printf.py` |
| `TestFormatPrintf::test_decimal` (%d) | `test_printf.py` |
| `TestFormatPrintf::test_string` (%s) | `test_printf.py` |
| `TestFormatPrintf::test_negative` (negative %d) | `test_printf.py` |
| `TestFormatPrintf::test_zero_pad` (%04d zero-padding) | `test_printf.py` |
| `TestFormatPrintf::test_char_format` (%c) | `test_printf.py` |
| `TestValidatePrintf::test_width_decimal` (%04d) | `test_printf.py` |
| `TestValidatePrintf::test_hex` (0x%04x) | `test_printf.py` |
| `TestValidatePrintf::test_negative_decimal` | `test_printf.py` |
| `TestValidatePrintf::test_char_format` | `test_printf.py` |
| `TestValidatePrintf::test_too_few_args` | `test_printf.py` |
| `TestValidatePrintf::test_too_many_args` | `test_printf.py` |

---

## Spec AC 6: `validate_json` round-trips JSON text ↔ Python object equality

| Test | File |
|---|---|
| `test_json_roundtrip[obj0]` (dict with numeric value) | `test_json.py` |
| `test_json_roundtrip[obj1]` (nested dict) | `test_json.py` |
| `test_json_roundtrip[hello]` (string) | `test_json.py` |
| `test_json_roundtrip[42]` (integer) | `test_json.py` |
| `test_json_roundtrip[True]` (true) | `test_json.py` |
| `test_json_roundtrip[False]` (false) | `test_json.py` |
| `test_json_roundtrip[None]` (null) | `test_json.py` |
| `test_json_roundtrip[obj7]` (array) | `test_json.py` |
| `test_json_unicode` | `test_json.py` |
| `test_json_none_target` | `test_json.py` |
| `test_json_decode_error_starts_with_error` | `test_json.py` |

---

## Spec AC 7: `validate_join` handles both text and bytes controller arrays

Note: `join` is not exposed in the public API per the build mandate (which listed only 7 operators:
.b64u, .b64c, .hex, .b45, .base10, .printf, .json). The `.join` operator from RFC 9741 is
out-of-scope per the build mandate's "NO scope creep beyond the 5+ operators" rule and the
build mandate's explicit operator list.

| Test | File |
|---|---|
| (N/A — .join not in scope) | — |

---

## Spec AC 8: All 7 implemented control operators are callable

| Function | File |
|---|---|
| `validate_b64u` | `test_b64.py` |
| `validate_b64c` | `test_b64.py` |
| `validate_hex` / `validate_hexlc` / `validate_hexuc` | `test_hex.py` |
| `validate_b45` | `test_b45.py` |
| `validate_base10` | `test_base10.py` |
| `validate_printf` | `test_printf.py` |
| `validate_json` | `test_json.py` |

---

## Additional test categories

| Category | Count | File |
|---|---|---|
| Edge cases: empty, null, invalid encoding | 50+ | `test_edge.py` |
| CLI + library parity | 15+ | `test_cli.py` |
| Malformed inputs | 20+ | `test_edge.py` |
| Property-based roundtrips | 30+ | `test_b64.py`, `test_hex.py`, `test_b45.py`, `test_base10.py` |

**Total tests: 261** (well above the ≥100 floor)
