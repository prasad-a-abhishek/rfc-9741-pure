#!/usr/bin/env python3
"""Fuzz harness for .json (JSON text ↔ Python object).

Targets: validate_json, decode_json, encode_json.
Total contract: every public function must return a structured error on
malformed input, never raise an uncaught exception.

Library contract:
  validate_json(target: str, controller: Any) -> bool
  decode_json(target: str) -> Any              # Python obj or "ERROR:..." str
  encode_json(obj: Any) -> str                 # str or "ERROR:..." str
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc9741pure import (
        validate_json,
        decode_json,
        encode_json,
    )


def _pick_object(fdp: atheris.FuzzedDataProvider):
    """Pick a representative Python object for encode_json fuzzing.

    Five shapes that exercise different json.dumps code paths:
      0: int
      1: float
      2: str (may be empty or contain control chars)
      3: list
      4: dict
    """
    kind = fdp.ConsumeIntInRange(0, 4)
    if kind == 0:
        return fdp.ConsumeIntInRange(-(2**31), 2**31 - 1)
    if kind == 1:
        return fdp.ConsumeProbability()
    if kind == 2:
        return fdp.ConsumeUnicodeNoSurrogates(128)
    if kind == 3:
        n = fdp.ConsumeIntInRange(0, 4)
        return [fdp.ConsumeUnicodeNoSurrogates(8) for _ in range(n)]
    return {fdp.ConsumeUnicodeNoSurrogates(4): fdp.ConsumeIntInRange(0, 100)}


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    raw = fdp.ConsumeUnicodeNoSurrogates(4096)

    # Decode side: arbitrary text → Python object or "ERROR:...".
    decoded = decode_json(raw)
    # Validate surface: signature is (target: str, controller: Any).
    validate_json(raw, decoded)

    # Encode side: pick a representative object.
    obj = _pick_object(fdp)
    encoded = encode_json(obj)
    if isinstance(encoded, str) and not encoded.startswith("ERROR:"):
        # Exercise the roundtrip — encoded text is well-formed JSON.
        decode_json(encoded)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
