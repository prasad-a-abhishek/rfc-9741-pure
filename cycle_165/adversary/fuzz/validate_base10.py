#!/usr/bin/env python3
"""Fuzz harness for .base10 (decimal integer text).

Targets: validate_base10, decode_base10, encode_base10.
Total contract: every public function must return a structured error on
malformed input, never raise an uncaught exception.

Library contract:
  validate_base10(target: str, controller: int) -> bool
  decode_base10(target: str) -> int            # int or "ERROR:..." str
  encode_base10(value: int) -> str             # str or "ERROR:..." str
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc9741pure import (
        validate_base10,
        decode_base10,
        encode_base10,
    )


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    raw = fdp.ConsumeUnicodeNoSurrogates(256)

    # Encode side: pick a bounded integer to keep fuzz side-effect-free.
    value = fdp.ConsumeIntInRange(-(2**63), 2**63 - 1)
    encode_base10(value)

    # Decode side: text → int.
    decode_base10(raw)

    # Validation: total signature.
    validate_base10(raw, value)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
