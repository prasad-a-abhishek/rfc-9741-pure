#!/usr/bin/env python3
"""Fuzz harness for .hex / .hexlc / .hexuc — RFC 4648 §8.

Targets: validate_hex, validate_hexlc, validate_hexuc, decode_hex, encode_hex.
Total contract: every public function must return a structured error on
malformed input, never raise an uncaught exception.

Library contract:
  validate_hex(target: str, controller: bytes) -> bool
  validate_hexlc(target: str, controller: bytes) -> bool
  validate_hexuc(target: str, controller: bytes) -> bool
  decode_hex(target: str) -> bytes             # bytes or "ERROR:..." str
  encode_hex(data: bytes) -> str               # str or "ERROR:..." str
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc9741pure import (
        validate_hex,
        validate_hexlc,
        validate_hexuc,
        decode_hex,
        encode_hex,
    )


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    raw = fdp.ConsumeUnicodeNoSurrogates(4096)
    payload = fdp.ConsumeBytes(128)

    decode_hex(raw)
    encode_hex(payload)
    validate_hex(raw, payload)
    validate_hexlc(raw, payload)
    validate_hexuc(raw, payload)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
