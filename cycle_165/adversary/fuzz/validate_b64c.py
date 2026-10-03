#!/usr/bin/env python3
"""Fuzz harness for .b64c (Base64 classic, padded) — RFC 4648 §4.

Targets: validate_b64c, decode_b64c, encode_b64c.
Total contract: every public function must return a structured error on
malformed input, never raise an uncaught exception.

Library contract:
  validate_b64c(target: str, controller: bytes) -> bool
  decode_b64c(target: str) -> bytes            # bytes or "ERROR:..." str
  encode_b64c(data: bytes) -> str              # str or "ERROR:..." str
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc9741pure import (
        validate_b64c,
        decode_b64c,
        encode_b64c,
    )


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    raw = fdp.ConsumeUnicodeNoSurrogates(4096)
    payload = fdp.ConsumeBytes(256)

    decode_b64c(raw)
    encode_b64c(payload)
    validate_b64c(raw, payload)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
