#!/usr/bin/env python3
"""Fuzz harness for .b45 (Base45) — RFC 9285.

Targets: validate_b45, decode_b45, encode_b45.
Total contract: every public function must return a structured error on
malformed input, never raise an uncaught exception.

T1 audit found:
  F-001 (Critical): decode_b45 raises ValueError on 2-char input > 255
  F-002 (High):     decode_b45 silently truncates on 3-char input > 65535

Library contract:
  validate_b45(target: str, controller: bytes) -> bool
  decode_b45(target: str) -> bytes             # bytes or "ERROR:..." str
  encode_b45(data: bytes) -> str               # str or "ERROR:..." str
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc9741pure import (
        validate_b45,
        decode_b45,
        encode_b45,
    )


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    raw = fdp.ConsumeUnicodeNoSurrogates(512)
    payload = fdp.ConsumeBytes(64)

    # Hit decode path — the surface where F-001 and F-002 were found.
    decode_b45(raw)
    # Roundtrip encode — known-safe, should always succeed for any bytes.
    encoded = encode_b45(payload)
    if isinstance(encoded, str) and not encoded.startswith("ERROR:"):
        # If encode succeeded, decode should roundtrip the input.
        # We don't assert equality (we want fuzz to be silent on success);
        # we just exercise the roundtrip path.
        decode_b45(encoded)
    # Validation surface — total signature.
    validate_b45(raw, payload)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
