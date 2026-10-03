#!/usr/bin/env python3
"""Fuzz harness for .b64u (Base64url, no padding) — RFC 4648 §5.

Targets: validate_b64u, decode_b64u, encode_b64u.
Total contract: every public function must return a structured error on
malformed input, never raise an uncaught exception.

Library contract:
  validate_b64u(target: str, controller: bytes) -> bool
  decode_b64u(target: str) -> bytes            # bytes or "ERROR:..." str
  encode_b64u(data: bytes) -> str              # str or "ERROR:..." str
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc9741pure import (
        validate_b64u,
        decode_b64u,
        encode_b64u,
    )

# Note: any exception here is a finding.  Atheris records the crash, and
# T4 triages.  We do not catch generic Exception — that's the whole point
# of a fuzz harness for the totality invariant.


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    raw = fdp.ConsumeUnicodeNoSurrogates(4096)
    payload = fdp.ConsumeBytes(256)

    # 1) decode_b64u — must never raise; may return bytes or "ERROR:...".
    decode_b64u(raw)

    # 2) encode_b64u(payload) — must never raise; returns str or "ERROR:...".
    encode_b64u(payload)

    # 3) validate_b64u(raw, payload) — total signature (target, controller).
    #    Library returns False on type mismatch — never raises.
    validate_b64u(raw, payload)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
