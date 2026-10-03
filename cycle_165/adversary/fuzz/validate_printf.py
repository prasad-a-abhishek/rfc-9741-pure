#!/usr/bin/env python3
"""Fuzz harness for .printf (printf-style formatting).

Targets: validate_printf, decode_printf, format_printf.
Total contract: every public function must return a structured error on
malformed input, never raise an uncaught exception.

T1 audit found:
  F-M03 (Medium):  %% literal escape is broken
  F-M04 (Medium):  bool round-trip broken
  F-M05 (Medium):  %c codepoint mismatch
  F-High (eval):   CLI cmd_encode/cmd_decode use eval() on user input — RCE.
                   This is a CLI-layer bug; we exercise it via cli_main.

Library contract:
  validate_printf(target: str, controller: list) -> bool
  decode_printf(target: str) -> list            # list[Any] or "ERROR:..." str
  format_printf(fmt: str, *args) -> str        # str or "ERROR:..." str
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc9741pure import (
        validate_printf,
        decode_printf,
        format_printf,
    )


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    fmt = fdp.ConsumeUnicodeNoSurrogates(256)
    arg = fdp.ConsumeUnicodeNoSurrogates(64)

    # Single int arg (most common printf case).
    int_arg = fdp.ConsumeIntInRange(-(2**31), 2**31 - 1)
    format_printf(fmt, int_arg)

    # Two-arg form: fmt, str_arg (for %s/%c and %% specifiers).
    format_printf(fmt, arg)

    # Validation: signature is (target: str, controller: list).
    validate_printf(fmt, [int_arg, arg])

    # Decode (parse) a printf-formatted string back to [fmt, args].
    decode_printf(fmt)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
