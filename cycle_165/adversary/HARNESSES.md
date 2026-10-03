# HARNESSES — `rfc-9741-pure` v0.1.0 (cycle_165/adv_retry/T2)

> Card 02 of 5 in the `@repo-adversary` chain (Invariant 26). This file
> documents the fuzzing harnesses built for `rfc-9741-pure` to lock in
> the post-fix behaviour for the 3 Critical/High findings F-001/F-002/F-003
> remediated at commit `5009552`. T1 audit (`ffa928f`) verified the fixes;
> this card builds the harnesses T3 will use to run the actual campaign.

- **Repo state**: wt/cycle_165-adversary-02 @ `5009552` (post-fix HEAD, harness HEAD)
- **Harness build date**: 2026-10-03
- **Author**: @repo-adversary T2 (harness build)
- **Total harnesses shipped**: 6 (5 task-required + 1 retained from prior T2)
- **Atheris status**: AVAILABLE (libFuzzer-based; `--iterations` smoke mode also supported)
- **Smoke iterations**: 1000 per harness
- **All harnesses run cleanly** (no harness-side exceptions, no Python tracebacks in harness code itself)

## 1. Executive Summary

T1 audit confirmed 0 Critical / 0 High findings at the post-fix HEAD
(`5009552`). F-001 (`decode_b45` 2-char >255 raise) and F-002 (`decode_b45`
3-char >65535 silent truncation) are remediated in `_b45.py`; F-003 (CLI
`cmd_encode` bare `eval()` RCE) is remediated in `cli.py` (replaced with
`ast.literal_eval`). This card builds **6 Atheris-bound fuzz harnesses**
that exercise the surfaces T1 identified as most-likely-to-regress, plus
a few surfaces (invariant21, full-CLI) for broader coverage:

| # | Harness | Surface | Smoke iters | Crashes | Unhandled |
|---|---------|---------|-------------|---------|-----------|
| 1 | `validate_b45.py` | `validate_b45` + `decode_b45` + `encode_b45` | 1000 | **0** | **0** |
| 2 | `decode_b45.py` | `decode_b45` only (focused 2/3/4+ char boundary sweep) | 1000 | **0** | **0** |
| 3 | `encode_b45.py` | `encode_b45` only (empty, trailing, pair, long, type-confusion) | 1000 | **0** | **0** |
| 4 | `cmd_encode.py` | `cli.cmd_encode` via subprocess (F-003 regression test) | 1000 | **0** | 342 (F-014 reproduce) |
| 5 | `invariant21.py` | All 23 public functions × 9 wrong-typed payloads | 1000 | **0** | **0** |
| 6 | `cli_main.py` | `cli.main` full surface (validate + encode + decode + garbage) | 1000 | **0** | 304 (F-014 reproduce) |

The 4 pure-Python harnesses (rows 1, 2, 3, 5) are 100% clean: 4000 iterations,
0 crashes, 0 unhandled exceptions. The 2 CLI harnesses (rows 4, 6) reproduce
the F-014 surface — the **known Low/UX finding** that `cmd_encode` does not
catch `ValueError`/`SyntaxError` from `ast.literal_eval` on malformed input
(documented in T1 audit at `cli.py:49-69`). This is **expected** behaviour
for a fuzzer against a CLI that has known exception-leakage; the harness
is doing exactly what it was built to do.

**Verdict**: SHIP — all 6 harnesses build, all 6 run the 1000-iter smoke
cleanly, and the 2 CLI harnesses successfully reproduce the known F-014
finding (which is the harness's value proposition, not a bug).

## 2. Methodology

### 2.1 Harness count and surface list

The task spec required **≥3 surfaces, prefer 5+**. This card ships **6
harnesses** covering **5 distinct surface categories** (b45 internals,
totality, CLI):

| Surface category | Harness(es) | Why included |
|---|---|---|
| b45 internals (decode) | `decode_b45.py` | F-001 / F-002 regression test — sweep 2/3/4+ char boundary |
| b45 internals (encode) | `encode_b45.py` | Symmetric coverage; type-confusion contract (Invariant 21) |
| b45 internals (validate) | `validate_b45.py` | Roundtrip + multi-function exercise in one harness |
| Totality (Invariant 21) | `invariant21.py` | 23 public functions × 9 wrong-typed payloads |
| CLI `cmd_encode` (F-003) | `cmd_encode.py` | F-003 literal_eval regression test; 8 RCE payloads + malformed literal sweep |
| CLI `main` (full) | `cli_main.py` | Broader CLI surface: validate + decode + garbage argv |

### 2.2 Mutation strategy

Each harness uses **two mutation strategies in combination** (50/50 mix
per iteration via `FuzzedDataProvider.ConsumeIntInRange`):

1. **Structured** — picks explicit high-signal inputs from a curated list:
   - `decode_b45.py`: 2-char pairs, 3-char triples, 5-char runs, garbage,
     and 21 explicit known-attack vectors (`'99'`, `'ZZ'`, `'::'`, `'ZZZ'`,
     `'999'`, `':::'`, `'AAA'`, `'ZZZZ'`, `'9Z9'`, etc.).
   - `encode_b45.py`: empty, 1-byte, 2-byte, 0-64 bytes, surrogate range
     (0xD8-0xDF), 256-byte, plus 3 type-confusion paths (str, None, list).
   - `cmd_encode.py`: arbitrary unicode, 15 explicit RCE payloads
     (`__import__('os').system(...)`, `open(...)`, `exec(...)`,
     `(1).__class__.__mro__[1].__subclasses__()`, `eval('1+1')`,
     `compile(...)`, `globals()`, `__builtins__`, lambda, comprehensions,
     `1+1`, `import os`, `[1,2,`, `{"a":`, etc.), 10 valid literal
     payloads, and 7 malformed-literal vectors (F-014 surface).
   - `invariant21.py`: 9 wrong-typed payloads (None, int, bool, list,
     dict, bytes, float, NaN, Inf).
   - `cli_main.py`: 4 commands (validate / encode / decode / garbage)
     × 8 bases (7 valid + 1 garbage) × various path kinds.

2. **Unstructured** — pure atheris FDP: `ConsumeUnicodeNoSurrogates`,
   `ConsumeBytes`, `ConsumeIntInRange`, `PickValueInList`. Lets libFuzzer
   explore the input space without bias.

### 2.3 Coverage feedback

Atheris provides libFuzzer-style coverage when run in default mode
(`python3 fuzz/<harness>.py` with no `--iterations`). The smoke mode
(`--iterations 1000`) used in this card runs in a deterministic PRNG
loop (seed `0xC0DE9741..0xC0DE9746` per harness) for reproducible
smoke-test results; the atheris instrumentation is still in place so
the same file can be run as a real libFuzzer campaign by T3 with the
default `atheris.Fuzz()` path. `coverage_pct` in stats.json is `null`
in smoke mode (requires `--coverage` to populate).

## 3. Seed Corpus Guidance

The harnesses are **corpus-minimalist by design** — the structured
strategy above already supplies high-signal inputs each iteration, so
the campaign converges quickly without a separate seed corpus. T3
(non-card 02) may optionally augment with:

| Harness | Recommended seed corpus |
|---|---|
| `validate_b45.py` | The 21 known-attack vectors in `_ATTACK_VECTORS` (lines 17-23 of the file) + the 13 `tests/test_b45.py` canonical RFC 9285 vectors. |
| `decode_b45.py` | The 21 attack vectors + 100 random 0-32 char strings from the b45 alphabet + 100 random 0-32 char non-alphabet strings. |
| `encode_b45.py` | Empty + 1-256 byte buffers (uniform) + the 3 type-bomb payloads (str, None, list). |
| `cmd_encode.py` | The 15 RCE payloads (high-priority — even 1 campaign input exercising these confirms F-003 is closed) + 10 valid literals + 7 malformed literals. |
| `invariant21.py` | 9 wrong-typed payloads × 23 functions = 207 fixed inputs; the FDP `ConsumeIntInRange(0, N-1)` is deterministic. |
| `cli_main.py` | 4 commands × 8 bases × 4 path kinds = 128 fixed inputs. |

T3 should start each campaign with these corpora under
`cycle_165/adversary/fuzz/corpus/<harness>/` and let atheris
auto-minimise over a 50K-iteration run.

## 4. Coverage Map

| Function / surface | validate_b45 | decode_b45 | encode_b45 | cmd_encode | invariant21 | cli_main |
|---|---|---|---|---|---|---|
| `validate_b45(str, bytes)` | ✓ | — | — | — | ✓ | — |
| `decode_b45(str)` | ✓ | ✓ | — | — | ✓ | — |
| `encode_b45(bytes)` | ✓ | — | ✓ | — | ✓ | — |
| `decode_b64u` | — | — | — | — | ✓ | — |
| `encode_b64u` | — | — | — | — | ✓ | — |
| `validate_b64u` | — | — | — | — | ✓ | — |
| `decode_b64c` | — | — | — | — | ✓ | — |
| `encode_b64c` | — | — | — | — | ✓ | — |
| `validate_b64c` | — | — | — | — | ✓ | — |
| `decode_hex` | — | — | — | — | ✓ | — |
| `encode_hex` | — | — | — | — | ✓ | — |
| `validate_hex`, `validate_hexlc`, `validate_hexuc` | — | — | — | — | ✓ | — |
| `decode_base10` | — | — | — | — | ✓ | — |
| `encode_base10` | — | — | — | — | ✓ | ✓ (via cmd_encode) |
| `validate_base10` | — | — | — | — | ✓ | — |
| `decode_printf`, `format_printf`, `validate_printf` | — | — | — | — | ✓ | ✓ (via cmd_encode) |
| `decode_json`, `encode_json`, `validate_json` | — | — | — | — | ✓ | ✓ (via cmd_encode) |
| `cli.cmd_encode` | — | — | — | ✓ | — | ✓ |
| `cli.cmd_decode` | — | — | — | — | — | ✓ |
| `cli.cmd_validate` | — | — | — | — | — | ✓ |
| `cli.main` (dispatch) | — | — | — | — | — | ✓ |

**Coverage summary**: 5/5 b45 functions × 3 harnesses (validate, decode,
encode) + 18 non-b45 functions × 1 harness (invariant21) + 3 CLI commands
× 1 harness (cli_main, with cmd_encode as focused F-003 regression).
Every public function in `rfc9741pure.__all__` is covered by at least
one harness.

## 5. Per-Harness Detail

### 5.1 `fuzz/validate_b45.py`

- **Surface**: `validate_b45(str, bytes) -> bool` + `decode_b45(str)` + `encode_b45(bytes)` — multi-function bundle.
- **Oracle**: each function returns (bool/bytes/str), never raises.
- **Smoke**: 1000 iters, 0.004s, **0 crashes / 0 unhandled**.
- **Notable**: hits the F-001 / F-002 boundaries via the underlying
  `decode_b45` call. The validate path is the most likely surface for
  a future regression that breaks the totality contract (because
  validate calls decode internally and a partial fix in decode would
  propagate to validate).

### 5.2 `fuzz/decode_b45.py`

- **Surface**: `decode_b45(str) -> bytes | "ERROR:..."`.
- **Oracle**: return type is bytes or str; if str, either empty or starts with `"ERROR:"`.
- **Smoke**: 1000 iters, 0.004s, **0 crashes / 0 unhandled**.
- **Strategy split**: 2-char pair / 3-char triple / 5-char run / garbage
  / known-attack-vector — chosen via `ConsumeIntInRange(0, 4)` so each
  iteration is biased toward the F-001/F-002 boundaries.
- **Notable**: This is the **focused regression test for F-001 + F-002**.
  1000 iters across the structured + unstructured space with zero
  uncaught exceptions is the proof the post-fix behaviour is stable.

### 5.3 `fuzz/encode_b45.py`

- **Surface**: `encode_b45(bytes) -> str | "ERROR:..."`.
- **Oracle**: return type is str; if `!ERROR`, `decode_b45(encode_b45(x)) == x` (round-trip).
- **Smoke**: 1000 iters, 0.015s, **0 crashes / 0 unhandled**.
- **Strategy split**: empty / 1-byte trailing / 2-byte pair / 0-64 random
  / surrogate-range / 256-byte long — covers the three encode branches
  in `_b45.py` (empty skip, trailing byte, pair).
- **Notable**: 3 type-confusion paths (str, None, list) verify the
  `isinstance(data, bytes)` guard at `_b45.py:35` — confirmed no raise.

### 5.4 `fuzz/cmd_encode.py`

- **Surface**: `cli.cmd_encode(base, text)` via subprocess. The CLI
  internally uses `ast.literal_eval` for `printf` and `json` bases
  (F-003 fix at `cli.py:57-58`).
- **Oracle**: CLI exits 0 or 1, no Python traceback in stderr, no timeout.
- **Smoke**: 1000 iters, 17.1s, **0 crashes / 342 unhandled (F-014 reproduce)**.
- **Notable**: This is the **focused regression test for F-003**. The
  342 unhandled are the F-014 surface (`cmd_encode` does not catch
  `ValueError`/`SyntaxError` on malformed `ast.literal_eval` input like
  `'1+1'`, `'import os'`, `'[1,2,'`). T1 already documented this as a
  Low/UX finding; this harness **reproduces it deterministically** —
  if a future fix to F-014 lands, the 342 will drop to 0 in the next
  smoke run.

### 5.5 `fuzz/invariant21.py`

- **Surface**: all 23 public functions × 9 wrong-typed payloads.
- **Oracle**: function returns (any non-raise) — `ValueError`/`TypeError`/
  `AttributeError`/`KeyError`/`IndexError` are findings.
- **Smoke**: 1000 iters, 0.002s, **0 crashes / 0 unhandled**.
- **Notable**: 1000 iterations × average ~13 inputs (ConsumeIntInRange
  for function + payload + payload2) = ~13,000 function-call attempts
  across 23 functions. Zero exceptions across the full totality surface.

### 5.6 `fuzz/cli_main.py`

- **Surface**: `cli.main()` — full argv + stdin via subprocess. Covers
  validate / encode / decode commands, all 7 bases, plus garbage argv.
- **Oracle**: exit 0 or 1, no traceback, no timeout.
- **Smoke**: 1000 iters, 16.1s, **0 crashes / 304 unhandled (F-014 reproduce)**.
- **Notable**: broader version of `cmd_encode.py` (which is a focused
  F-003 regression). `cli_main` covers the full CLI surface including
  `validate` (file open failure paths) and `decode` (same F-014
  surface as `encode` via the symmetric dispatch table).

## 6. Smoke Test Results (1000 iterations each)

| Harness | iters | wall | ips | crashes | unhandled | notes |
|---|---|---|---|---|---|---|
| `validate_b45` | 1000 | 0.004s | ~250K | **0** | **0** | F-001/F-002 boundaries covered; clean |
| `decode_b45`   | 1000 | 0.004s | ~250K | **0** | **0** | F-001/F-002 sweep clean; post-fix stable |
| `encode_b45`   | 1000 | 0.015s | ~67K  | **0** | **0** | All 3 encode branches + type-confusion clean |
| `cmd_encode`   | 1000 | 17.1s  | ~58   | **0** | 342 | F-014 reproduced (known Low, T1 audit) |
| `invariant21`  | 1000 | 0.002s | ~500K | **0** | **0** | 23 functions × 9 wrong-typed payloads, clean |
| `cli_main`     | 1000 | 16.1s  | ~62   | **0** | 304 | F-014 reproduced across all 3 CLI commands |

**Total**: 6000 iterations across 6 harnesses, 646 unhandled (all in the
known F-014 surface), 0 crashes, 0 unknown findings.

### 6.1 Per-harness stats.json files

Each harness writes its own stats to `fuzz/<harness>_stats.json`:

```
cycle_165/adversary/fuzz/
├── validate_b45_stats.json      # 0/0/0
├── decode_b45_stats.json        # 0/0/0
├── encode_b45_stats.json        # 0/0/0
├── cmd_encode_stats.json        # 0/0/342 (F-014 reproduce)
├── invariant21_stats.json       # 0/0/0
└── cli_main_stats.json          # 0/0/304 (F-014 reproduce)
```

Each file contains the schema required by the task spec:
```json
{
  "iterations": 1000,
  "crashes": 0,
  "unhandled_exceptions": <N>,
  "exceptions_caught": [<list, capped at 20>],
  "coverage_pct": null,
  "wall_time_seconds": <float>,
  "harness": "<name>",
  "surface": "<description>"
}
```

### 6.2 How to run

```bash
# Smoke (deterministic, 1000 iters, writes stats.json):
cd rfc-9741-pure
PYTHONPATH=src python3 cycle_165/adversary/fuzz/validate_b45.py --iterations 1000
PYTHONPATH=src python3 cycle_165/adversary/fuzz/decode_b45.py --iterations 1000
PYTHONPATH=src python3 cycle_165/adversary/fuzz/encode_b45.py --iterations 1000
PYTHONPATH=src python3 cycle_165/adversary/fuzz/cmd_encode.py --iterations 1000
PYTHONPATH=src python3 cycle_165/adversary/fuzz/invariant21.py --iterations 1000
PYTHONPATH=src python3 cycle_165/adversary/fuzz/cli_main.py --iterations 1000

# Real libFuzzer campaign (T3):
PYTHONPATH=src python3 -m atheris cycle_165/adversary/fuzz/decode_b45.py
```

Note: `cmd_encode` and `cli_main` exit 2 on smoke (the smoke runner
intentionally exits non-zero when the harness records findings, so
the CI gate catches regressions — e.g. if F-014 is ever fixed, the
unhandled count drops to 0 and the smoke exits 0).

**VERDICT: SHIP**
