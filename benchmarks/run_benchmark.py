#!/usr/bin/env python3
"""
Benchmark: rfc9741pure.encode_b64u vs base64.urlsafe_b64encode
5 iterations × 5 workload sizes (10 KB – 1 MB).
Reports Mean, P95 latency and Peak Memory.
"""
import base64
import gc
import os
import sys
import time
import tracemalloc
from statistics import mean, median
from typing import List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rfc9741pure import encode_b64u  # noqa: E402

# ── workload sizes ──────────────────────────────────────────────────────────
WORKLOADS = [
    ("10 KB", 10 * 1024),
    ("100 KB", 100 * 1024),
    ("500 KB", 500 * 1024),
    ("1 MB", 1024 * 1024),
]

ITERATIONS = 5


def make_payload(size: int) -> bytes:
    """Deterministic pseudo-random byte payload."""
    data = bytearray(size)
    for i in range(size):
        data[i] = (i * 73 + 17) % 256
    return bytes(data)


def time_fn(fn, *args) -> Tuple[float, float, float]:
    """Return (mean_ms, p95_ms, peak_kb). Forces gc between runs."""
    times: List[float] = []
    peak_kb = 0.0
    for _ in range(ITERATIONS):
        gc.collect()
        tracemalloc.reset_peak()
        tracemalloc.start()
        t0 = time.perf_counter()
        fn(*args)
        t1 = time.perf_counter()
        _, pk = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        times.append((t1 - t0) * 1000)
        peak_kb = max(peak_kb, pk / 1024)
    times.sort()
    p95 = times[int(len(times) * 0.95)] if times else 0.0
    return round(mean(times), 3), round(p95, 3), round(peak_kb, 1)


def run() -> List[dict]:
    results = []
    print(f"{'Payload':<10} {'Op':<45} {'Mean(ms)':<10} {'P95(ms)':<10} {'Peak(KB)':<10}")
    print("-" * 90)
    for label, size in WORKLOADS:
        payload = make_payload(size)
        for op_name, fn, args in [
            ("rfc9741pure.encode_b64u", encode_b64u, (payload,)),
            ("base64.urlsafe_b64encode", base64.urlsafe_b64encode, (payload,)),
        ]:
            mean_ms, p95_ms, peak_kb = time_fn(fn, *args)
            results.append(
                {
                    "payload": label,
                    "op": op_name,
                    "mean_ms": mean_ms,
                    "p95_ms": p95_ms,
                    "peak_kb": peak_kb,
                }
            )
            print(f"{label:<10} {op_name:<45} {mean_ms:<10.3f} {p95_ms:<10.3f} {peak_kb:<10.1f}")
    return results


if __name__ == "__main__":
    results = run()
    print("\nDone.")
