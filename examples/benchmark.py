"""Measure the latency of push() and the throughput of the guard.

Run with: uv run python examples/benchmark.py
"""

import statistics
import time

from pii_stream_guard import StreamingGuard

SENTENCE = "Kontakt: max.muster@example.ch, AHV 756.1234.5678.97, sonst nichts. "
TEXT = SENTENCE * 1000  # about 68,000 characters
CHUNK_SIZES = [1, 20, 1000]
RUNS = 10  # each run streams TEXT through a new guard


def push_latencies(chunk_size: int) -> list[float]:
    """Stream TEXT in chunks of chunk_size and return the seconds per push()."""
    guard = StreamingGuard()
    latencies = []
    for i in range(0, len(TEXT), chunk_size):
        chunk = TEXT[i : i + chunk_size]
        start = time.perf_counter()
        guard.push(chunk)
        latencies.append(time.perf_counter() - start)
    guard.finish()
    return latencies


print(f"{len(TEXT):,} characters, {RUNS} runs per chunk size")
print("chunk size   runs   pushes/run   mean (us)   p50 (us)   p95 (us)   characters/s")
for chunk_size in CHUNK_SIZES:
    latencies = [t for _ in range(RUNS) for t in push_latencies(chunk_size)]
    percentiles = statistics.quantiles(latencies, n=100)
    mean, p50, p95 = statistics.mean(latencies), percentiles[49], percentiles[94]
    throughput = len(TEXT) * RUNS / sum(latencies)
    print(
        f"{chunk_size:>10}   {RUNS:>4}   {len(latencies) // RUNS:>10,}   "
        f"{mean * 1e6:>9.1f}   {p50 * 1e6:>8.1f}   {p95 * 1e6:>8.1f}   "
        f"{throughput:>12,.0f}"
    )
