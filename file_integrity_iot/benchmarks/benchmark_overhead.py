"""
benchmark_overhead.py
----------------------
Measures the computational overhead of the signing (device-side) and
verification (cloud-side) operations across a range of payload sizes,
to demonstrate that cost is dominated by the constant-size BLS
operation rather than payload size (thanks to hash-then-sign).

Run:
    python -m benchmarks.benchmark_overhead

Note: py_ecc is a pure-Python reference implementation of BLS12-381,
so absolute timings here (~100-300ms/op) are much slower than a
production deployment would see with a native/optimized binding such
as `blst` or `py-arkworks-bls12381` (sub-millisecond per op). The
*relative* comparisons -- payload-size independence and near-linear
fleet scaling -- hold regardless of which backend is used, which is
the property this benchmark is meant to demonstrate.
"""

from __future__ import annotations

import os
import statistics
import time

from core import bls_crypto
from core.envelope import DataEnvelope
from core.verification_pipeline import VerificationPipeline
from devices.iot_device import IoTDevice
from server.cloud_server import CloudServer


def _time_ms(fn, iterations=8):
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return {
        "mean_ms": statistics.mean(samples),
        "p95_ms": sorted(samples)[int(0.95 * len(samples)) - 1],
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def benchmark_payload_sizes():
    sizes = [64, 1024, 64 * 1024, 1024 * 1024]  # 64B, 1KB, 64KB, 1MB
    device = IoTDevice(device_id="bench-device")
    server = CloudServer()
    server.provision_device(device)

    print(f"{'Payload':>10} | {'Sign (ms)':>18} | {'Verify (ms)':>18}")
    print("-" * 54)

    for size in sizes:
        payload = os.urandom(size)

        sign_stats = _time_ms(lambda: device.create_envelope(payload), iterations=8)

        envelope = device.create_envelope(payload)
        # Reset sequence tracking so repeated verification doesn't trip
        # the anti-replay check while benchmarking.
        def make_and_verify():
            server.pipeline._last_sequence[device.device_id] = envelope.sequence - 1
            server.pipeline.verify_envelope(envelope)

        verify_stats = _time_ms(make_and_verify, iterations=8)

        label = f"{size}B" if size < 1024 * 1024 else f"{size // (1024*1024)}MB"
        print(
            f"{label:>10} | mean={sign_stats['mean_ms']:.3f} p95={sign_stats['p95_ms']:.3f}"
            f" | mean={verify_stats['mean_ms']:.3f} p95={verify_stats['p95_ms']:.3f}"
        )


def benchmark_fleet_scaling():
    print("\nFleet scaling (fixed 1KB payload per device):")
    print(f"{'#Devices':>10} | {'Total verify time (ms)':>24} | {'ms/device':>10}")
    print("-" * 52)

    for n in [1, 5, 20, 50]:
        server = CloudServer()
        devices = [IoTDevice(device_id=f"d{i}") for i in range(n)]
        for d in devices:
            server.provision_device(d)

        envelopes = [d.create_envelope(os.urandom(1024)) for d in devices]

        t0 = time.perf_counter()
        for e in envelopes:
            server.pipeline.verify_envelope(e)
        total_ms = (time.perf_counter() - t0) * 1000

        print(f"{n:>10} | {total_ms:>24.3f} | {total_ms / n:>10.3f}")


if __name__ == "__main__":
    print("=== BLS Sign/Verify overhead vs payload size ===")
    benchmark_payload_sizes()
    benchmark_fleet_scaling()
