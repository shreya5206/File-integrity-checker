"""
simulate_multidevice.py
------------------------
Simulates a fleet of IoT devices concurrently streaming telemetry to a
single cloud server, to test correctness and scalability of the
verification pipeline under realistic multi-device load.

Run:
    python -m benchmarks.simulate_multidevice --devices 50 --readings 20 --tamper-rate 0.1
"""

from __future__ import annotations

import argparse
import random
import time

from devices.iot_device import IoTDevice
from server.cloud_server import CloudServer


def run_simulation(num_devices: int, readings_per_device: int, tamper_rate: float, seed: int = 42):
    random.seed(seed)

    server = CloudServer()
    devices = [IoTDevice(device_id=f"sensor-{i:04d}") for i in range(num_devices)]
    for d in devices:
        server.provision_device(d)

    print(f"Provisioned {num_devices} devices on cloud server.\n")

    total_sent = 0
    total_tampered = 0
    t0 = time.perf_counter()

    for round_idx in range(readings_per_device):
        for device in devices:
            reading = {
                "temp_c": round(random.uniform(-10, 45), 2),
                "humidity": round(random.uniform(0, 100), 2),
                "battery_pct": round(random.uniform(5, 100), 1),
                "round": round_idx,
            }
            envelope = device.create_envelope(
                payload=_serialize(reading)
            )

            # Simulate an attacker/network fault tampering with the
            # payload *after* signing but before it reaches the cloud.
            if random.random() < tamper_rate:
                envelope.payload = envelope.payload[:-1] + bytes(
                    [envelope.payload[-1] ^ 0xFF]
                )
                total_tampered += 1

            server.receive(envelope)
            total_sent += 1

    elapsed = time.perf_counter() - t0

    print(server.status_report())
    print()
    print(f"Total transmissions: {total_sent}")
    print(f"Deliberately tampered: {total_tampered}")
    print(f"Wall-clock time: {elapsed:.3f}s "
          f"({(elapsed / total_sent) * 1000:.3f} ms/verification avg)")

    # Correctness assertion: every tampered payload must have been
    # caught, and no legitimate payload should ever be rejected.
    detected = server.pipeline.stats["rejections_by_reason"].get(
        "digest_mismatch_tamper_detected", 0
    )
    assert detected == total_tampered, (
        f"Correctness failure: expected {total_tampered} tamper detections, "
        f"got {detected}"
    )
    expected_accepted = total_sent - total_tampered
    assert server.pipeline.stats["accepted"] == expected_accepted, "Accepted count mismatch"
    print("\n[OK] All tampered payloads detected; all legitimate payloads accepted.")


def _serialize(reading: dict) -> bytes:
    import json

    return json.dumps(reading, sort_keys=True).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Multi-device IoT integrity simulation")
    parser.add_argument("--devices", type=int, default=50)
    parser.add_argument("--readings", type=int, default=20)
    parser.add_argument("--tamper-rate", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    run_simulation(args.devices, args.readings, args.tamper_rate, args.seed)


if __name__ == "__main__":
    main()
