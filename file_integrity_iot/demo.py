"""
demo.py
-------
End-to-end walkthrough of the File Integrity Verification System:

  1. Provision an IoT device (BLS keypair generated on-device).
  2. Register its public key with the cloud server.
  3. Device signs and transmits a data file.
  4. Cloud verifies and stores it.
  5. Simulate an in-transit tampering attack -> show it gets caught.
  6. Simulate a replay attack -> show it gets caught.

Run:
    python demo.py
"""

from devices.iot_device import IoTDevice
from server.cloud_server import CloudServer


def main():
    print("=" * 60)
    print("File Integrity Verification System for Cloud IoT (BLS)")
    print("=" * 60)

    # 1 & 2. Provisioning
    device = IoTDevice(device_id="factory-sensor-001")
    server = CloudServer()
    server.provision_device(device)
    print(f"\n[Device] Generated BLS keypair for '{device.device_id}'")
    print(f"[Device] Public key: {device.public_key.hex()[:32]}...")
    print(f"[Cloud ] Registered device public key.")

    # 3 & 4. Legitimate transmission
    reading = {"temperature_c": 22.4, "humidity_pct": 41.0, "vibration_hz": 60.1}
    envelope = device.send_telemetry(reading)
    print(f"\n[Device] Signed telemetry: {reading}")
    print(f"[Device] Digest: {envelope.digest.hex()[:16]}...")
    print(f"[Device] Signature: {envelope.signature.hex()[:16]}...")

    result = server.receive(envelope)
    print(f"[Cloud ] Verification result: "
          f"{'ACCEPTED' if result.accepted else 'REJECTED'} "
          f"({result.reason.value}), {result.latency_ms:.3f}ms")

    # 5. Tampering attack simulation
    print("\n--- Simulating a man-in-the-middle tampering attack ---")
    envelope2 = device.send_telemetry({"temperature_c": 22.5, "humidity_pct": 40.8})
    print(f"[Device] Sent reading, digest={envelope2.digest.hex()[:16]}...")
    tampered_payload = envelope2.payload.replace(b"22.5", b"99.9")
    print(f"[Attacker] Intercepted and modified payload in transit "
          f"(spoofing a dangerous temperature reading).")
    envelope2.payload = tampered_payload

    result2 = server.receive(envelope2)
    print(f"[Cloud ] Verification result: "
          f"{'ACCEPTED' if result2.accepted else 'REJECTED'} "
          f"({result2.reason.value})")

    # 6. Replay attack simulation
    print("\n--- Simulating a replay attack ---")
    envelope3 = device.send_telemetry({"temperature_c": 21.9})
    server.receive(envelope3)
    print("[Attacker] Captured a valid, already-accepted envelope and re-sent it.")
    replay_result = server.receive(envelope3)
    print(f"[Cloud ] Verification result: "
          f"{'ACCEPTED' if replay_result.accepted else 'REJECTED'} "
          f"({replay_result.reason.value})")

    # Final report
    print("\n" + server.status_report())


if __name__ == "__main__":
    main()
