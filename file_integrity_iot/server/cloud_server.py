"""
cloud_server.py
----------------
Simulates the cloud-side storage service. Devices are provisioned here
(their public keys registered), incoming envelopes are pushed through
the VerificationPipeline, and only payloads that pass every check are
"committed" to storage. Anything else is quarantined/logged with the
specific rejection reason, giving an auditable trail of tamper
attempts vs. legitimate traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from core.envelope import DataEnvelope
from core.verification_pipeline import VerificationPipeline, VerificationResult
from devices.iot_device import IoTDevice


@dataclass
class StoredObject:
    device_id: str
    sequence: int
    payload: bytes
    digest_hex: str


class CloudServer:
    def __init__(self, max_clock_skew_seconds: float = 30.0):
        self.pipeline = VerificationPipeline(max_clock_skew_seconds=max_clock_skew_seconds)
        self.storage: List[StoredObject] = []
        self.quarantine: List[dict] = []  # rejected payloads + reason, for audit

    def provision_device(self, device: IoTDevice) -> None:
        """Register a device's public key with the cloud (out-of-band
        provisioning step, e.g. during manufacturing / onboarding)."""
        self.pipeline.register_device(device.device_id, device.public_key)

    def receive(self, envelope: DataEnvelope) -> VerificationResult:
        """Entry point for an inbound transmission from a device."""
        result = self.pipeline.verify_envelope(envelope)

        if result.accepted:
            self.storage.append(
                StoredObject(
                    device_id=envelope.device_id,
                    sequence=envelope.sequence,
                    payload=envelope.payload,
                    digest_hex=envelope.digest.hex(),
                )
            )
        else:
            self.quarantine.append(
                {
                    "device_id": result.device_id,
                    "sequence": result.sequence,
                    "reason": result.reason.value,
                }
            )
        return result

    def status_report(self) -> str:
        lines = [
            "=== Cloud Server Status ===",
            f"Registered devices: {len(self.pipeline._registry)}",
            f"Objects stored:      {len(self.storage)}",
            f"Quarantined:         {len(self.quarantine)}",
            "",
            self.pipeline.summary(),
        ]
        return "\n".join(lines)
