"""
envelope.py
-----------
Defines the wire format that IoT devices transmit to the cloud:
payload + metadata + BLS signature over (device_id || seq || timestamp
|| digest). Bundling the digest with device id, sequence number and
timestamp into the signed message (rather than signing the digest
alone) is what stops replay attacks and cross-device signature reuse.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field

from core import hash_utils


@dataclass
class DataEnvelope:
    device_id: str
    payload: bytes
    sequence: int
    timestamp: float = field(default_factory=time.time)
    digest: bytes = field(init=False)
    signature: bytes | None = field(default=None, init=False)

    def __post_init__(self):
        self.digest = hash_utils.hash_bytes(self.payload)

    def signing_message(self) -> bytes:
        """
        Construct the exact byte string that gets signed / verified.
        Binding device_id + sequence + timestamp + digest together
        means an attacker can't replay an old (valid) signature against
        new data, or splice one device's signature onto another
        device's payload.
        """
        dev = self.device_id.encode("utf-8")
        return (
            struct.pack(">I", len(dev))
            + dev
            + struct.pack(">Q", self.sequence)
            + struct.pack(">d", self.timestamp)
            + self.digest
        )

    def to_wire(self) -> dict:
        """Serialize for transmission (e.g. as JSON/CBOR over MQTT/HTTP)."""
        if self.signature is None:
            raise ValueError("envelope must be signed before transmission")
        return {
            "device_id": self.device_id,
            "payload": self.payload.hex(),
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "digest": self.digest.hex(),
            "signature": self.signature.hex(),
        }

    @staticmethod
    def from_wire(data: dict) -> "DataEnvelope":
        env = DataEnvelope(
            device_id=data["device_id"],
            payload=bytes.fromhex(data["payload"]),
            sequence=data["sequence"],
            timestamp=data["timestamp"],
        )
        # Trust but verify: recompute digest locally rather than trusting
        # the transmitted one; a mismatch here is itself a tamper signal.
        wire_digest = bytes.fromhex(data["digest"])
        env.signature = bytes.fromhex(data["signature"])
        env._wire_digest = wire_digest  # noqa: SLF001 stashed for pipeline check
        return env
