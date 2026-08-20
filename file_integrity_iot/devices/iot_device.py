"""
iot_device.py
-------------
Simulates a resource-constrained IoT device that:
  1. Holds a BLS keypair (generated once, private key never leaves
     the device).
  2. Produces data (sensor telemetry or a file to upload).
  3. Wraps it in a DataEnvelope and signs it with a single BLS
     signature before transmission.

Signing overhead is deliberately kept to "one BLS sign over a fixed
96-byte message" per transmission -- independent of payload size --
which is what keeps this practical on constrained hardware (see
core/hash_utils.py for why we hash-then-sign).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

from core import bls_crypto
from core.envelope import DataEnvelope


@dataclass
class IoTDevice:
    device_id: str
    keypair: bls_crypto.KeyPair = field(default=None)
    _sequence: int = field(default=0, init=False, repr=False)

    def __post_init__(self):
        if self.keypair is None:
            # Seed deterministically from device_id for reproducible demos;
            # real devices would use a hardware RNG instead.
            self.keypair = bls_crypto.generate_keypair(
                seed=self.device_id.encode("utf-8").ljust(32, b"\0")[:32]
            )

    @property
    def public_key(self) -> bytes:
        return self.keypair.public_key

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def create_envelope(self, payload: bytes, timestamp: Optional[float] = None) -> DataEnvelope:
        """Wrap arbitrary payload bytes (sensor reading, file chunk,
        firmware blob, etc.) into a signed, transmit-ready envelope."""
        envelope = DataEnvelope(
            device_id=self.device_id,
            payload=payload,
            sequence=self._next_sequence(),
        )
        if timestamp is not None:
            envelope.timestamp = timestamp

        message = envelope.signing_message()
        envelope.signature = bls_crypto.sign(self.keypair.private_key, message)
        return envelope

    def send_file(self, path: str) -> DataEnvelope:
        """Read a file from disk and produce a signed envelope for it."""
        with open(path, "rb") as f:
            payload = f.read()
        return self.create_envelope(payload)

    def send_telemetry(self, reading: dict) -> DataEnvelope:
        """Convenience helper for structured sensor readings."""
        import json

        payload = json.dumps(reading, sort_keys=True).encode("utf-8")
        return self.create_envelope(payload)
