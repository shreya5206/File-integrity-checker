"""
verification_pipeline.py
-------------------------
The real-time verification pipeline that runs on the cloud side.

For every incoming DataEnvelope it performs, in order (cheapest /
fastest checks first, so tampered or malformed data is rejected with
minimal wasted CPU):

  1. Structural check      - envelope well-formed, signature present
  2. Freshness check       - timestamp within an acceptable clock skew
                              window and sequence number strictly
                              increasing (anti-replay)
  3. Digest recomputation  - re-hash the received payload and compare
                              against the transmitted digest (cheap,
                              catches accidental corruption / obvious
                              tampering instantly)
  4. Signature verification- BLS-verify the signed message against the
                              device's registered public key (expensive,
                              only reached if 1-3 pass)

Each stage returns a VerificationResult so callers (and the test
suite) can see exactly where/why a payload was rejected.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from core import bls_crypto, hash_utils
from core.envelope import DataEnvelope


class RejectReason(Enum):
    NONE = "ok"
    MALFORMED = "malformed_envelope"
    UNKNOWN_DEVICE = "unknown_device"
    CLOCK_SKEW = "timestamp_outside_window"
    REPLAY = "sequence_not_increasing"
    DIGEST_MISMATCH = "digest_mismatch_tamper_detected"
    BAD_SIGNATURE = "signature_verification_failed"


@dataclass
class VerificationResult:
    accepted: bool
    reason: RejectReason
    device_id: str
    sequence: Optional[int] = None
    latency_ms: Optional[float] = None

    def __bool__(self):
        return self.accepted


class VerificationPipeline:
    """
    Stateful cloud-side verifier. Tracks registered device public keys
    and the last-seen sequence number per device to reject replays.
    """

    def __init__(self, max_clock_skew_seconds: float = 30.0):
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self._registry: Dict[str, bytes] = {}          # device_id -> public_key
        self._last_sequence: Dict[str, int] = {}        # device_id -> last seq seen
        self.stats = {
            "received": 0,
            "accepted": 0,
            "rejected": 0,
            "rejections_by_reason": {},
        }

    # -- device management -------------------------------------------------
    def register_device(self, device_id: str, public_key: bytes) -> None:
        self._registry[device_id] = public_key
        self._last_sequence.setdefault(device_id, -1)

    def is_registered(self, device_id: str) -> bool:
        return device_id in self._registry

    # -- main entry point -----------------------------------------------
    def verify_envelope(self, envelope: DataEnvelope) -> VerificationResult:
        start = time.perf_counter()
        self.stats["received"] += 1

        result = self._run_checks(envelope)

        result.latency_ms = (time.perf_counter() - start) * 1000
        if result.accepted:
            self.stats["accepted"] += 1
            self._last_sequence[envelope.device_id] = envelope.sequence
        else:
            self.stats["rejected"] += 1
            self.stats["rejections_by_reason"][result.reason.value] = (
                self.stats["rejections_by_reason"].get(result.reason.value, 0) + 1
            )
        return result

    def _run_checks(self, envelope: DataEnvelope) -> VerificationResult:
        device_id = getattr(envelope, "device_id", "unknown")

        # 1. structural check
        if envelope.signature is None or not envelope.device_id:
            return VerificationResult(False, RejectReason.MALFORMED, device_id)

        if not self.is_registered(envelope.device_id):
            return VerificationResult(False, RejectReason.UNKNOWN_DEVICE, device_id)

        # 2a. freshness / clock skew
        now = time.time()
        if abs(now - envelope.timestamp) > self.max_clock_skew_seconds:
            return VerificationResult(
                False, RejectReason.CLOCK_SKEW, device_id, envelope.sequence
            )

        # 2b. anti-replay: sequence must strictly increase per device
        last_seq = self._last_sequence.get(envelope.device_id, -1)
        if envelope.sequence <= last_seq:
            return VerificationResult(
                False, RejectReason.REPLAY, device_id, envelope.sequence
            )

        # 3. cheap digest recomputation before expensive crypto
        recomputed_digest = hash_utils.hash_bytes(envelope.payload)
        wire_digest = getattr(envelope, "_wire_digest", envelope.digest)
        if recomputed_digest != wire_digest or recomputed_digest != envelope.digest:
            return VerificationResult(
                False, RejectReason.DIGEST_MISMATCH, device_id, envelope.sequence
            )

        # 4. BLS signature verification (expensive, checked last)
        public_key = self._registry[envelope.device_id]
        message = envelope.signing_message()
        if not bls_crypto.verify(public_key, message, envelope.signature):
            return VerificationResult(
                False, RejectReason.BAD_SIGNATURE, device_id, envelope.sequence
            )

        return VerificationResult(True, RejectReason.NONE, device_id, envelope.sequence)

    def summary(self) -> str:
        s = self.stats
        rate = (s["accepted"] / s["received"] * 100) if s["received"] else 0.0
        lines = [
            f"Received:  {s['received']}",
            f"Accepted:  {s['accepted']} ({rate:.1f}%)",
            f"Rejected:  {s['rejected']}",
        ]
        if s["rejections_by_reason"]:
            lines.append("Rejections by reason:")
            for reason, count in sorted(s["rejections_by_reason"].items()):
                lines.append(f"  - {reason}: {count}")
        return "\n".join(lines)
