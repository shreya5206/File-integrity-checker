"""
test_verification.py
---------------------
Unit tests covering:
  - BLS keygen / sign / verify correctness
  - Envelope round-trip (wire serialize/deserialize)
  - Verification pipeline: legitimate traffic accepted
  - Tamper detection: modified payload rejected
  - Replay detection: reused sequence number rejected
  - Unknown device / bad signature rejection
  - Signature aggregation across multiple devices

Run:
    python -m pytest tests/ -v
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import bls_crypto
from core.envelope import DataEnvelope
from core.verification_pipeline import RejectReason, VerificationPipeline
from devices.iot_device import IoTDevice
from server.cloud_server import CloudServer


# ---------------------------------------------------------------- core BLS
def test_keypair_generation_deterministic_with_seed():
    kp1 = bls_crypto.generate_keypair(seed=b"a" * 32)
    kp2 = bls_crypto.generate_keypair(seed=b"a" * 32)
    assert kp1.private_key == kp2.private_key
    assert kp1.public_key == kp2.public_key


def test_sign_and_verify_roundtrip():
    kp = bls_crypto.generate_keypair(seed=b"b" * 32)
    msg = b"integrity check payload"
    sig = bls_crypto.sign(kp.private_key, msg)
    assert bls_crypto.verify(kp.public_key, msg, sig) is True


def test_verify_fails_on_wrong_message():
    kp = bls_crypto.generate_keypair(seed=b"c" * 32)
    sig = bls_crypto.sign(kp.private_key, b"original")
    assert bls_crypto.verify(kp.public_key, b"tampered", sig) is False


def test_verify_fails_on_wrong_key():
    kp1 = bls_crypto.generate_keypair(seed=b"d" * 32)
    kp2 = bls_crypto.generate_keypair(seed=b"e" * 32)
    sig = bls_crypto.sign(kp1.private_key, b"hello")
    assert bls_crypto.verify(kp2.public_key, b"hello", sig) is False


def test_batch_aggregate_verify():
    devices = [bls_crypto.generate_keypair(seed=bytes([i]) * 32) for i in range(5)]
    messages = [f"message-{i}".encode() for i in range(5)]
    sigs = [bls_crypto.sign(kp.private_key, m) for kp, m in zip(devices, messages)]

    agg_sig = bls_crypto.aggregate_signatures(sigs)
    pubkeys = [kp.public_key for kp in devices]

    assert bls_crypto.verify_batch(pubkeys, messages, agg_sig) is True

    # Tamper with one message -> aggregate verification must fail
    bad_messages = messages.copy()
    bad_messages[2] = b"tampered-message"
    assert bls_crypto.verify_batch(pubkeys, bad_messages, agg_sig) is False


# ---------------------------------------------------------------- envelope
def test_envelope_wire_roundtrip():
    device = IoTDevice(device_id="dev-1")
    envelope = device.create_envelope(b"sensor payload")
    wire = envelope.to_wire()

    restored = DataEnvelope.from_wire(wire)
    assert restored.device_id == envelope.device_id
    assert restored.payload == envelope.payload
    assert restored.sequence == envelope.sequence
    assert restored.signature == envelope.signature


# ---------------------------------------------------------------- pipeline
def test_pipeline_accepts_legitimate_transmission():
    server = CloudServer()
    device = IoTDevice(device_id="dev-legit")
    server.provision_device(device)

    envelope = device.create_envelope(b"clean data")
    result = server.receive(envelope)

    assert result.accepted is True
    assert result.reason == RejectReason.NONE
    assert len(server.storage) == 1


def test_pipeline_detects_tampered_payload():
    server = CloudServer()
    device = IoTDevice(device_id="dev-tamper")
    server.provision_device(device)

    envelope = device.create_envelope(b"original data")
    # Tamper with payload AFTER signing but BEFORE it reaches the cloud,
    # simulating an on-path attacker or storage corruption.
    envelope.payload = b"malicious data"

    result = server.receive(envelope)

    assert result.accepted is False
    assert result.reason == RejectReason.DIGEST_MISMATCH
    assert len(server.storage) == 0
    assert len(server.quarantine) == 1


def test_pipeline_rejects_forged_signature():
    server = CloudServer()
    device = IoTDevice(device_id="dev-forge")
    attacker = IoTDevice(device_id="attacker")  # not registered
    server.provision_device(device)

    envelope = device.create_envelope(b"data")
    # Attacker forges a signature with their own key but claims to be `device`
    forged_msg = envelope.signing_message()
    envelope.signature = bls_crypto.sign(attacker.keypair.private_key, forged_msg)

    result = server.receive(envelope)
    assert result.accepted is False
    assert result.reason == RejectReason.BAD_SIGNATURE


def test_pipeline_rejects_unknown_device():
    server = CloudServer()
    unregistered = IoTDevice(device_id="ghost-device")

    envelope = unregistered.create_envelope(b"data")
    result = server.receive(envelope)

    assert result.accepted is False
    assert result.reason == RejectReason.UNKNOWN_DEVICE


def test_pipeline_rejects_replayed_sequence():
    server = CloudServer()
    device = IoTDevice(device_id="dev-replay")
    server.provision_device(device)

    envelope = device.create_envelope(b"data-1")
    first = server.receive(envelope)
    assert first.accepted is True

    # Replay the exact same envelope again
    replay_result = server.receive(envelope)
    assert replay_result.accepted is False
    assert replay_result.reason == RejectReason.REPLAY


def test_pipeline_rejects_stale_timestamp():
    pipeline = VerificationPipeline(max_clock_skew_seconds=5)
    device = IoTDevice(device_id="dev-stale")
    pipeline.register_device(device.device_id, device.public_key)

    old_envelope = device.create_envelope(b"data", timestamp=time.time() - 3600)
    # Must re-sign after mutating timestamp so the signature matches
    old_envelope.signature = bls_crypto.sign(
        device.keypair.private_key, old_envelope.signing_message()
    )

    result = pipeline.verify_envelope(old_envelope)
    assert result.accepted is False
    assert result.reason == RejectReason.CLOCK_SKEW


def test_pipeline_stats_tracking():
    server = CloudServer()
    device = IoTDevice(device_id="dev-stats")
    server.provision_device(device)

    for i in range(5):
        server.receive(device.create_envelope(f"data-{i}".encode()))

    tampered = device.create_envelope(b"good")
    tampered.payload = b"bad"
    server.receive(tampered)

    assert server.pipeline.stats["received"] == 6
    assert server.pipeline.stats["accepted"] == 5
    assert server.pipeline.stats["rejected"] == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
