"""
bls_crypto.py
-------------
Cryptographic verification module built on BLS (Boneh-Lynn-Shacham)
signatures over the BLS12-381 curve.

Why BLS for IoT?
  * Signatures are extremely compact (96 bytes) and public keys are small
    (48 bytes) -- important for bandwidth-constrained IoT devices.
  * Signatures from many devices can be *aggregated* into a single
    96-byte signature, which is what makes this practical to validate
    at scale in the cloud (see verify_aggregate / aggregate_signatures).
  * Deterministic, no randomness required at signing time -> lower
    overhead on resource constrained hardware than schemes like ECDSA
    that need a secure RNG per signature.

This module wraps `py_ecc`'s reference implementation of the BLS
G2ProofOfPossession ("PoP") signature scheme (IETF draft-irtf-cfrg-bls
-signature), which is the standard, audited construction used in
production systems (e.g. Ethereum consensus layer).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

from py_ecc.bls import G2ProofOfPossession as bls_pop


# BLS private keys must be in [1, r-1] where r is the curve order.
_CURVE_ORDER = (
    52435875175126190479447740508185965837690552500527637822603658699938581184513
)


class BLSError(Exception):
    """Raised for any BLS key / signature failure."""


@dataclass(frozen=True)
class KeyPair:
    """A device's BLS keypair. `private_key` never leaves the device
    in a real deployment -- it is kept here only for simulation."""

    private_key: int
    public_key: bytes  # 48-byte compressed G1 point

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()


def generate_keypair(seed: bytes | None = None) -> KeyPair:
    """
    Generate a new BLS keypair.

    In production, `seed` would come from a hardware RNG / secure
    element on the IoT device. For simulation/testing, a seed can be
    supplied for reproducibility.
    """
    if seed is not None:
        # Derive a deterministic-but-uniform scalar from the seed.
        sk = int.from_bytes(seed, "big") % (_CURVE_ORDER - 1) + 1
    else:
        sk = secrets.randbelow(_CURVE_ORDER - 1) + 1

    pk = bls_pop.SkToPk(sk)
    return KeyPair(private_key=sk, public_key=pk)


def sign(private_key: int, message: bytes) -> bytes:
    """Sign a message (typically a SHA-256 digest of file/telemetry
    data) with a device's BLS private key. Returns a 96-byte signature."""
    if not isinstance(message, (bytes, bytearray)):
        raise BLSError("message must be bytes")
    try:
        return bls_pop.Sign(private_key, bytes(message))
    except Exception as exc:  # pragma: no cover - defensive
        raise BLSError(f"signing failed: {exc}") from exc


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a single BLS signature against a public key and message."""
    try:
        return bls_pop.Verify(public_key, bytes(message), bytes(signature))
    except Exception:
        # py_ecc raises on malformed points rather than returning False
        return False


def aggregate_signatures(signatures: Sequence[bytes]) -> bytes:
    """
    Combine many devices' signatures into a single 96-byte signature.

    This is the key scalability feature: a cloud server verifying
    telemetry from thousands of IoT devices does not need to verify
    each signature individually if all devices signed the *same*
    message -- see `verify_aggregate`. For distinct per-device
    messages, use `verify_batch` (fast aggregate verify) instead.
    """
    if not signatures:
        raise BLSError("cannot aggregate an empty signature set")
    return bls_pop.Aggregate(list(signatures))


def verify_aggregate(public_keys: Sequence[bytes], message: bytes, agg_signature: bytes) -> bool:
    """Verify an aggregated signature where every signer signed the
    *same* message (e.g. all devices attesting to the same firmware
    hash)."""
    try:
        return bls_pop._AggregateVerify(  # noqa: SLF001 (internal but stable)
            list(public_keys), [message] * len(public_keys), agg_signature
        )
    except Exception:
        return False


def verify_batch(
    public_keys: Sequence[bytes], messages: Sequence[bytes], agg_signature: bytes
) -> bool:
    """
    Fast aggregate verify: each device may have signed a *different*
    message (e.g. each device's own data hash), all combined into one
    aggregate signature. This is the mode used by the multi-device
    verification pipeline in this project.
    """
    if len(public_keys) != len(messages):
        raise BLSError("public_keys and messages must be the same length")
    try:
        return bls_pop.AggregateVerify(list(public_keys), list(messages), agg_signature)
    except Exception:
        return False
