"""
hash_utils.py
-------------
Utilities for producing the fixed-size digests that get BLS-signed.

We hash before signing for two reasons:
  1. BLS signing operates on arbitrary-length messages by first hashing
     to a curve point internally, but hashing our payload to a fixed
     32-byte SHA-256 digest *first* keeps what we sign small and
     constant-size regardless of file/telemetry size -- important for
     low-power devices with limited RAM/flash.
  2. It lets the cloud side re-hash received data and do a cheap
     digest comparison before even touching the (more expensive)
     signature verification, so obviously-corrupted payloads are
     rejected fast.
"""

from __future__ import annotations

import hashlib
import os
from typing import BinaryIO, Union

_CHUNK_SIZE = 64 * 1024  # 64KB streaming chunks, friendly to constrained devices


def hash_bytes(data: bytes) -> bytes:
    """SHA-256 digest of an in-memory bytes object."""
    return hashlib.sha256(data).digest()


def hash_file(path: Union[str, os.PathLike]) -> bytes:
    """
    Stream-hash a file from disk without loading it fully into memory.
    Suitable for constrained devices reading from flash storage.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            hasher.update(chunk)
    return hasher.digest()


def hash_stream(stream: BinaryIO) -> bytes:
    """Stream-hash from any file-like object (e.g. a socket buffer)."""
    hasher = hashlib.sha256()
    for chunk in iter(lambda: stream.read(_CHUNK_SIZE), b""):
        hasher.update(chunk)
    return hasher.digest()


def digest_hex(digest: bytes) -> str:
    return digest.hex()
