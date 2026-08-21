# File Integrity Verification System for Cloud IoT

A Python implementation of a cryptographic verification module that
validates data integrity between IoT devices and cloud storage, using
**BLS (Boneh-Lynn-Shacham) signatures** on the BLS12-381 curve.

## What it does

- **Signs data at the source.** Each IoT device holds a BLS keypair
  and signs a hash of every payload it transmits (telemetry reading
  or file).
- **Detects tampering in transit.** The cloud recomputes the hash of
  received data and verifies the BLS signature before accepting
  anything into storage — any modification, whether malicious or due
  to network corruption, is caught.
- **Stays lightweight on-device.** BLS signatures are 96 bytes and
  public keys are 48 bytes; signing cost is independent of payload
  size because we hash-then-sign (SHA-256 digest first, sign the
  fixed-size digest + metadata).
- **Scales to many devices.** BLS signatures support aggregation, so
  a cloud service verifying thousands of devices doesn't have to pay
  full per-signature cost for every message (see `verify_batch` /
  `aggregate_signatures` in `core/bls_crypto.py`).
- **Blocks replay attacks.** Signed messages bind device ID +
  sequence number + timestamp + digest together, and the pipeline
  rejects any envelope with a non-increasing sequence number or a
  stale timestamp.

## Project structure

```
file_integrity_iot/
├── core/
│   ├── bls_crypto.py            # BLS keygen, sign, verify, aggregate
│   ├── hash_utils.py            # SHA-256 hashing (file/bytes/stream)
│   ├── envelope.py              # Signed data envelope (wire format)
│   └── verification_pipeline.py # Real-time cloud-side verification pipeline
├── devices/
│   └── iot_device.py            # Simulated IoT device (keygen, sign, transmit)
├── server/
│   └── cloud_server.py          # Simulated cloud storage + verification service
├── benchmarks/
│   ├── simulate_multidevice.py  # Multi-device correctness/scalability test
│   └── benchmark_overhead.py    # Sign/verify overhead vs payload size & fleet size
├── tests/
│   └── test_verification.py     # Unit tests (pytest)
├── demo.py                      # End-to-end walkthrough with attack simulations
├── requirements.txt
└── README.md
```

## Setup

```bash
pip install -r requirements.txt
```

## Usage

**Run the end-to-end demo** (provisioning, legitimate transmission,
tampering attack, replay attack):

```bash
python demo.py
```

**Run the test suite:**

```bash
python -m pytest tests/ -v
```

**Run the multi-device scalability/correctness simulation:**

```bash
python -m benchmarks.simulate_multidevice --devices 50 --readings 20 --tamper-rate 0.1
```

**Run the computational-overhead benchmark:**

```bash
python -m benchmarks.benchmark_overhead
```

## How verification works (pipeline order)

Each incoming transmission is checked in cheapest-first order so
malformed or tampered data is rejected with minimal wasted CPU:

1. **Structural check** — envelope well-formed, signature present, device registered.
2. **Freshness check** — timestamp within allowed clock skew; sequence number strictly increasing (anti-replay).
3. **Digest recomputation** — re-hash the received payload, compare to transmitted digest (cheap, catches corruption/tampering fast).
4. **Signature verification** — BLS-verify the signed message against the device's registered public key (only reached if steps 1–3 pass).

## Design notes

- Uses `py_ecc`'s reference BLS12-381 implementation (the
  `G2ProofOfPossession` scheme from IETF draft-irtf-cfrg-bls-signature,
  the same construction used in Ethereum's consensus layer). It's a
  pure-Python implementation, so it's meant for correctness
  demonstration and testing — swap in a native binding (e.g. `blst`)
  for production-grade performance.
- Private keys never leave the simulated device object in this repo;
  in a real deployment they'd live in a hardware secure element / TPM.
- `core/hash_utils.py` streams files in 64KB chunks so integrity
  checks don't require loading an entire file into memory — relevant
  for constrained devices reading from flash storage.
