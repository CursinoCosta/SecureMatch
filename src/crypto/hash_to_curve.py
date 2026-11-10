"""
Deterministic Hash-to-Curve mapping for secp256k1.

Maps arbitrary byte strings (e.g. Canonical Record Identifiers) deterministically
onto valid elliptic curve points using a domain-separated Hash-and-Increment procedure.
"""

from __future__ import annotations
import hashlib
from typing import Iterable, List, Tuple
from .curve import P, B, Point

DEFAULT_DOMAIN_TAG: bytes = b"SecureMatch-secp256k1-v1"


def hash_to_curve(
    data: bytes,
    domain_tag: bytes = DEFAULT_DOMAIN_TAG,
) -> Point:
    """
    Deterministically maps an arbitrary byte sequence to a point on secp256k1.

    Algorithm (Domain-Separated Hash-and-Increment):
    1. Initialize counter c = 0.
    2. Compute candidate x = SHA-256(domain_tag || ":" || c || ":" || data) mod P.
    3. Check if z = x^3 + 7 mod P is a quadratic residue via Euler's criterion:
       z^((P-1)/2) == 1 (mod P).
    4. If true:
       Compute principal root y = z^((P+1)/4) mod P.
       Canonicalize y to be the even root (to guarantee unique determinism).
       Return Point(x, y).
    5. If false, increment c and repeat.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Data must be bytes, got {type(data).__name__}.")

    counter = 0
    prefix = domain_tag + b":"

    while True:
        # Construct domain-separated payload
        payload = prefix + counter.to_bytes(4, byteorder="big") + b":" + data
        digest = hashlib.sha256(payload).digest()
        candidate_x = int.from_bytes(digest, byteorder="big") % P

        # Evaluate curve equation: z = x^3 + 7 mod P
        z = (candidate_x * candidate_x * candidate_x + B) % P

        # Check quadratic residue via Euler's criterion
        if pow(z, (P - 1) // 2, P) == 1:
            # P = 3 mod 4, principal root is z^((P+1)/4) mod P
            y = pow(z, (P + 1) // 4, P)

            # Canonicalize to even y-coordinate
            if y % 2 != 0:
                y = P - y

            return Point(candidate_x, y)

        counter += 1


def hash_to_curve_with_stats(
    data: bytes,
    domain_tag: bytes = DEFAULT_DOMAIN_TAG,
) -> Tuple[Point, int]:
    """
    Same as hash_to_curve, but additionally returns the number of counter iterations
    required to find a valid quadratic residue (useful for empirical profiling).
    """
    counter = 0
    prefix = domain_tag + b":"

    while True:
        payload = prefix + counter.to_bytes(4, byteorder="big") + b":" + data
        digest = hashlib.sha256(payload).digest()
        candidate_x = int.from_bytes(digest, byteorder="big") % P

        z = (candidate_x * candidate_x * candidate_x + B) % P

        if pow(z, (P - 1) // 2, P) == 1:
            y = pow(z, (P + 1) // 4, P)
            if y % 2 != 0:
                y = P - y
            return Point(candidate_x, y), counter + 1

        counter += 1


def _parallel_hash_worker(chunk: List[bytes], domain_tag: bytes) -> List[Point]:
    return [hash_to_curve(rec, domain_tag) for rec in chunk]


def batch_hash_to_curve(
    records: Iterable[bytes],
    domain_tag: bytes = DEFAULT_DOMAIN_TAG,
) -> List[Point]:
    """
    Maps a sequence of byte records to curve points in batch.
    Automatically leverages multi-core parallel processing for large batches (N >= 500).
    """
    recs = list(records)
    n = len(recs)
    if n < 500:
        return [hash_to_curve(rec, domain_tag) for rec in recs]

    import os
    import multiprocessing as mp
    cpu_count = min(4, os.cpu_count() or 1)
    chunk_size = (n + cpu_count - 1) // cpu_count
    chunks = [recs[i:i + chunk_size] for i in range(0, n, chunk_size)]

    with mp.Pool(processes=cpu_count) as pool:
        chunk_results = pool.starmap(_parallel_hash_worker, [(c, domain_tag) for c in chunks])

    flat_results: List[Point] = []
    for r in chunk_results:
        flat_results.extend(r)
    return flat_results

