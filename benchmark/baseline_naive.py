"""
Naive SHA-256 private set intersection baseline for SecureMatch.

Implements an insecure baseline where Party A and Party B simply hash their records
using plain SHA-256 and exchange the digests to compute the set intersection.

This baseline serves to:
1. Measure the raw theoretical maximum throughput of hash-only matching without asymmetric crypto.
2. Quantify the "Privacy Tax": the exact computational and communication overhead of
   true commutative elliptic curve cryptography (secp256k1 ECDH-PSI) versus naive hashing.
"""

from __future__ import annotations
import hashlib
import time
from typing import Any, Dict, List, Set, Tuple


def naive_sha256_psi(
    party_a_records: List[str],
    party_b_records: List[str],
) -> Tuple[Set[str], Dict[str, Any]]:
    """
    Executes a naive SHA-256 matching exchange.

    Party A hashes its elements and sends SHA256 digests.
    Party B hashes its elements and computes intersection on hashes.
    Party B returns matched hashes to Party A.

    Args:
        party_a_records: Raw or normalized string identifiers of Party A.
        party_b_records: Raw or normalized string identifiers of Party B.

    Returns:
        Tuple of (matched_plaintexts_set, benchmark_metrics_dict).
    """
    t_start = time.perf_counter()

    # Step 1: Party A hashes its items
    t_a0 = time.perf_counter()
    a_hash_to_plain = {
        hashlib.sha256(item.encode("utf-8")).digest(): item
        for item in party_a_records
    }
    t_a_hash = time.perf_counter() - t_a0

    # Step 2: Party B hashes its items
    t_b0 = time.perf_counter()
    b_hash_to_plain = {
        hashlib.sha256(item.encode("utf-8")).digest(): item
        for item in party_b_records
    }
    t_b_hash = time.perf_counter() - t_b0

    # Step 3: Intersection computation (Party B checks set membership)
    t_match0 = time.perf_counter()
    b_hashes = set(b_hash_to_plain.keys())
    matched_hashes = set(a_hash_to_plain.keys()).intersection(b_hashes)
    t_match = time.perf_counter() - t_match0

    total_time = time.perf_counter() - t_start

    # Wire byte calculation:
    # Party A sends |A| * 32 bytes (SHA-256 digests)
    # Party B sends |Intersection| * 32 bytes back to Party A
    bytes_a_to_b = len(party_a_records) * 32
    bytes_b_to_a = len(matched_hashes) * 32
    total_wire_bytes = bytes_a_to_b + bytes_b_to_a

    matched_plaintexts = {a_hash_to_plain[h] for h in matched_hashes}

    metrics = {
        "party_a_count": len(party_a_records),
        "party_b_count": len(party_b_records),
        "intersection_count": len(matched_plaintexts),
        "time_a_hash_sec": t_a_hash,
        "time_b_hash_sec": t_b_hash,
        "time_intersection_sec": t_match,
        "total_time_sec": total_time,
        "records_per_sec": (len(party_a_records) + len(party_b_records)) / total_time if total_time > 0 else 0,
        "bytes_a_to_b": bytes_a_to_b,
        "bytes_b_to_a": bytes_b_to_a,
        "total_wire_bytes": total_wire_bytes,
    }

    return matched_plaintexts, metrics
