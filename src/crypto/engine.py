"""
High-level cryptographic engine for Commutative Diffie-Hellman operations.
"""

from __future__ import annotations
import os
import multiprocessing as mp
from typing import Iterable, List
from .curve import Point, point_multiply, generate_private_scalar
from .hash_to_curve import hash_to_curve, batch_hash_to_curve


def _parallel_blind_worker(chunk: List[Point], scalar: int) -> List[Point]:
    """Top-level worker function for multiprocessing pool."""
    return [point_multiply(scalar, pt) for pt in chunk]


def blind_point(scalar: int, point: Point) -> Point:
    """Computes scalar blinding P' = scalar * P."""
    return point_multiply(scalar, point)


def blind_points(scalar: int, points: Iterable[Point]) -> List[Point]:
    """
    Blinds an iterable of curve points with a given private scalar.
    Automatically leverages multi-core parallel processing for large batches (N >= 500).
    """
    pts = list(points)
    n = len(pts)
    if n < 500:
        return [point_multiply(scalar, pt) for pt in pts]

    cpu_count = min(4, os.cpu_count() or 1)
    chunk_size = (n + cpu_count - 1) // cpu_count
    chunks = [pts[i:i + chunk_size] for i in range(0, n, chunk_size)]

    with mp.Pool(processes=cpu_count) as pool:
        chunk_results = pool.starmap(_parallel_blind_worker, [(c, scalar) for c in chunks])

    flat_results: List[Point] = []
    for r in chunk_results:
        flat_results.extend(r)
    return flat_results


def hash_and_blind(scalar: int, record_bytes: bytes) -> Point:
    """Maps a raw byte record to a curve point and blinds it: scalar * H(record)."""
    pt = hash_to_curve(record_bytes)
    return point_multiply(scalar, pt)


def hash_and_blind_batch(scalar: int, records: Iterable[bytes]) -> List[Point]:
    """Maps and blinds an iterable of byte records."""
    recs = list(records)
    pts = batch_hash_to_curve(recs)
    return blind_points(scalar, pts)
