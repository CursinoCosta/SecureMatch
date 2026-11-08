"""
High-level cryptographic engine for Commutative Diffie-Hellman operations.
"""

from __future__ import annotations
from typing import Iterable, List
from .curve import Point, point_multiply, generate_private_scalar
from .hash_to_curve import hash_to_curve, batch_hash_to_curve


def blind_point(scalar: int, point: Point) -> Point:
    """Computes scalar blinding P' = scalar * P."""
    return point_multiply(scalar, point)


def blind_points(scalar: int, points: Iterable[Point]) -> List[Point]:
    """Blinds an iterable of curve points with a given private scalar."""
    return [point_multiply(scalar, pt) for pt in points]


def hash_and_blind(scalar: int, record_bytes: bytes) -> Point:
    """Maps a raw byte record to a curve point and blinds it: scalar * H(record)."""
    pt = hash_to_curve(record_bytes)
    return point_multiply(scalar, pt)


def hash_and_blind_batch(scalar: int, records: Iterable[bytes]) -> List[Point]:
    """Maps and blinds an iterable of byte records."""
    return [hash_and_blind(scalar, rec) for rec in records]

