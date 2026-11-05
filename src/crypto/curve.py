"""
secp256k1 Elliptic Curve Arithmetic Engine.

Implements finite field arithmetic and Jacobian projective coordinate operations
for the Koblitz curve secp256k1 (y^2 = x^3 + 7 mod p).
Pure Python with zero external compilation dependencies.
"""

from __future__ import annotations
import secrets
from typing import Optional, Tuple

# secp256k1 curve domain parameters (Standards for Efficient Cryptography - SEC 2)
# Field prime p = 2^256 - 2^32 - 977
P: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Curve coefficients for y^2 = x^3 + A*x + B mod p
A: int = 0
B: int = 7

# Base generator point G = (Gx, Gy)
GX: int = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY: int = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Prime order of the base point subgroup n (SEC 2: secp256k1)
N: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Cofactor h
H: int = 1


class Point:
    """Represents an affine point (x, y) on the curve, or the Point at Infinity."""

    __slots__ = ("x", "y")

    def __init__(self, x: Optional[int], y: Optional[int]) -> None:
        if (x is None and y is not None) or (x is not None and y is None):
            raise ValueError("Both coordinates must be None (point at infinity) or both integers.")
        if x is not None:
            self.x = x % P
            self.y = y % P
        else:
            self.x = None
            self.y = None

    @classmethod
    def infinity(cls) -> "Point":
        """Returns the neutral group element (Point at Infinity)."""
        return cls(None, None)

    @property
    def is_infinity(self) -> bool:
        """Check if this point is the neutral element."""
        return self.x is None

    def is_on_curve(self) -> bool:
        """Validates if the point satisfies the curve equation y^2 = x^3 + 7 (mod p)."""
        if self.is_infinity:
            return True
        left = (self.y * self.y) % P
        right = (self.x * self.x * self.x + B) % P
        return left == right

    def to_compressed_bytes(self) -> bytes:
        """
        Serializes the point into SEC 1 compressed format (33 bytes).
        Format: [0x02 if y is even else 0x03] + [32-byte big-endian x]
        """
        if self.is_infinity:
            return b"\x00" * 33

        prefix = b"\x02" if (self.y % 2 == 0) else b"\x03"
        x_bytes = self.x.to_bytes(32, byteorder="big")
        return prefix + x_bytes

    @classmethod
    def from_compressed_bytes(cls, data: bytes) -> "Point":
        """
        Parses and validates a 33-byte SEC 1 compressed curve point.
        Recovers y via the modular square root since p = 3 (mod 4).
        """
        if len(data) != 33:
            raise ValueError(f"Compressed point must be exactly 33 bytes, got {len(data)}.")

        if data == b"\x00" * 33:
            return cls.infinity()

        prefix = data[0]
        if prefix not in (0x02, 0x03):
            raise ValueError(f"Invalid compressed point prefix: {hex(prefix)}. Expected 0x02 or 0x03.")

        x = int.from_bytes(data[1:], byteorder="big")
        if x >= P:
            raise ValueError("x-coordinate is out of range [0, P - 1].")

        # Compute z = x^3 + 7 mod P
        z = (x * x * x + B) % P

        # Check quadratic residue via Euler's criterion: z^((P-1)/2) == 1 (mod P)
        if pow(z, (P - 1) // 2, P) != 1:
            raise ValueError("Provided x-coordinate does not lie on the curve (not a quadratic residue).")

        # Since P = 3 (mod 4), the principal modular square root is y = z^((P+1)/4) mod P
        y = pow(z, (P + 1) // 4, P)

        # Match parity specified by the prefix
        y_is_even = (y % 2 == 0)
        expected_even = (prefix == 0x02)
        if y_is_even != expected_even:
            y = P - y

        pt = cls(x, y)
        if not pt.is_on_curve():
            raise ValueError("Decoded point failed curve equation validation.")
        return pt

    def to_uncompressed_bytes(self) -> bytes:
        """Serializes the point into SEC 1 uncompressed format (65 bytes: 0x04 + X + Y)."""
        if self.is_infinity:
            return b"\x00" * 65
        return b"\x04" + self.x.to_bytes(32, "big") + self.y.to_bytes(32, "big")

    @classmethod
    def from_uncompressed_bytes(cls, data: bytes) -> "Point":
        """Parses a 65-byte uncompressed point."""
        if len(data) != 65:
            raise ValueError(f"Uncompressed point must be exactly 65 bytes, got {len(data)}.")
        if data == b"\x00" * 65:
            return cls.infinity()
        if data[0] != 0x04:
            raise ValueError(f"Invalid uncompressed prefix: {hex(data[0])}. Expected 0x04.")
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:65], "big")
        if x >= P or y >= P:
            raise ValueError("Coordinates exceed field prime P.")
        pt = cls(x, y)
        if not pt.is_on_curve():
            raise ValueError("Point is not on the curve.")
        return pt

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y

    def __hash__(self) -> int:
        return hash((self.x, self.y))

    def __repr__(self) -> str:
        if self.is_infinity:
            return "Point(Infinity)"
        return f"Point(x=0x{self.x:064x}, y=0x{self.y:064x})"


# Standard base generator point G
G = Point(GX, GY)


# ---------------------------------------------------------------------------
# Projective Jacobian Coordinate Arithmetic (X:Y:Z where x = X/Z^2, y = Y/Z^3)
# Eliminates expensive modular inversion from inner doubling/addition loops.
# ---------------------------------------------------------------------------

JacobianPoint = Tuple[int, int, int]


def _jacobian_double(p: JacobianPoint) -> JacobianPoint:
    """Doubles a point in Jacobian projective coordinates for secp256k1 (A = 0)."""
    x1, y1, z1 = p
    if y1 == 0 or z1 == 0:
        return (0, 0, 0)

    y1_sq = (y1 * y1) % P
    s = (4 * x1 * y1_sq) % P
    m = (3 * x1 * x1) % P  # Since A = 0
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * y1_sq * y1_sq) % P
    z3 = (2 * y1 * z1) % P
    return (x3, y3, z3)


def _jacobian_add(p: JacobianPoint, q: JacobianPoint) -> JacobianPoint:
    """Adds two points in Jacobian coordinates."""
    x1, y1, z1 = p
    x2, y2, z2 = q

    if z1 == 0:
        return q
    if z2 == 0:
        return p

    z1_sq = (z1 * z1) % P
    z2_sq = (z2 * z2) % P

    u1 = (x1 * z2_sq) % P
    u2 = (x2 * z1_sq) % P

    s1 = (y1 * z2 * z2_sq) % P
    s2 = (y2 * z1 * z1_sq) % P

    if u1 == u2:
        if s1 != s2:
            return (0, 0, 0)  # P + (-P) = Infinity
        return _jacobian_double(p)

    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h_sq = (h * h) % P
    h_cu = (h * h_sq) % P

    x3 = (r * r - h_cu - 2 * u1 * h_sq) % P
    y3 = (r * (u1 * h_sq - x3) - s1 * h_cu) % P
    z3 = (h * z1 * z2) % P
    return (x3, y3, z3)


def _to_affine(p: JacobianPoint) -> Point:
    """Converts a Jacobian projective point (X:Y:Z) back to an affine Point (x, y)."""
    x, y, z = p
    if z == 0:
        return Point.infinity()

    inv_z = pow(z, P - 2, P)
    inv_z2 = (inv_z * inv_z) % P
    inv_z3 = (inv_z2 * inv_z) % P
    return Point((x * inv_z2) % P, (y * inv_z3) % P)


def point_multiply(k: int, pt: Point) -> Point:
    """
    Computes the scalar multiplication k * pt on secp256k1 using Jacobian coordinates.
    Runs in linear time relative to scalar bitlength.
    """
    if pt.is_infinity or k % N == 0:
        return Point.infinity()

    k = k % N
    result: JacobianPoint = (0, 0, 0)
    current: JacobianPoint = (pt.x, pt.y, 1)

    while k > 0:
        if k & 1:
            result = _jacobian_add(result, current)
        current = _jacobian_double(current)
        k >>= 1

    return _to_affine(result)


def generate_private_scalar() -> int:
    """
    Generates a cryptographically secure private scalar in [1, N - 1]
    using the OS CSPRNG.
    """
    # secrets.randbelow(upper) returns integer in [0, upper - 1]
    # We want [1, N - 1], so we pick in [0, N - 2] and add 1
    return secrets.randbelow(N - 1) + 1
