"""
Unit tests for the SecureMatch cryptographic engine (secp256k1 & Hash-to-Curve).
"""

import unittest
from src.crypto.curve import (
    P,
    N,
    G,
    Point,
    point_multiply,
    generate_private_scalar,
)
from src.crypto.hash_to_curve import (
    hash_to_curve,
    hash_to_curve_with_stats,
    batch_hash_to_curve,
)
from src.crypto.engine import (
    blind_point,
    hash_and_blind,
)


class TestCurveArithmetic(unittest.TestCase):
    """Tests for secp256k1 curve parameters and Jacobian point operations."""

    def test_generator_on_curve(self):
        """The standard base generator G must satisfy y^2 = x^3 + 7 (mod P)."""
        self.assertTrue(G.is_on_curve())
        self.assertFalse(G.is_infinity)

    def test_scalar_multiplication_identities(self):
        """Test multiplication by 0, 1, order N, and N + 1."""
        # 1 * G == G
        pt_1 = point_multiply(1, G)
        self.assertEqual(pt_1, G)

        # 0 * G == Infinity
        pt_0 = point_multiply(0, G)
        self.assertTrue(pt_0.is_infinity)

        # N * G == Infinity (by definition of subgroup order)
        pt_n = point_multiply(N, G)
        self.assertTrue(pt_n.is_infinity)

        # (N + 1) * G == G
        pt_n1 = point_multiply(N + 1, G)
        self.assertEqual(pt_n1, G)

        # (N - 1) * G == -G = (Gx, P - Gy)
        pt_nm1 = point_multiply(N - 1, G)
        self.assertEqual(pt_nm1.x, G.x)
        self.assertEqual(pt_nm1.y, P - G.y)

    def test_private_scalar_generation(self):
        """Generated scalars must be within [1, N - 1]."""
        for _ in range(50):
            k = generate_private_scalar()
            self.assertGreaterEqual(k, 1)
            self.assertLess(k, N)

    def test_compressed_point_serialization_roundtrip(self):
        """Test 33-byte compressed point serialization and exact recovery."""
        # Test generator point
        comp_g = G.to_compressed_bytes()
        self.assertEqual(len(comp_g), 33)
        self.assertIn(comp_g[0], (0x02, 0x03))
        recovered_g = Point.from_compressed_bytes(comp_g)
        self.assertEqual(recovered_g, G)

        # Test arbitrary scalar point
        k = generate_private_scalar()
        pt_k = point_multiply(k, G)
        comp_k = pt_k.to_compressed_bytes()
        self.assertEqual(len(comp_k), 33)
        recovered_k = Point.from_compressed_bytes(comp_k)
        self.assertEqual(recovered_k, pt_k)
        self.assertTrue(recovered_k.is_on_curve())

        # Test infinity point serialization
        inf = Point.infinity()
        comp_inf = inf.to_compressed_bytes()
        self.assertEqual(comp_inf, b"\x00" * 33)
        recovered_inf = Point.from_compressed_bytes(comp_inf)
        self.assertTrue(recovered_inf.is_infinity)

    def test_uncompressed_point_serialization_roundtrip(self):
        """Test 65-byte uncompressed serialization."""
        uncomp = G.to_uncompressed_bytes()
        self.assertEqual(len(uncomp), 65)
        self.assertEqual(uncomp[0], 0x04)
        recovered = Point.from_uncompressed_bytes(uncomp)
        self.assertEqual(recovered, G)

    def test_invalid_compressed_point_rejection(self):
        """Decoder must reject truncated data, invalid prefixes, or points not on curve."""
        # Wrong length
        with self.assertRaises(ValueError):
            Point.from_compressed_bytes(b"\x02" + b"\x00" * 31)

        # Invalid prefix byte
        with self.assertRaises(ValueError):
            Point.from_compressed_bytes(b"\x05" + G.x.to_bytes(32, "big"))

        # Coordinate x >= P
        invalid_x = (P + 5).to_bytes(32, "big")
        with self.assertRaises(ValueError):
            Point.from_compressed_bytes(b"\x02" + invalid_x)


class TestHashToCurve(unittest.TestCase):
    """Tests for deterministic hash-to-curve mapping."""

    def test_determinism(self):
        """Hashing the same input must always produce the identical curve point."""
        data = b"cpf:11:12345678901"
        pt1 = hash_to_curve(data)
        pt2 = hash_to_curve(data)
        self.assertEqual(pt1, pt2)
        self.assertTrue(pt1.is_on_curve())
        self.assertFalse(pt1.is_infinity)

    def test_domain_separation(self):
        """Different domain tags must produce distinct points for the same input."""
        data = b"cnpj:14:12345678000195"
        pt_v1 = hash_to_curve(data, domain_tag=b"Tag-V1")
        pt_v2 = hash_to_curve(data, domain_tag=b"Tag-V2")
        self.assertNotEqual(pt_v1, pt_v2)

    def test_hash_to_curve_statistical_properties(self):
        """Hash-and-increment should average ~2 iterations per mapping."""
        total_iters = 0
        samples = 40
        for i in range(samples):
            payload = f"test_record_{i}".encode("utf-8")
            pt, iters = hash_to_curve_with_stats(payload)
            self.assertTrue(pt.is_on_curve())
            total_iters += iters
        avg_iters = total_iters / samples
        # Expected value is 2.0. With 40 samples, expect between 1.0 and 4.0.
        self.assertGreater(avg_iters, 1.0)
        self.assertLess(avg_iters, 4.0)

    def test_batch_hashing(self):
        """Batch hashing preserves item-wise equality."""
        records = [b"rec_1", b"rec_2", b"rec_3"]
        points = batch_hash_to_curve(records)
        self.assertEqual(len(points), 3)
        for i, pt in enumerate(points):
            self.assertEqual(pt, hash_to_curve(records[i]))


class TestCommutativeProperty(unittest.TestCase):
    """
    Tests the foundational mathematical requirement of Commutative ECDH-PSI:
    a * (b * H(x)) == b * (a * H(x)) == (a * b) * H(x)
    """

    def test_commutative_scalar_multiplication(self):
        """Verify commutativity across multiple random scalars and input records."""
        test_inputs = [
            b"cpf:11:11122233344",
            b"cnpj:14:98765432000100",
            b"phone:14:+5531999998888|region:2:MG",
            b"account_id:8:USR-5432",
        ]

        for record in test_inputs:
            # Map input to curve point P = H(record)
            P_pt = hash_to_curve(record)

            # Generate private scalars for Party A and Party B
            scalar_a = generate_private_scalar()
            scalar_b = generate_private_scalar()

            # Path 1: Party A blinds first, Party B blinds second: b * (a * P)
            P_a = blind_point(scalar_a, P_pt)
            P_ba = blind_point(scalar_b, P_a)

            # Path 2: Party B blinds first, Party A blinds second: a * (b * P)
            P_b = blind_point(scalar_b, P_pt)
            P_ab = blind_point(scalar_a, P_b)

            # Direct multiplication with combined scalar: (a * b mod N) * P
            scalar_ab = (scalar_a * scalar_b) % N
            P_direct = blind_point(scalar_ab, P_pt)

            # Both paths and direct scalar multiplication must yield the exact same point
            self.assertEqual(P_ba, P_ab, f"Commutativity failed for record: {record}")
            self.assertEqual(P_ba, P_direct)

            # Compressed byte serializations must be identical
            self.assertEqual(P_ba.to_compressed_bytes(), P_ab.to_compressed_bytes())

    def test_distinct_inputs_produce_distinct_blinded_points(self):
        """Two different inputs x != y must produce distinct doubly-blinded points."""
        scalar_a = generate_private_scalar()
        scalar_b = generate_private_scalar()

        x = b"record_alpha"
        y = b"record_beta"

        # Blinded points for x
        pt_x = hash_to_curve(x)
        blinded_x = blind_point(scalar_b, blind_point(scalar_a, pt_x))

        # Blinded points for y
        pt_y = hash_to_curve(y)
        blinded_y = blind_point(scalar_b, blind_point(scalar_a, pt_y))

        self.assertNotEqual(blinded_x, blinded_y)
        self.assertNotEqual(blinded_x.to_compressed_bytes(), blinded_y.to_compressed_bytes())


if __name__ == "__main__":
    unittest.main()
