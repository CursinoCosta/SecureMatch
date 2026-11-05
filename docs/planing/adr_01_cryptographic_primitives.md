# ADR 01: Cryptographic Primitives & Elliptic Curve Selection

* **Status:** Accepted
* **Date:** 2026-11-05
* **Author:** Mateus Cursino Costa (Matrícula: `2022043191`)
* **Project:** SecureMatch (UFMG Cryptography 2026/2)

---

## 1. Context & Problem Statement

SecureMatch implements a two-party Private Set Intersection (PSI) protocol based on Commutative Diffie-Hellman on Elliptic Curves (ECDH-PSI). In this protocol:
1. Dataset elements are mapped to points on an elliptic curve: $P = H(x) \in E(\mathbb{F}_p)$.
2. Both parties perform scalar point multiplications: $P_a = a \cdot P$ and $P_{ba} = b \cdot P_a$.
3. Commutativity ensures $a \cdot (b \cdot P) = b \cdot (a \cdot P) = (ab) \cdot P$.

To build an efficient, secure, and reproducible system in Python, we must formally evaluate and select:
1. **The Elliptic Curve Setting** (`secp256k1` vs. `Curve25519` vs. `NIST P-256`).
2. **The Execution & Arithmetic Engine** (high-level OpenSSL bindings vs. optimized projective field arithmetic).
3. **The Hash-to-Curve Algorithm** (Hash-and-Increment vs. Simplified SWU / RFC 9380).

---

## 2. Comparative Analysis & Empirical Benchmarks

### 2.1. Elliptic Curve Candidates

| Curve | Curve Equation Form | Field Size | Key Strengths | Limitations in Commutative PSI |
| :--- | :--- | :--- | :--- | :--- |
| **`secp256k1`** | Short Weierstrass: $y^2 = x^3 + 7 \pmod p$ | 256 bits | • $A = 0$ simplifies Jacobian doubling.<br>• $p \equiv 3 \pmod 4$ enables fast modular square root via Euler's criterion.<br>• Standard in cryptocurrency & DCC crypto coursework.<br>• Compressed points are 33 bytes. | Slightly slower in constant-time Montgomery ladder compared to Curve25519. |
| **`Curve25519`** | Montgomery: $y^2 = x^3 + 486662x^2 + x$ | 255 bits | • Constant-time Montgomery ladder by default.<br>• $x$-only arithmetic (32-byte representation). | Requires recovering $y$ or using special maps (Elligator 2) for arbitrary point mapping; less transparent coordinate verification. |
| **`NIST P-256`** | Short Weierstrass: $y^2 = x^3 - 3x + b$ | 256 bits | • Ubiquitous in TLS/PKI standards. | $A = -3$ adds overhead to point doubling; complex parameter origin. |

### 2.2. The OpenSSL / `cryptography` Library Limitation in PSI
High-level cryptographic libraries (including Python's `cryptography` OpenSSL wrapper) are designed exclusively for standard ECDH key agreement over a fixed generator $G$ (`priv.exchange(ec.ECDH(), peer_pub)`). Under this API:
- Only the 32-byte $x$-coordinate is returned.
- Arbitrary point scalar multiplication returning full curve points $(x', y')$ is deliberately not exposed by standard EVP APIs.
- Therefore, commutative PSI requires either dedicated lower-level C-bindings or optimized finite-field arithmetic over curve parameters.

### 2.3. Projective Coordinate Benchmarks (Pure Python Engine)
We benchmarked scalar point multiplication in Python 3.10 on the test platform:

```
[Secp256k1] Affine coordinates (naive modular inversion per step):  13.67 ms / op
[Secp256k1] Jacobian projective coordinates (X:Y:Z, modular inv at end): 2.23 ms / op
[Curve25519] Montgomery ladder (x-only, 255-bit scalar):             2.39 ms / op
```

**Key Takeaway:** Implementing Jacobian coordinates ($X = X/Z^2, Y = Y/Z^3$) on `secp256k1` achieves **2.23 ms per scalar multiplication** in zero-dependency pure Python. For $1{,}000$ elements, this yields $\approx 2.2$ seconds of crypto time, easily scaling across batch workloads while guaranteeing 100% portability.

---

## 3. Hash-to-Curve Selection

### 3.1. Candidates Considered
1. **RFC 9380 Simplified SWU (Shallue-van de Woestijne-Ulas):** Constant-time algebraic mapping. Excellent for timing-sensitive side-channel scenarios, but high implementation complexity for Weierstrass curves with $AB = 0$.
2. **Deterministic Hash-and-Increment (Trial Hashing):**
   - Candidate $x = \text{SHA-256}(\text{payload} \parallel \text{counter}) \pmod p$.
   - Test if $z = x^3 + 7 \pmod p$ is a quadratic residue via Euler's criterion: $z^{(p-1)/2} \equiv 1 \pmod p$.
   - Compute square root $y = z^{(p+1)/4} \pmod p$ (exploiting $p \equiv 3 \pmod 4$).
   - Pick deterministic canonical sign (e.g., even $y$).

### 3.2. Empirical Validation
Benchmarked over $100$ trials:
- **Average latency per hash-to-curve:** `0.499 ms`
- **Average counter iterations:** `1.94` (matches theoretical geometric distribution $E[X] = 2$).
- Under the Random Oracle Model (ROM), this yields a uniform, collision-resistant distribution on the curve.

---

## 4. Architectural Decision

1. **Primary Curve Setting:** **`secp256k1`**
   - Arithmetic: Jacobian projective coordinates for point doubling and addition ($A = 0, B = 7$).
   - Point Serialization: Standard SEC 1 compressed format (**33 bytes**):
     - `0x02` prefix if $y$ is even, `0x03` if $y$ is odd, followed by 32-byte big-endian $x$-coordinate.
2. **Hash-to-Curve Method:** **Deterministic Hash-and-Increment with Euler Quadratic Residue Test**.
3. **Randomness & Scalar Generation:** Cryptographically secure OS entropy (`secrets.randbelow(N)` where $N$ is the curve group order).
4. **Modularity:** The cryptographic layer will expose a clean interface (`CurvePoint`, `ScalarKey`, `hash_to_curve()`) so alternate curves (such as Curve25519) can be plugged in seamlessly for comparison.
