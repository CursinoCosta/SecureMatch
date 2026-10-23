# CryptaLink-PSI: Privacy-Preserving Record Linkage via Elliptic Curve Diffie-Hellman Private Set Intersection

---

## 1. Executive Context & Academic Constraints

* **Course**: Cryptography (2026/2)
* **Institution**: Departamento de Ciência da Computação (DCC), Instituto de Ciências Exatas (ICEx), Universidade Federal de Minas Gerais (UFMG)
* **Professor**: Prof. Jeroen van de Graaf
* **Author / Role**: Solo Undergrad Student (Data Engineer profile)
* **Project Type**: Programming / Implementation & Empirical Evaluation
* **Timeline**:
  * **Proposal Submission**: October 21–22, 2026 (Max 1 page)
  * **Final Code, Report & Slides Delivery**: November 18, 2026
  * **Presentation**: 15–20 minutes talk + live CLI/benchmark demo
* **Project Name**: **CryptaLink-PSI** (*Privacy-Preserving Record Linkage Engine for Relational & Tabular Data via Commutative ECDH-PSI*)

---

## 2. Project Mission & The Problem Statement

Organizations in highly regulated sectors (e.g., healthcare providers, financial institutions, public registries like DATASUS, and insurance networks) frequently need to identify common entities—such as cross-referencing fraud lists or cohort studies—without exposing non-intersecting customer or patient records.

### The Naive Trap (Why Cryptography is Necessary)
A common data engineering mistake is hashing identifiers with unsalted or salted SHA-256 and exchanging hash tables. Because national identifiers (such as the Brazilian **CPF**, which consists of only $10^{11}$ possible combinations) or phone numbers have low entropy, an untrusted party or passive eavesdropper can brute-force the entire search space in seconds via precomputed rainbow tables or GPU hash clusters.

### The Cryptographic Solution
**CryptaLink-PSI** implements a two-party **Private Set Intersection (PSI)** system based on the **Commutative Diffie-Hellman** protocol on Elliptic Curves (ECDH). It couples a **Canonical Identity Preparation Pipeline** (for data normalization and collision-resistant record representation) with a secure mathematical exchange where neither party learns anything about the other party's data beyond the intersecting subset.

---

## 3. Mathematical Foundations & Security Architecture

### 3.1. Mathematical Primitives
* **Curve Setting**: Short Weierstrass curve `secp256k1` ($y^2 = x^3 + 7 \pmod p$) or Edwards curve `Curve25519` ($y^2 = x^3 + 486662x^2 + x \pmod{2^{255}-19}$).
* **Base Field / Group**: Finite field $\mathbb{F}_p$, group $E(\mathbb{F}_p)$ of prime order $r$.
* **CSPRNG Scalar Generation**: Private scalars $a, b \in \mathbb{Z}_r^*$ generated via cryptographically secure OS entropy (`secrets` or `os.urandom`).
* **Hash-to-Curve ($H: \{0,1\}^* \rightarrow E(\mathbb{F}_p)$)**:
  * Raw strings cannot be directly treated as point coordinates. 
  * The implementation uses deterministic **Hash-and-Increment** (or RFC 9380 simplified mapping):
    $$\text{Compute } x = \text{SHA-256}(\text{payload} \parallel \text{counter})$$
    Check if $x^3 + 7$ is a quadratic residue in $\mathbb{F}_p$ via Euler's criterion:
    $$z^{(p-1)/2} \equiv 1 \pmod p$$
    If true, find $y = z^{(p+1)/4} \pmod p$, returning valid point $P(x, y)$. If false, increment the counter.

### 3.2. Commutativity Property
Elliptic curve point multiplication by a scalar is associative and commutative over private exponents:
$$a \cdot (b \cdot P) = b \cdot (a \cdot P) = (a \cdot b) \cdot P$$

### 3.3. Threat & Adversarial Model
* **Semi-Honest (Honest-but-Curious) Model**: Both parties follow the protocol steps correctly but attempt to infer as much information as possible from the messages received.
* **Security Reductions**:
  * Security reduces to the **Computational Diffie-Hellman (CDH)** problem on the chosen curve.
  * Without knowledge of scalar $a$, Party B cannot recover $H(x)$ from $a \cdot H(x)$.
  * Random permutations (shuffling) prevent index linkage attacks.

---

## 4. End-to-End Protocol Flow (Two-Party Client-Server)

Let **Party A** be the **Client** with private dataset $X = \{x_1, \dots, x_m\}$.  
Let **Party B** be the **Server** with private dataset $Y = \{y_1, \dots, y_n\}$.

```
Party A (Client)                                                  Party B (Server)
Private scalar: a ∈ ℤᵣ*                                           Private scalar: b ∈ ℤᵣ*
Input Set: X = {x₁, ..., xₘ}                                      Input Set: Y = {y₁, ..., yₙ}
---------------------------------------------------------------------------------------------
1. Map & Encrypt Set X:
   For each xᵢ ∈ X:
     P_{a,i} = a · H(xᵢ)
   Serialize to compressed points (33 bytes each)

2. Transmit Round 1 ------------------ M₁ = { P_{a,i} } ------------->

                                                                 3. Process Received Points:
                                                                    For each P_{a,i} ∈ M₁:
                                                                      P_{ba,i} = b · P_{a,i}
                                                                    Apply Random Permutation:
                                                                      S_ba = Shuffle({ P_{ba,i} })

                                                                 4. Map & Encrypt Own Set Y:
                                                                    For each yⱼ ∈ Y:
                                                                      P_{b,j} = b · H(yⱼ)

5. Receive Round 2 <--------------- M₂ = { S_ba, { P_{b,j} } } -------

6. Final Decryption & Matching:
   For each P_{b,j} ∈ M₂:
     P_{ab,j} = a · P_{b,j}
   Build Lookup Table:
     T = { P_{ab,j} }
   Compute Intersection:
     Match if P_{ba,i} ∈ T.
   Map matched indices back to original plaintext records in X.
```

---

## 5. System Architecture & Modular Layout

```
cryptalink-psi/
├── README.md
├── requirements.txt
├── setup.py
├── data_pipeline/               # Identity engineering & normalization
│   ├── __init__.py
│   ├── normalizers.py           # Case, accent, Unicode NFKD, and digit stripping
│   ├── validators.py            # Checksum validations (e.g., Brazilian CPF)
│   ├── schema.py                # Single vs Composite key schemas (Length-prefixed CRI)
│   └── pipeline.py              # Tabular ingestion (CSV, Parquet) -> bytes arrays
├── crypto/                      # Core mathematical engine
│   ├── __init__.py
│   ├── curve.py                 # Curve parameters (secp256k1) & finite field arithmetic
│   ├── hash_to_curve.py         # Deterministic hash-to-point engine
│   └── ecdh_engine.py           # Scalar keygen, point multiplication, serialization
├── protocol/                    # Protocol state machine
│   ├── __init__.py
│   ├── messages.py              # Framing, binary point packing, metadata wrappers
│   ├── party_client.py          # Client state machine
│   └── party_server.py          # Server state machine
├── transport/                   # Transport & network abstraction
│   ├── __init__.py
│   ├── memory_channel.py        # Zero-overhead in-memory queue (for pure crypto tests)
│   └── socket_transport.py      # Asyncio TCP client/server with bandwidth tracker
├── benchmark/                   # Empirical evaluation suite
│   ├── generate_synthetic.py    # Dirty data & identity discrepancy generator
│   ├── run_benchmarks.py        # Automated test matrix (time, bytes, scale)
│   └── plot_metrics.py          # Generates publication-quality charts for slides
├── tests/                       # Unit & integration verification
│   ├── test_pipeline.py
│   ├── test_crypto.py
│   └── test_protocol_e2e.py
└── cli.py                       # Unified command-line interface
```

---

## 6. Detailed Specification for Each Subsystem

### 6.1. Data Pipeline: Canonical Record Identifiers (CRI)
To prevent hash mismatches caused by minor data discrepancies and to defend against delimiter collision attacks:
1. **Cleaning**:
   * Text fields: Unicode NFKD decomposition, lowercase, accent removal, whitespace trimming.
   * Numeric IDs (CPF): Strip punctuation `.` and `-`, enforce 11 digits, validate checksum digits.
2. **Length-Prefixed Serialization (CRI)**:
   For single key (e.g., CPF): `cpf:11:12345678901`  
   For composite key (e.g., Name + Birth Date):  
   `dob:10:1995-08-15|name:14:joao da silva`  
   *Sorting key names alphabetically guarantees canonical determinism.*

### 6.2. Cryptographic Engine
* Implement on top of optimized primitives (such as Python `cryptography` / `ec` or custom finite-field arithmetic over `secp256k1`).
* Output point format: **Compressed point format (33 bytes)**:
  `[0x02 or 0x03 prefix depending on y parity] + [32-byte big-endian x-coordinate]`.
* Memory optimization: Use generator pipelines or chunked evaluation to avoid loading millions of large BigInteger objects into Python memory simultaneously.

### 6.3. Networking & Transport
* Dual-mode transport:
  * **In-Memory Pipe**: Direct queue memory transfers to measure baseline CPU runtime without operating system socket noise.
  * **Asyncio TCP Transport**: Client and Server talk over actual network sockets. The transport layer implements an atomic `BandwidthMonitor` counting total payload bytes sent/received.

### 6.4. Benchmark & Profiling Suite
* **Independent Variables**:
  * Dataset sizes: $N \in \{100, 500, 1{,}000, 5{,}000, 10{,}000, 50{,}000\}$.
  * Intersection overlap: $0\%$, $10\%$, $50\%$, $100\%$.
  * Pipeline state: Canonical normalization **ENABLED** vs **DISABLED** (quantifying false negative rates caused by dirty data).
* **Dependent Metrics**:
  * Ingestion & CRI generation time ($\text{ms}$).
  * Hash-to-curve latency ($\text{ms}$).
  * Client vs Server scalar point multiplication time ($\text{ms}$).
  * Total wire bandwidth consumption ($\text{KB} / \text{MB}$).
  * Scalability linearity: Prove $O(m + n)$ complexity empirically.
* **Comparative Baseline**:
  * Benchmark against a **Naive Insecure SHA-256 Matcher** to quantify the exact "privacy tax" (latency overhead of ECDH vs plain hashing).

---

## 7. Master Execution Steps for the Coding Agent

### Step 0: Context Verification & Proposal Generation (Immediate)
* **Goal**: Validate requirements and generate a pristine, formal, 1-page HTML proposal compliant with the course call for proposals.
* **Proposal Structure**:
  1. **Title**: CryptaLink-PSI: A Canonical Privacy-Preserving Record Linkage Pipeline via Commutative Elliptic Curve Private Set Intersection.
  2. **Author**: Solo Undergrad (Data Engineer profile), Cryptography 2026/2, Prof. Jeroen van de Graaf.
  3. **Abstract ($\approx 1/3$ page)**: Motivation, the vulnerability of naive hash matching on low-entropy identifiers (CPFs), ECDH-PSI mathematical approach, and integration with an identity data canonicalization pipeline.
  4. **Type**: `Programming / implementation`.
  5. **Expected Results & Deliverables**: GitHub repository, CLI tool, synthetic benchmark suite, automated tests, empirical report, and a 15–20 minute presentation slide deck.

### Step 1: Data Pipeline & Identity Canonicalization
* Build `normalizers.py`, `validators.py`, and `schema.py`.
* Implement length-prefixed Canonical Record Identifier (CRI) logic.
* Implement synthetic dirty-data generator injecting realistic casing, punctuation, and accent discrepancies.

### Step 2: Cryptographic Math Core
* Implement `secp256k1` curve operations, scalar generation via CSPRNG, and Hash-to-Curve mapping.
* Build automated unit tests validating point validity and commutativity: $a \cdot (b \cdot P) == b \cdot (a \cdot P)$.

### Step 3: Protocol State Machine & Transport
* Implement `party_client.py` and `party_server.py`.
* Implement the 2-round exchange flow, random shuffling of doubly-encrypted sets, and intersection extraction.
* Implement both in-memory and asyncio TCP sockets with byte counters.

### Step 4: Verification, Benchmarking & Visuals
* Build end-to-end integration tests (asserting that client output equals standard Python `set(A) & set(B)`).
* Implement automated benchmark runner across set sizes $[10^2, 5 \times 10^4]$.
* Generate clean performance plots (Matplotlib/Seaborn) for runtime, communication volume, and pipeline vs crypto overhead.

### Step 5: Deliverables Polish
* Package unified `cli.py` (`--mode server`, `--mode client`, `--mode benchmark`).
* Compile the final project report and create the 15–20 minute presentation deck structure.