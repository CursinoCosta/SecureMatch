# SecureMatch: Configurable Privacy-Preserving Record Linkage via ECDH-PSI

[![Course](https://img.shields.io/badge/UFMG-Cryptography%20(2026%2F2)-blue.svg)](#academic-context)
[![Protocol](https://img.shields.io/badge/Protocol-Commutative%20ECDH--PSI-green.svg)](#cryptographic-architecture)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](#license)

**SecureMatch** is a two-party **Private Set Intersection (PSI)** system based on Commutative Elliptic Curve Diffie-Hellman (ECDH) cryptography. Designed for relational databases and tabular data engineering pipelines, it enables cross-organizational entity reconciliation without exposing non-matching sensitive records.

---

## 1. Motivation: The Vulnerability of Naive Hashing

Organizations in regulated sectors (such as healthcare cohorts, inter-bank fraud detection, and public registry synchronization) routinely need to discover shared records between disparate databases without disclosing non-intersecting data.

A frequent but dangerous industry mistake is exchanging hashed identifiers (e.g., plain or salted SHA-256). Because real-world identifiers like national IDs (e.g., Brazilian CPF with only $10^{11}$ combinations), phone numbers, or organizational codes possess low entropy, an untrusted party or eavesdropper can brute-force the entire search space in minutes via precomputed rainbow tables or GPU clusters.

**SecureMatch** resolves this by computing the set intersection mathematically through a two-round zero-knowledge exchange where neither party learns anything about the other party's data beyond the intersecting elements.

---

## 2. Cryptographic Architecture

### 2.1. Commutative Exponentiation Property
The protocol relies on the commutative property of scalar multiplication over elliptic curves:
$$a \cdot (b \cdot P) = b \cdot (a \cdot P) = (a \cdot b) \cdot P$$
where $a, b \in \mathbb{Z}_r^*$ are private random scalars held by Party A (Client) and Party B (Server), and $P = H(x) \in E(\mathbb{F}_p)$ is a point obtained via a deterministic hash-to-curve primitive.

### 2.2. Protocol Exchange Flow
1. **Round 1 (Client $\rightarrow$ Server):** Client maps records $X = \{x_1, \dots, x_m\}$ to curve points, blinds each point with private scalar $a$ ($P_{a,i} = a \cdot H(x_i)$), and sends $\{P_{a,i}\}$ to the Server.
2. **Round 2 (Server $\rightarrow$ Client):** Server blinds the received points with scalar $b$ ($P_{ba,i} = b \cdot P_{a,i}$), applies a random permutation (shuffling) to eliminate positional linkage, blinds its own dataset $Y = \{y_1, \dots, y_n\}$ ($P_{b,j} = b \cdot H(y_j)$), and transmits both sets back to the Client.
3. **Intersection Extraction (Client):** Client multiplies Server points with its private scalar $a$ ($P_{ab,j} = a \cdot P_{b,j}$) and matches against the shuffled doubly-blinded set $\{P_{ba,i}\}$.

Under the Computational Diffie-Hellman (CDH) assumption in the semi-honest (honest-but-curious) model, the intersection $X \cap Y$ is computed in linear $O(|X| + |Y|)$ time without revealing disjoint items.

---

## 3. Core System Components

* **Configurable Schema Engine:** Supports dynamic negotiation of match keys between parties. Allows pre-established identifiers (e.g., CPF, CNPJ, normalized phone numbers with geographic region) as well as custom composite keys and domain-specific attributes.
* **Canonical Data Normalization:** Pre-processing pipeline that performs Unicode normalization, whitespace trimming, and standard format validation to ensure typographical differences do not produce false negative mismatches.
* **Cryptographic Primitives Module:** Implementation and evaluation of candidate elliptic curves (e.g., `secp256k1`, `Curve25519`), CSPRNG scalar generation, and secure hash-to-curve mappings.
* **Dual Transport Layer:** Provides both zero-overhead in-memory communication (for pure cryptographic latency benchmarks) and asynchronous TCP socket transport with network bandwidth instrumentation.
* **Empirical Benchmark Suite:** Automated matrix testing performance, latency, and communication volume across dataset sizes from $N = 10^2$ to $5 \times 10^4$ records, contrasted with a naive SHA-256 baseline to evaluate the concrete "privacy tax".

---

## 4. Repository Structure

```text
SecureMatch/
├── README.md
├── docs/
│   ├── proposal/
│   │   ├── proposal.tex          # Project proposal source
│   │   ├── proposal.pdf          # 1-page proposal document
│   │   └── projeto-call-for-proposals-3.pdf
│   └── planing/
│       ├── articles.md           # Curated literature & BibTeX entries
│       └── cryptalink_psi_project_blueprint.md
├── src/                          # Implementation (to be populated)
│   ├── data_pipeline/            # Schema validation & canonicalization
│   ├── crypto/                   # Curve arithmetic & hash-to-curve mapping
│   ├── protocol/                 # Client & Server state machines
│   └── transport/                # In-memory and TCP socket transport
├── benchmark/                    # Synthetic data & profiling suite
└── tests/                        # Unit and protocol integration tests
```

---

## 5. Academic Context

* **Course:** Cryptography (2026/2)
* **Department:** Departamento de Ciência da Computação (DCC), Instituto de Ciências Exatas (ICEx)
* **Institution:** Universidade Federal de Minas Gerais (UFMG)
* **Professor:** Prof. Jeroen van de Graaf
* **Author:** Mateus Cursino Costa (Matrícula: `2022043191`)
* **Project Type:** Programming / Implementation

---

## 6. License

This project is licensed under the MIT License.
