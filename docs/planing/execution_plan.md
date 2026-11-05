# SecureMatch: Project Execution Plan & Roadmap

**Project Name:** SecureMatch — Configurable Privacy-Preserving Record Linkage via Elliptic Curve Diffie-Hellman Private Set Intersection  
**Course:** Cryptography (2026/2) — DCC / ICEx / UFMG  
**Instructor:** Prof. Jeroen van de Graaf  
**Author:** Mateus Cursino Costa (Matrícula: `2022043191`)  
**Timeline:** November 5, 2026 – November 18, 2026 (Delivery & Presentations)  
**Status:** In Progress — Active Tracking  

---

## 1. Executive Summary & Objective

The objective of **SecureMatch** is to build, verify, and empirically evaluate a two-party Private Set Intersection (PSI) system using Commutative Elliptic Curve Diffie-Hellman (ECDH) in Python. 

The project addresses the vulnerability of naive hash-matching over low-entropy identifiers (e.g., CPFs, CNPJs, phone numbers) by providing:
1. **Key Flexibility:** A configurable schema engine allowing parties to agree dynamically on single or composite match patterns (standardized IDs, composite attributes, internal codes).
2. **Robust Data Normalization:** Canonical data preparation to prevent false negative hash mismatches and delimiter injection attacks.
3. **Rigorous Cryptographic Primitives:** Researched and benchmarked elliptic curve selections and hash-to-curve mappings under the semi-honest Computational Diffie-Hellman (CDH) model.
4. **Empirical Benchmarking:** Quantifying the "privacy tax" (computation and bandwidth overhead) of ECDH-PSI compared to naive hashing across dataset sizes up to $50{,}000$ records.
5. **Academic Deliverables:** Documented repository, comprehensive final report, and a 15–20 minute presentation slide deck with a step-by-step execution walkthrough.

---

## 2. Milestone Schedule & Timeline Overview

```
Nov 05 — Nov 07: Phase 0 — Research Spike & Technical Architecture (Curves & Schemas)
Nov 07 — Nov 09: Phase 1 — Cryptographic Core & Mathematical Foundations
Nov 09 — Nov 11: Phase 2 — Configurable Schema Engine & Normalization Pipeline
Nov 11 — Nov 13: Phase 3 — Protocol State Machines & Dual-Transport Layer
Nov 13 — Nov 15: Phase 4 — Empirical Benchmarking & Privacy-Tax Analysis
Nov 15 — Nov 17: Phase 5 — CLI Tooling, Presentation Slides & Final Report
Nov 18:          Final Delivery & In-Class Presentation
```

---

## 3. Detailed Work Breakdown Structure (WBS)

### Phase 0: Research Spike & Technical Foundations (Nov 5 – Nov 7)
*Objective: Conduct technical trade-off analyses, establish design decisions, and document architectural foundations before writing production code.*

- [x] **Task 0.1: Elliptic Curve & Library Evaluation Spike**
  - Compare candidate curves: `secp256k1` (Koblitz, efficient multiplication), `Curve25519` (Montgomery, timing attack resistance), and `NIST P-256`.
  - Evaluate Python runtime performance and cryptographic primitives: Python `cryptography` package vs. specialized bindings vs. optimized finite-field implementation.
  - Document findings and decision rationale in `docs/planing/adr_01_cryptographic_primitives.md`.
- [x] **Task 0.2: Hash-to-Curve Algorithm Analysis**
  - Compare Hash-and-Increment (counter-based quadratic residue search via Euler's criterion) vs. RFC 9380 simplified SWU (Straight-line / constant-time).
  - Assess security implications under the Random Oracle Model (ROM) and performance trade-offs in Python.
- [x] **Task 0.3: Match Key Specification & Protocol Negotiation Design**
  - Define declarative schema format (JSON / YAML / lightweight spec) for party agreement on match keys.
  - Specify canonical length-prefixed serialization (CRI) format to guarantee deterministic byte encoding and prevent delimiter injection attacks.
- [x] **Task 0.4: Project Scaffolding & Virtual Environment**
  - Initialize clean repository folder layout (`src/`, `tests/`, `benchmark/`, `docs/`).
  - Setup `requirements.txt` with locked dependencies and `pytest` harness.

---

### Phase 1: Cryptographic Core Engine (Nov 7 – Nov 9)
*Objective: Implement the mathematical engine, point operations, scalar blinding, and hash-to-point mappings with automated unit verification.*

- [ ] **Task 1.1: Curve Arithmetic & Key Generation**
  - Implement secure scalar generation $k \in \mathbb{Z}_r^*$ using cryptographically secure entropy (`secrets` / OS CSPRNG).
  - Point multiplication routines for single and batch operations.
- [ ] **Task 1.2: Deterministic Hash-to-Curve Module (`src/crypto/hash_to_curve.py`)**
  - Implement deterministic mapping from arbitrary normalized byte strings $\{0,1\}^* \rightarrow E(\mathbb{F}_p)$.
  - Ensure collision resistance and uniform distribution across curve subgroups.
- [ ] **Task 1.3: Point Serialization & Compression**
  - Implement standard compressed point serialization (e.g., 33-byte format: prefix byte + 32-byte $x$-coordinate).
  - Implement deserialization and point-on-curve validation checks.
- [ ] **Task 1.4: Cryptographic Invariant Testing (`tests/test_crypto.py`)**
  - Unit tests verifying:
    - Points lie on the curve: $y^2 \equiv x^3 + ax + b \pmod p$.
    - Commutativity invariant: $a \cdot (b \cdot P) == b \cdot (a \cdot P)$ across random scalars and inputs.
    - Determinism: identical input strings yield identical curve points.
    - Zero scalar / identity point boundary handling.

---

### Phase 2: Configurable Schema & Normalization Pipeline (Nov 9 – Nov 11)
*Objective: Build the identity engineering layer that parses custom match keys, normalizes records, and outputs canonical byte representations.*

- [ ] **Task 2.1: Canonical Record Identifier (CRI) Engine (`src/data_pipeline/schema.py`)**
  - Implement length-prefixed deterministic string serializer:  
    `field_1:length_1:value_1|field_2:length_2:value_2` (with sorted keys for canonical order).
  - Guard against delimiter manipulation (e.g., ensuring `name="a|b"` does not inject fake attributes).
- [ ] **Task 2.2: Configurable Field Normalizers (`src/data_pipeline/normalizers.py`)**
  - Text normalization: Unicode NFKD decomposition, diacritic stripping, case folding, and whitespace collapsing.
  - Pre-built standard formatters:
    - Brazilian CPF / CNPJ: punctuation stripping, 11/14 digit validation, checksum verification.
    - Phone numbers: country code standardization, region/area code tagging.
    - Internal IDs / alphanumeric keys: padding, trimming, casing rules.
  - Custom composite keys: support multi-attribute combinations (e.g., `BirthDate + PostalCode + LastName`).
- [ ] **Task 2.3: Ingestion Adapters (`src/data_pipeline/ingestion.py`)**
  - Streaming readers for common tabular data formats (CSV, JSON, Python dictionaries) converting records to normalized byte arrays.
- [ ] **Task 2.4: Pipeline Unit Tests (`tests/test_pipeline.py`)**
  - Test dirty-data resilience: verify that varying encodings, accents, and punctuation normalize to identical bytes.
  - Test schema negotiation and rejection of incompatible schemas between parties.

---

### Phase 3: Protocol State Machines & Dual-Transport Layer (Nov 11 – Nov 13)
*Objective: Implement the interactive 2-round PSI protocol state machine with random permutation and pluggable transport channels.*

- [ ] **Task 3.1: Protocol Framing & Message Envelopes (`src/protocol/messages.py`)**
  - Binary/packed message format for point exchanges, schema handshake, and metadata.
- [ ] **Task 3.2: Party State Machines (`src/protocol/party_client.py`, `party_server.py`)**
  - **Client Round 1:** Blinds set $X$ with scalar $a \rightarrow \{a \cdot H(x_i)\}$.
  - **Server Round 2:**
    - Blinds incoming client points with scalar $b \rightarrow \{b \cdot (a \cdot H(x_i))\}$.
    - Applies cryptographically secure random permutation (Fisher-Yates shuffle) to eliminate index/positional leakage.
    - Blinds own set $Y$ with scalar $b \rightarrow \{b \cdot H(y_j)\}$.
    - Transmits shuffled doubly-encrypted points and singly-encrypted server points to Client.
  - **Client Round 3:**
    - Computes $a \cdot (b \cdot H(y_j))$.
    - Computes set intersection in $O(|X| + |Y|)$ via hash set lookup.
    - Maps matched points back to original local plaintext records.
- [ ] **Task 3.3: Pluggable Transport Layer (`src/transport/`)**
  - `memory_channel.py`: Direct in-memory queue transport (bypasses OS networking to measure pure algorithmic CPU latency).
  - `socket_transport.py`: Asynchronous TCP client-server sockets with real network emulation and byte counters.
- [ ] **Task 3.4: End-to-End Integration Tests (`tests/test_protocol_e2e.py`)**
  - Assert that `client.compute_intersection() == set(client_raw) & set(server_raw)` across disjoint, identical, and partial-overlap datasets.
  - Test security properties: verify that server learns 0 information about client inputs.

---

### Phase 4: Empirical Benchmark Suite & Privacy-Tax Analysis (Nov 13 – Nov 15)
*Objective: Execute comprehensive performance experiments, profile CPU/bandwidth bottlenecks, and quantify the privacy tax.*

- [ ] **Task 4.1: Synthetic Data & Scenario Generator (`benchmark/generate_synthetic.py`)**
  - Generate controllable datasets with configurable overlap percentages ($0\%, 10\%, 50\%, 100\%$).
  - Inject dirty data (typos, casing differences, missing punctuation) to measure the impact of normalization.
- [ ] **Task 4.2: Automated Benchmark Runner (`benchmark/run_benchmarks.py`)**
  - Test matrix across input scales: $N \in [100, 500, 1{,}000, 5{,}000, 10{,}000, 50{,}000]$.
  - Measure:
    - Hash-to-curve latency ($\mu\text{s}$ per element).
    - Scalar multiplication throughput.
    - Client vs. Server computation time.
    - Total communication volume (KB / MB transferred).
    - Ingestion & normalization overhead vs. cryptographic computation overhead.
- [ ] **Task 4.3: Baseline Comparison (Quantifying the "Privacy Tax")**
  - Implement a naive hashing baseline (SHA-256 set matching) to establish raw speed upper bounds.
  - Compute the precise overhead ratio: $\text{Latency}_{\text{ECDH}} / \text{Latency}_{\text{SHA-256}}$ and $\text{Bandwidth}_{\text{ECDH}} / \text{Bandwidth}_{\text{SHA-256}}$.
- [ ] **Task 4.4: Publication-Quality Plot Generation (`benchmark/plot_metrics.py`)**
  - Generate clean Matplotlib figures for the final report and slides:
    - Execution time vs. Dataset size (linear scaling verification).
    - Network bandwidth transferred vs. Dataset size.
    - Component breakdown (Normalization vs. Hash-to-Curve vs. Point Multiplication vs. Transport).

---

### Phase 5: CLI, Presentation Slides & Final Report (Nov 15 – Nov 18)
*Objective: Package the project into an intuitive CLI tool, compile the formal academic report, and create the presentation slide deck.*

- [ ] **Task 5.1: Unified Command Line Interface (`src/cli.py`)**
  - CLI commands:
    - `securematch server --host 0.0.0.0 --port 9000 --data server.csv --schema cpf`
    - `securematch client --host 127.0.0.1 --port 9000 --data client.csv --schema cpf`
    - `securematch benchmark --scale 1000,5000,10000 --output-dir ./results`
    - `securematch demo --step-by-step`: Interactive step-by-step recreation of each mathematical round for class presentation.
- [ ] **Task 5.2: Final Project Report (`docs/report/report.tex`)**
  - Structure:
    1. Introduction & Regulatory Motivation (LGPD/GDPR, low-entropy vulnerability).
    2. Cryptographic Formulation & Security Reductions under CDH.
    3. Architecture, Schemas, & Normalization Pipeline.
    4. Experimental Benchmark Results & Privacy-Tax Analysis.
    5. Retrospective: Difficulties encountered, deviations from initial plan, and lessons learned.
  - Compile to `docs/report/report.pdf`.
- [ ] **Task 5.3: Presentation Slide Deck (`docs/presentation/`)**
  - 15–20 minute presentation deck covering:
    - Motivation & the Naive Hash Trap.
    - Mathematical mechanism: Commutative ECDH and Hash-to-Curve.
    - Configurable matching schemas in practice.
    - Benchmark results, charts, and linear scaling analysis.
    - Step-by-step protocol demonstration walkthrough.
- [ ] **Task 5.4: Final Packaging & Code Quality Review**
  - Verify clean repository structure, docstrings, reproduction instructions in `README.md`.
  - Staging and local commit ready for user's push.

---

## 4. Risk Analysis & Mitigation Strategies

| Risk | Impact | Likelihood | Mitigation Strategy |
| :--- | :---: | :---: | :--- |
| **Python BigInt / EC multiplication performance bottleneck at $N = 50{,}000$** | High | Medium | Profile early during Phase 0 spike. If pure Python curve multiplication is slow, utilize C-accelerated primitives (e.g., `cryptography.hazmat` / OpenSSL bindings) or batch generator processing to keep memory bounded. |
| **Hash-to-Curve failure or quadratic residue search latency** | Medium | Low | Use standard Hash-and-Increment with bounded iterations or RFC 9380 simplified SWU mapping; pre-validate prime field residue parameters. |
| **Data normalization discrepancies across diverse schemas** | Medium | Medium | Unit test normalizers against dirty synthetic datasets with randomized accents, case variations, and punctuation before integrating with the crypto engine. |
| **Time constraints prior to Nov 18** | High | Medium | Strict modular decoupling. Core cryptographic protocol and in-memory benchmarks take priority; network sockets and CLI enhancements build on top without blocking report metrics. |

---

## 5. Deliverable Checklist (Course Assessment Alignment)

- [ ] **Item 1: Working GitHub Repository & Result (40%)**
  - Working, documented Python implementation in `src/`.
  - Comprehensive unit and integration test suite passing in `tests/`.
  - Benchmark suite and reproducibility scripts in `benchmark/`.
- [ ] **Item 2: Short Technical Report (Item 1 & 2 evaluation)**
  - Detailed report comparing expected vs. achieved results.
  - In-depth documentation of difficulties encountered and deviations from original blueprint.
- [ ] **Item 3: Presentation Slides & Result Walkthrough (20%)**
  - Presentation slides tailored for a 15–20 minute in-class talk.
  - Clear demonstration / recreation of protocol execution steps.
- [ ] **Documentation Integrity**
  - All architecture decision records (ADRs) kept in `docs/planing/`.
  - All progress tracked against this execution plan.

