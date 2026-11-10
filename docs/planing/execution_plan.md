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
Nov 15 — Nov 16: Phase 5 — Interactive Streamlit UI & Visual Demonstration Suite
Nov 16 — Nov 17: Phase 6 — CLI Tooling, Presentation Slides & Final Report
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

- [x] **Task 1.1: Curve Arithmetic & Key Generation**
  - Implement secure scalar generation $k \in \mathbb{Z}_r^*$ using cryptographically secure entropy (`secrets` / OS CSPRNG).
  - Point multiplication routines for single and batch operations.
- [x] **Task 1.2: Deterministic Hash-to-Curve Module (`src/crypto/hash_to_curve.py`)**
  - Implement deterministic mapping from arbitrary normalized byte strings $\{0,1\}^* \rightarrow E(\mathbb{F}_p)$.
  - Ensure collision resistance and uniform distribution across curve subgroups.
- [x] **Task 1.3: Point Serialization & Compression**
  - Implement standard compressed point serialization (e.g., 33-byte format: prefix byte + 32-byte $x$-coordinate).
  - Implement deserialization and point-on-curve validation checks.
- [x] **Task 1.4: Cryptographic Invariant Testing (`tests/test_crypto.py`)**
  - Unit tests verifying:
    - Points lie on the curve: $y^2 \equiv x^3 + ax + b \pmod p$.
    - Commutativity invariant: $a \cdot (b \cdot P) == b \cdot (a \cdot P)$ across random scalars and inputs.
    - Determinism: identical input strings yield identical curve points.
    - Zero scalar / identity point boundary handling.

---

### Phase 2: Configurable Schema & Normalization Pipeline (Nov 9 – Nov 11)
*Objective: Build the identity engineering layer that parses custom match keys, normalizes records, and outputs canonical byte representations.*

- [x] **Task 2.1: Canonical Record Identifier (CRI) Engine (`src/data_pipeline/schema.py`)**
  - Implement length-prefixed deterministic string serializer:  
    `field_1:length_1:value_1|field_2:length_2:value_2` (with sorted keys for canonical order).
  - Guard against delimiter manipulation (e.g., ensuring `name="a|b"` does not inject fake attributes).
- [x] **Task 2.2: Configurable Field Normalizers (`src/data_pipeline/normalizers.py`)**
  - Text normalization: Unicode NFKD decomposition, diacritic stripping, case folding, and whitespace collapsing.
  - Pre-built standard formatters:
    - Brazilian CPF / CNPJ: punctuation stripping, 11/14 digit validation, checksum verification (supporting both numeric and modern alphanumeric CNPJ).
    - Phone numbers: country code standardization, region/area code tagging.
    - Internal IDs / alphanumeric keys: padding, trimming, casing rules.
  - Custom composite keys: support multi-attribute combinations (e.g., `BirthDate + PostalCode + LastName`).
- [x] **Task 2.3: Ingestion Adapters (`src/data_pipeline/ingestion.py`)**
  - Streaming readers for common tabular data formats (CSV, JSON, Python dictionaries) converting records to normalized byte arrays.
- [x] **Task 2.4: Pipeline Unit Tests (`tests/test_pipeline.py`)**
  - Test dirty-data resilience: verify that varying encodings, accents, and punctuation normalize to identical bytes.
  - Test schema negotiation and rejection of incompatible schemas between parties.

---

### Phase 3: Protocol State Machines & Dual-Transport Layer (Nov 11 – Nov 13)
*Objective: Implement the interactive 2-round PSI protocol state machine with random permutation and pluggable transport channels.*

- [x] **Task 3.1: Protocol Framing & Message Envelopes (`src/protocol/messages.py`)**
  - Binary/packed message format for point exchanges, schema handshake, and metadata.
- [x] **Task 3.2: Party State Machines (`src/protocol/party_client.py`, `party_server.py`)**
  - **Client Round 1:** Blinds set $X$ with scalar $a \rightarrow \{a \cdot H(x_i)\}$.
  - **Server Round 2:**
    - Blinds incoming client points with scalar $b \rightarrow \{b \cdot (a \cdot H(x_i))\}$.
    - Applies cryptographically secure random permutation (Fisher-Yates shuffle) to eliminate index/positional leakage on server points.
    - Blinds own set $Y$ with scalar $b \rightarrow \{b \cdot H(y_j)\}$.
    - Transmits doubly-encrypted points and shuffled singly-encrypted server points to Client.
  - **Client Round 3:**
    - Computes $a \cdot (b \cdot H(y_j))$.
    - Computes set intersection in $O(|X| + |Y|)$ via hash set lookup.
    - Maps matched points back to original local plaintext records.
- [x] **Task 3.3: Pluggable Transport Layer (`src/transport/`)**
  - `memory_channel.py`: Direct in-memory queue transport (bypasses OS networking to measure pure algorithmic CPU latency).
  - `socket_transport.py`: Asynchronous TCP client-server sockets with real network emulation and byte counters.
- [x] **Task 3.4: End-to-End Integration Tests (`tests/test_protocol_e2e.py`)**
  - Assert that `client.compute_intersection() == set(client_raw) & set(server_raw)` across disjoint, identical, and partial-overlap datasets.
  - Test security properties: verify that server learns 0 information about client inputs.

---

### Phase 4: Empirical Benchmark Suite & Privacy-Tax Analysis (Completed)
*Objective: Execute comprehensive performance experiments, profile CPU/bandwidth bottlenecks, and quantify the privacy tax.*

- [x] **Task 4.1: Synthetic Data & Scenario Generator (`benchmark/generate_synthetic.py`)**
  - Generate controllable datasets with configurable overlap percentages ($0\%, 10\%, 50\%, 100\%$).
  - Supports CPF, CNPJ (numeric + modern Receita Federal alphanumeric), Phone + Region, and arbitrary random 2-4 column composite keys.
  - Injects dirty data (punctuation masks, whitespace, casing, accents) to measure normalization resilience.
- [x] **Task 4.2: Automated Benchmark Runner (`benchmark/run_benchmarks.py`)**
  - Evaluates 5 core empirical experiments:
    1. Scalability & Privacy Tax ($N \in [50, 100, 200, 500, 1000, 2000]$).
    2. Component runtime breakdown (Normalization 0.1%, Hash-to-Curve 10.4%, Blinding 83.9%, Wire 5.7%).
    3. Asymmetric scale dilemma ($|A| \ll |B|$, e.g., clinic cohort vs regional hospital).
    4. Channel transport overhead (In-Memory direct channel vs Localhost TCP socket).
    5. Data quality decay & False Negative Rate ($\eta \in [0\%, 50\%]$ noise).
  - Serializes full metrics to `benchmark/results/metrics.json`.
- [x] **Task 4.3: Baseline Comparison & Security Cracker (`benchmark/baseline_naive.py` & `benchmark/security_cracker.py`)**
  - Implemented naive SHA-256 PSI baseline to measure the theoretical CPU upper bound and exact "Privacy Tax" multiplier.
  - Implemented practical cryptanalysis suite:
    - Preimage attack recovering SHA-256 CPFs in $< 0.3\text{ s}$ and CNPJs in $< 0.01\text{ s}$.
    - Exhaustive ECDLP discrete logarithm search on `secp256k1` demonstrating $\sim 140{,}000\text{ pts/s}$, proving $2.7 \times 10^{64}$ years / $1.9 \times 10^{54}$ universe lifetimes needed to exhaust the 256-bit keyspace.
- [x] **Task 4.4: Publication-Quality Plot Generation (`benchmark/plot_metrics.py`)**
  - Generated 6 publication-ready figures in `benchmark/results/`:
    - `fig1_scalability_privacy_tax.png`: Execution time and Privacy Tax curve.
    - `fig2_component_breakdown.png`: Stage breakdown bar and donut chart.
    - `fig3_asymmetric_scale.png`: Latency and wire volume under asymmetric scales.
    - `fig4_cpu_vs_network.png`: In-Memory vs TCP socket overhead.
    - `fig5_data_decay_fnr.png`: Recall resilience vs noise (Raw vs Normalized).
    - `fig6_security_cryptanalysis.png`: Keyspace coverage and crack time comparison.

---

### Phase 5: Interactive Streamlit UI & Visual Demonstration (Nov 15 – Nov 16)
*Objective: Build an intuitive, accessible web interface to make SecureMatch interactive, demonstrate protocol steps for the class presentation, and visually explore the privacy tax.*

- [ ] **Task 5.1: Streamlit Dashboard Scaffolding (`src/ui/app.py`)**
  - Multi-tab layout: Interactive PSI Playground, Step-by-Step Educational Walkthrough, Schema Designer, and Live Benchmark Visualizer.
- [ ] **Task 5.2: Interactive PSI Playground Tab**
  - Select or configure schema (CPF, CNPJ numeric/alphanumeric, Phone + Region, custom).
  - Load pre-built sample datasets or upload custom CSVs for Party A (Client) and Party B (Server).
  - Execute matching and visually inspect:
    - Normalization & CRI inspection.
    - Compressed curve points and blinded coordinates.
    - Overlap highlighting without exposing disjoint rows.
- [ ] **Task 5.3: Step-by-Step Educational Walkthrough Tab**
  - Interactive stage-by-stage visualization of the commutative double-lock:
    $a \cdot (b \cdot P) == b \cdot (a \cdot P)$.
  - Explains what an eavesdropper sees vs. what client and server learn at each step.
- [ ] **Task 5.4: Live Benchmark & Privacy Tax Visualizer Tab**
  - Run real-time performance and scalability benchmarks on synthetic datasets.
  - Interactive plots showing Latency vs. Scale and Wire Bandwidth vs. Scale compared to naive SHA-256.

### Phase 6: CLI, Presentation Slides & Final Report (Nov 16 – Nov 18)
*Objective: Package the project into an intuitive CLI tool, compile the formal academic report, and create the presentation slide deck.*

- [ ] **Task 6.1: Unified Command Line Interface (`src/cli.py`)**
  - CLI commands:
    - `securematch server --host 0.0.0.0 --port 9000 --data server.csv --schema cpf`
    - `securematch client --host 127.0.0.1 --port 9000 --data client.csv --schema cpf`
    - `securematch benchmark --scale 1000,5000,10000 --output-dir ./results`
    - `securematch ui`: Launch the interactive Streamlit dashboard.
- [ ] **Task 6.2: Final Project Report (`docs/report/report.tex`)**
  - Structure:
    1. Introduction & Regulatory Motivation (LGPD/GDPR, low-entropy vulnerability).
    2. Cryptographic Formulation & Security Reductions under CDH.
    3. Architecture, Schemas, & Normalization Pipeline.
    4. Experimental Benchmark Results & Privacy-Tax Analysis.
    5. Retrospective: Difficulties encountered, deviations from initial plan, and lessons learned.
  - Compile to `docs/report/report.pdf`.
- [ ] **Task 6.3: Presentation Slide Deck (`docs/presentation/`)**
  - 15–20 minute presentation deck covering:
    - Motivation & the Naive Hash Trap.
    - Mathematical mechanism: Commutative ECDH and Hash-to-Curve.
    - Configurable matching schemas in practice.
    - Benchmark results, charts, and linear scaling analysis.
    - Live Streamlit visual walkthrough.
- [ ] **Task 6.4: Final Packaging & Code Quality Review**
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

