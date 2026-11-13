# Master Prompt: Slide Deck Generation for Graduate Seminar Presentation
## Topic: Confidential Record Linkage via Elliptic-Curve Diffie-Hellman Private Set Intersection (ECDH-PSI)

---

### INSTRUCTIONS FOR THE SLIDE GENERATION AGENT / DESIGNER

You are an expert academic presentation designer and university lecturer specializing in Applied Cryptography, Distributed Systems, and Privacy-Enhancing Technologies (PETs). 

Your objective is to generate an authoritative, highly polished **8-to-9 slide graduate-level presentation deck** (suitable for a 15-minute seminar at UFMG - DCC) based strictly on the rigorous mathematical, architectural, and empirical content provided below.

#### Tone, Style & Aesthetic Constraints:
1. **Academic & Professional Rigor:** Strictly avoid generic "AI marketing buzzwords" (e.g., *"revolutionizing"*, *"game-changer"*, *"seamless magic"*, *"supercharge"*, *"unlocking potential"*). Maintain an objective, formal academic register suitable for a master's or doctoral defense.
2. **Layout & Typography:** Clean, high-contrast, minimalist scientific presentation style (reminiscent of LaTeX Beamer or top-tier conference decks like IEEE S&P, USENIX Security, ACM CCS). Use monospaced font blocks for mathematical notation, cryptographic signatures, and protocol exchanges.
3. **Information Density & Focus:** Zero slide clutter. Rather than inundating the audience with multiple secondary graphs, each slide addresses a single core theoretical or empirical question.
4. **Visual Assets:** Reference the exact figures located in `presentation/assets/` where indicated.

---

## SLIDE SPECIFICATIONS (15-Minute Seminar Arc)

---

### Slide 1: Title & Administrative Context
- **Header:** Confidential Record Linkage via Elliptic-Curve Diffie-Hellman Private Set Intersection (ECDH-PSI)
- **Subtitle:** Practical, Symmetrical Entity Resolution Under the Semi-Honest Adversarial Model
- **Metadata:**
  - Course: Advanced Cryptography / Security Seminar (UFMG - DCC)
  - Date & Academic Term: 2026
  - Presentation Duration: 15 Minutes
- **Visual Design:** Formal academic cover layout. Clean margins, prominent title hierarchy, institutional metadata.

---

### Slide 2: The Data Collaboration Dilemma & Threat Formulation
- **Slide Title:** The Record Linkage Dilemma: Utility vs. Cryptographic Confidentiality
- **Problem Statement:**
  - Distinct administrative entities (e.g., healthcare networks, financial institutions, public registries) maintain separate databases containing fragmented observations of overlapping population cohorts.
  - Mutual objective: Compute the exact intersection $I = S_A \cap S_B$ to enable longitudinal research, fraud ring identification, or epidemiological tracing.
  - Legal & Regulatory Constraints: Modern data protection statutes (LGPD, GDPR, HIPAA) mandate that non-intersecting records ($S_A \setminus I$ and $S_B \setminus I$) remain completely unrevealed.
- **Adversarial & Threat Model:**
  - **Semi-Honest (Honest-but-Curious) Model:** Participating nodes follow protocol execution rules faithfully, but inspect intermediate network transcripts and internal state to infer sensitive non-intersecting attributes.
  - **Decentralized Symmetry:** Peer-to-peer topology—zero reliance on trusted third-party escrow (TTPs), centralized coordinators, or hardware enclaves (TEEs).
- **Visual Element:** Clean Venn diagram showing datasets $S_A$ and $S_B$, with the intersection $I = S_A \cap S_B$ highlighted and cryptographic boundary locks on disjoint sets $(S_A \setminus I, S_B \setminus I)$.

---

### Slide 3: The Naive Fallacy: Why Deterministic Hashing Fails
- **Slide Title:** The "Hash-and-Compare" Fallacy: Insecurity of Deterministic Digests
- **The Naive Industry Practice:**
  - Organizations frequently attempt confidential matching by hashing primary identifiers with SHA-256 and exchanging raw digest lists:
    $$\text{Match condition: } \mathcal{H}(x) \stackrel{?}{=} \mathcal{H}(y)$$
- **Theoretical Vulnerability:**
  - Pre-image collision resistance ($\sim 2^{256}$) relies on high min-entropy across the input domain $\mathcal{X}$.
  - Real-world canonical identifiers exhibit bounded, low-entropy spaces:
    - Brazilian National ID (CPF): 9 digits + 2 check digits $\rightarrow |\mathcal{X}| = 10^9 \approx 2^{29.9}$ states.
    - National E.164 Telephone Numbers: 10 to 11 digits $\rightarrow |\mathcal{X}| \approx 10^{11} \approx 2^{36.5}$ states.
- **Empirical Cryptanalytic Inversion:**
  - Modern commodity GPUs evaluate $>10^{10}$ SHA-256 digests/second. The entire valid CPF population space ($10^9$) is completely inverted via offline dictionary or rainbow-table attacks in **$< 100$ milliseconds**.
  - Salt distribution paradox: Symmetric salts require pre-shared keys (creating insider vulnerability); asymmetric salts destroy deterministic equality checking.
- **Key Takeaway:** Unblinded deterministic hashing provides **zero forward privacy** against semi-honest peers.

---

### Slide 4: Cryptographic Primitive: Commutative ECDH-PSI
- **Slide Title:** Protocol Foundation: Commutative Diffie-Hellman on Elliptic Curves
- **Mathematical Foundations:**
  - Let $E(\mathbb{F}_p)$ be the Koblitz curve **$\text{secp256k1}$** of prime order $r$.
  - Hash-to-Curve function $\mathcal{H}_E: \{0,1\}^* \rightarrow E(\mathbb{F}_p)$ mapping arbitrary canonical records to non-identity curve points (via rejection sampling / try-and-increment).
  - Secret Ephemeral Scalars:
    - Party $A$ samples $k_A \stackrel{\$}{\leftarrow} \mathbb{Z}_r^*$
    - Party $B$ samples $k_B \stackrel{\$}{\leftarrow} \mathbb{Z}_r^*$
- **Two-Pass Commutative Blinding:**
  1. **Phase 1 (Local Blinding):**
     $$P_A = \{ k_A \cdot \mathcal{H}_E(x_i) \mid x_i \in S_A \}, \quad P_B = \{ k_B \cdot \mathcal{H}_E(y_j) \mid y_j \in S_B \}$$
  2. **Phase 2 (Cross-Blinding Exchange):**
     $$T_A = \{ k_B \cdot P_A = k_B \cdot k_A \cdot \mathcal{H}_E(x_i) \}, \quad T_B = \{ k_A \cdot P_B = k_A \cdot k_B \cdot \mathcal{H}_E(y_j) \}$$
  3. **Intersection Property (Commutativity over Abelian Curve Groups):**
     $$k_A \cdot (k_B \cdot \mathcal{H}_E(x)) = (k_A \cdot k_B) \cdot \mathcal{H}_E(x) = k_B \cdot (k_A \cdot \mathcal{H}_E(x))$$
- **Hardness Guarantee:**
  - Security reduces directly to the **Elliptic Curve Discrete Logarithm Problem (ECDLP)** and the **Computational Diffie-Hellman (CDH)** assumption on $\text{secp256k1}$ ($\sim 128$-bit security level).
  - Intercepting $k_A \cdot \mathcal{H}_E(x)$ leaks zero computational information regarding $\mathcal{H}_E(x)$ or scalar $k_A$.

---

### Slide 5: The SecureMatch Pipeline & Engineering Perks
- **Slide Title:** Production Architecture: Normalization, Key Synthesis & Peer-to-Peer Execution
- **System Components:**
  1. **Canonical Record Identifier (CRI) Standardization:**
     - Deterministic multi-stage normalization (Unicode NFKC canonical decomposition, punctuation stripping, consistent casing).
     - Solves the practical challenge of typographical inconsistencies *before* cryptographic hash-to-curve without leaking raw values.
  2. **Composite Key Synthesis:**
     - Dynamic multi-attribute key construction (e.g., `Phone + State`, `FirstNameInitial + BirthDate + PostalCode`).
     - Shareable Bilateral Match Specifications (deterministic JSON profiles governing field precedence and delimiters).
  3. **Cryptographic Core:**
     - Optimized scalar multiplication with affine coordinate transforms and 33-byte SEC1 compressed point serialization (`0x02` / `0x03` header prefix).
  4. **Decentralized Symmetrical Operation:**
     - Zero coordinator role; identical code paths execute symmetrically on both endpoints.
- **Architectural Value:** Separates sensitive payload data from linkage tokens—only ephemeral 33-byte cryptographic points are ever transmitted over the network.

---

### Slide 6: Empirical Scalability & Computational Decomposition
- **Slide Title:** Empirical Scalability: Strict $O(N)$ Linearity up to $500{,}000$ Records
- **Visual Assets:**
  - **Primary Figure (Full Width / Prominent):** `presentation/assets/fig1_scalability_privacy_tax.png`
  - **Secondary Inset (Corner / Compact):** `presentation/assets/fig2_component_breakdown.png`
- **Key Experimental Results:**
  - **Linear Complexity:** Protocol runtime maintains exact empirical $O(N)$ scaling across all tested volumes ($1{,}000$ to $500{,}000$ records per party, $1{,}000{,}000$ records total).
  - **Predictable Latency Profile:**
    - 1,000 records: $< 0.8$ seconds
    - 50,000 records: $\approx 35.6$ seconds
    - 500,000 records: Consistent linear progression with zero memory cliffs or garbage-collection stalls.
  - **Computational Breakdown (`fig2`):**
    - Scalar point multiplication dominates ($>88\%$ of CPU cycles).
    - Hash-to-curve try-and-increment represents $\approx 9\%$.
    - Set lookup and local hash-table operations represent $<3\%$.
  - **Speaker Takeaway:** Demonstrates that the "privacy tax" of strong cryptography is purely linear and completely practical on standard enterprise servers.

---

### Slide 7: Bandwidth Overhead & High-Assurance Cryptanalysis
- **Slide Title:** Network Efficiency & The 3-Hour Exhaustion Attack
- **Visual Assets (Two-Column Layout):**
  - **Left Column:** `presentation/assets/fig4_cpu_vs_network.png` (Bandwidth vs. CPU)
  - **Right Column:** `presentation/assets/fig6_security_cryptanalysis.png` (Exhaustion Attack)
- **Column 1: Network Footprint:**
  - Transmission cost is strictly fixed at **$33 \text{ bytes} \times N$** per exchange direction (SEC1 compressed points).
  - Linking $100{,}000$ records requires only **$3.3 \text{ MB}$** of network payload.
  - Asymmetric resource profile: Protocol is strictly CPU-bound, never network-bound—ideal for cross-datacenter and public-cloud execution.
- **Column 2: The 3-Hour Cryptanalytic Stress Test:**
  - **Adversarial Setup:** Semi-honest attacker armed with a precomputed dictionary of $10^7$ candidate identity points attempting offline scalar inversion against wiretapped tokens.
  - **Duration:** 3.0 continuous hours ($10{,}800$ seconds) under sustained execution.
  - **Empirical Metric:** **$1{,}411{,}726{,}800$ point operations** ($\approx 1.411 \times 10^9$ attempts).
  - **Empirical Success Rate:** **Strictly 0.000%** (zero keys recovered, zero records deanonymized).
  - **Theoretical Horizon:** Full scalar domain exhaustion of $\text{secp256k1}$ ($r \approx 1.1579 \times 10^{77}$) requires $> 10^{60}$ compute-years.

---

### Slide 8: Synthesis, Practical Trade-offs & Conclusions
- **Slide Title:** Conclusions, Trade-offs, and Future Directions
- **Core Contributions:**
  1. Validated that commutative elliptic-curve PSI delivers mathematically sound, regulatory-compliant (LGPD/GDPR) record linkage without trusted third parties.
  2. Overcame the fatal security flaws of deterministic hashing while preserving linear computational scalability and negligible bandwidth overhead ($33$ bytes/record).
  3. Engineered an open-source, reproducible peer-to-peer system featuring deterministic canonicalization profiles and cryptographic audit trails.
- **Fundamental Trade-offs & Boundaries:**
  - **Exact-Match vs. Fuzzy Matching:** Cryptographic PSI is strictly exact-match by definition (any character discrepancy triggers the cryptographic avalanche effect); robust canonicalization and composite key strategies are required upstream.
  - **Adversarial Model:** Guarantees hold under the semi-honest model; extending to malicious adversaries requires zero-knowledge proofs of well-formedness (e.g., Schnorr proofs of discrete log equality).
- **Future Optimizations:**
  - Parallel scalar multiplication via SIMD vectorization and GPU acceleration.
  - Interfacing with Privacy-Preserving Record Linkage (PPRL) Bloom-filter sketches for approximate linkage prior to exact PSI.

---

## SPEAKER Q&A QUICK-REFERENCE TABLE

| Dimension | Measured / Implemented Value |
|---|---|
| Elliptic Curve Primitive | Koblitz `secp256k1` ($\mathbb{F}_p$, 256-bit prime) |
| Security Equivalency | $\sim 128$ bits of symmetric security |
| Wire Serialization Format | SEC1 Compressed Point (33 bytes) |
| Maximum Experimental Scale | 500,000 records per organization (1,000,000 total) |
| Computational Complexity | Strict $O(N)$ scalar point multiplications |
| 3-Hour Exhaustion Work Factor | 1,411,726,800 point operations ($1.411 \times 10^9$) |
| Exhaustion Attack Success Rate | **0.000%** |
| Classical Time to Invert SHA-256 on CPF | $< 100$ milliseconds |
| Classical Time to Invert secp256k1 Scalar | Infeasible ($> 10^{60}$ compute-years) |
