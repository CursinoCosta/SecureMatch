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
    - Brazilian Corporate ID (CNPJ): 8 base digits + 4 branch digits + 2 check digits.
    - National E.164 Telephone Numbers: 10 to 11 digits $\rightarrow |\mathcal{X}| \approx 10^{11} \approx 2^{36.5}$ states.
- **The Core Flaw:** Deterministic hashing without secret-key binding offers zero forward privacy. Any observer or semi-honest participant with a precomputed dictionary can invert the entire identifier universe.

---

### Slide 4: Empirical Cryptanalysis: Cracking SHA-256 vs. secp256k1 Exhaustion
- **Slide Title:** Empirical Security: Inverting SHA-256 vs. Exhausting $\text{secp256k1}$
- **Objective:** Directly contrast the vulnerability of deterministic SHA-256 against the computational hardness of the $\text{secp256k1}$ discrete logarithm problem using exact empirical measurements.
- **Layout & Visual Structure:** Two distinct, high-contrast panels/columns comparing identical adversary resources.

- **Panel A: The Fragility of SHA-256 (Empirical Inversion)**
  - **Attack Model:** Deterministic pre-image recovery via sequential dictionary lookup against intercepted hashes on commodity single-core CPU.
  - **Case 1 — Brazilian National ID (CPF):**
    - Target Plaintext: `12345678909`
    - Target Hash: `7ec94663084bd506d4f0c3e21042df233681fd7426e93f397c921b1d3e397bba`
    - Evaluated Attempts: `56,790` evaluations
    - Execution Time to Crack: **`0.2835977739998725` seconds** ($\approx 283.60 \text{ ms}$)
    - Sustained Hash Rate: `200,248.40` hashes/sec
  - **Case 2 — Brazilian Corporate Tax ID (CNPJ):**
    - Target Plaintext: `12345678000195`
    - Target Hash: `ae9351af0d397d503ea2ec21addc17e364b940411cfa37d8e8874c06b550a40b`
    - Evaluated Attempts: `679` evaluations
    - Execution Time to Crack: **`0.0029102910000347038` seconds** ($\approx 2.91 \text{ ms}$)
    - Sustained Hash Rate: `233,310.00` hashes/sec
  - **Cryptanalytic Verdict:** Complete compromise. Low-entropy identifiers hashed with SHA-256 provide **zero security** against an honest-but-curious peer.

- **Panel B: The Intractability of $\text{secp256k1}$ (3-Hour Exhaustion Attack)**
  - **Attack Model:** Semi-honest wiretapper attempting to invert blinded curve point $P = k \cdot H(x)$ via scalar exhaustion over the elliptic curve subgroup.
  - **Key Space Dimension:**
    - Subgroup prime order $r$:
      $$r = 115792089237316195423570985008687907852837564279074904382605163141518161494337$$
      ($\approx 1.157920892373162 \times 10^{77}$ discrete states)
  - **Empirical Attack Parameters & Measured Results:**
    - Continuous Execution Duration: **`10800.048020872` seconds** (`3.0000133391311112` hours)
    - Total Point Multiplications Evaluated: **`1,411,050,000` attempts** ($\approx 1.41105 \times 10^9$)
    - Sustained Throughput: `130,652.20` scalar point ops/sec
    - Attack Success Rate: **Strictly 0.000%** (zero keys recovered, zero points inverted)
  - **Proportion of Keyspace Explored:**
    $$\text{Keyspace Explored} = \mathbf{1.2186065639666016 \times 10^{-66}\%}$$
    $$\left(\text{Fraction of total space: } 1.2186065639666016 \times 10^{-68}\right)$$
  - **Theoretical Horizon at Measured Throughput:**
    - Time required to exhaust scalar space: **`2.8083950981450736` $\times 10^{64}$ years**
    - Equivalent to **`2.0350689116993288` $\times 10^{54}$ lifetimes of the universe** (assuming $\approx 1.38 \times 10^{10}$ years/lifetime).

- **Slide Takeaway:** While raw SHA-256 breaks in fractions of a second (`0.0029` s to `0.2836` s), 3 hours of non-stop attack on $\text{secp256k1}$ covered only $10^{-66}\%$ of the space. Blinded curve points are computationally impenetrable.

---

### Slide 5: Cryptographic Primitive: Commutative ECDH-PSI
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

### Slide 6: The SecureMatch Pipeline & Engineering Perks
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

### Slide 7: Empirical Scalability & Computational Decomposition
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

### Slide 8: Bandwidth Overhead & Security Summary
- **Slide Title:** Network Footprint & The Asymmetric Resource Profile
- **Visual Asset:** `presentation/assets/fig4_cpu_vs_network.png` (Bandwidth vs. CPU)
- **Key Findings:**
  - Transmission cost is strictly fixed at **$33 \text{ bytes} \times N$** per exchange direction (SEC1 compressed points).
  - Linking $100{,}000$ records requires only **$3.3 \text{ MB}$** of network payload.
  - Asymmetric resource profile: Protocol is strictly CPU-bound, never network-bound—ideal for cross-datacenter and public-cloud execution.

---

### Slide 9: Synthesis, Practical Trade-offs & Conclusions
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
| Curve Subgroup Order $r$ | `115792089237316195423570985008687907852837564279074904382605163141518161494337` |
| Security Equivalency | $\sim 128$ bits of symmetric security |
| Wire Serialization Format | SEC1 Compressed Point (33 bytes) |
| Maximum Experimental Scale | 500,000 records per organization (1,000,000 total) |
| Computational Complexity | Strict $O(N)$ scalar point multiplications |
| SHA-256 CPF Crack Time | `0.2835977739998725` s (`56,790` attempts @ `200,248.40` ops/s) |
| SHA-256 CNPJ Crack Time | `0.0029102910000347038` s (`679` attempts @ `233,310.00` ops/s) |
| secp256k1 Continuous Attack Duration | `10800.048020872` s (`3.0000133391311112` hours) |
| secp256k1 Point Multiplications Evaluated | `1,411,050,000` attempts |
| secp256k1 Exhaustion Success Rate | **Strictly 0.000%** (0 keys recovered) |
| secp256k1 Keyspace Explored | **`1.2186065639666016e-66`%** (`1.2186065639666016e-68` fraction) |
| Time to Exhaust secp256k1 at Measured Rate | `2.8083950981450736e+64` years (`2.0350689116993288e+54` universe lifetimes) |
