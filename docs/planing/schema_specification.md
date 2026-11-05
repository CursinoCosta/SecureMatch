# SecureMatch: Match Key Specification & Canonical Record Identifier (CRI)

* **Document Version:** 1.0  
* **Date:** 2026-11-05  
* **Author:** Mateus Cursino Costa (Matrícula: `2022043191`)  
* **Project:** SecureMatch (UFMG Cryptography 2026/2)

---

## 1. Motivation: Why Key Flexibility & Normalization are Essential

In real-world data engineering, organizations looking to link records rarely share an identical database schema:
- Institution A may identify individuals by a national tax ID (**CPF** or **CNPJ**).
- Institution B may link accounts using a composite key: **Standardized Phone Number + Geographic Region (UF)**.
- Another organization may match records using a demographic composite: **Date of Birth + Full Name**.
- A private B2B consortium may agree on proprietary **Internal Account Codes**.

Furthermore, raw text strings contain formatting inconsistencies:
- Accents: `"São Paulo"` vs. `"Sao Paulo"`
- Casing: `"JOAO"` vs. `"joao"`
- Punctuation: `"123.456.789-01"` vs. `"12345678901"`
- Whitespace: `"  Maria  Silva "` vs. `"Maria Silva"`

Because cryptographic hash-to-curve functions are non-malleable and avalanche-sensitive, **even a single difference in whitespace or punctuation results in a completely different curve point**, producing false negative matching failures.

**SecureMatch** resolves this through two cooperating mechanisms:
1. **Configurable Matching Schemas:** Declarative specifications defining how fields are extracted, cleaned, and validated.
2. **Canonical Record Identifier (CRI):** A deterministic, delimiter-collision-resistant byte serializer.

---

## 2. Canonical Record Identifier (CRI) Format

To prevent **delimiter injection attacks** (where an attacker crafts an input like `name = "silva|dob:1990"` to forge composite attributes) and ensure strict byte-level determinism between both parties:

### 2.1. CRI Grammar
```text
CRI           := FIELD ("|" FIELD)*
FIELD         := FIELD_NAME ":" VALUE_LENGTH ":" NORMALIZED_VALUE
FIELD_NAME    := [a-z0-9_]+ (sorted alphabetically across fields)
VALUE_LENGTH  := ASCII integer (length of NORMALIZED_VALUE in UTF-8 bytes)
NORMALIZED_VALUE := UTF-8 byte sequence produced by field normalizers
```

### 2.2. Deterministic Sorting Rule
When a composite match key consists of multiple fields, the field keys **MUST be sorted in strict alphabetical order** before serialization. This guarantees that:
```text
Party A: { "region": "MG", "phone": "+5531999998888" }
Party B: { "phone": "+5531999998888", "region": "MG" }
```
both produce the exact same canonical string:
```text
phone:14:+5531999998888|region:2:MG
```

### 2.3. Delimiter Injection Defense
Because every value is explicitly prefixed with its exact byte length (`VALUE_LENGTH`), embedded delimiter characters (`:` or `|`) inside raw values cannot shift field boundaries or alter the parser state.

---

## 3. Pre-Built & Custom Schema Templates

SecureMatch supports standard single-key identifiers, composite attributes, and user-defined schemas:

### 3.1. Standard Identifier Templates
1. **`br_cpf` (Individual Brazilian Tax ID):**
   - Normalization: Remove all non-digit characters (`.`, `-`, spaces), pad with leading zeros to 11 digits.
   - Validation: Optional MOD-11 two-digit checksum verification.
   - Output CRI: `cpf:11:12345678901`
2. **`br_cnpj` (Corporate Brazilian Registry):**
   - Normalization: Strip formatting (`.`, `/`, `-`), pad to 14 digits.
   - Validation: MOD-11 verification.
   - Output CRI: `cnpj:14:12345678000195`
3. **`phone_region` (Standardized Phone + Geographic Area):**
   - Normalization:
     - Phone: Strip formatting, enforce E.164 standard (`+55...`).
     - Region: Uppercase ISO-3166-2 subcode (e.g., `MG`, `SP`, `RJ`).
   - Output CRI: `phone:14:+5531987654321|region:2:MG`
4. **`internal_id` (Domain-Specific / Proprietary Code):**
   - Normalization: Strip leading/trailing whitespace, uppercase, enforce alphanumeric pattern.
   - Output CRI: `account_id:10:ACC-998811`

### 3.2. Demographic Composite Key Template
- **`demographic_trio`:** Date of Birth + Normalized Full Name + Postal Code.
  - Name Normalization: Unicode NFKD decomposition, diacritic removal (`é` $\rightarrow$ `e`, `ç` $\rightarrow$ `c`), lowercase, single space collapse.
  - Date Normalization: ISO-8601 (`YYYY-MM-DD`).
  - Output CRI: `dob:10:1995-08-15|name:14:joao da silva|zip:8:30130100`

---

## 4. Declarative Schema Specification (JSON / YAML)

Schemas can be specified declaratively in JSON or YAML so Client and Server can configure their session:

```json
{
  "schema_id": "br_phone_region",
  "version": "1.0",
  "description": "Standardized Brazilian mobile phone and state federation code",
  "fields": [
    {
      "name": "phone",
      "type": "string",
      "normalizers": ["strip_non_digits", "e164_br"],
      "required": true
    },
    {
      "name": "region",
      "type": "string",
      "normalizers": ["strip_whitespace", "uppercase"],
      "regex": "^[A-Z]{2}$",
      "required": true
    }
  ]
}
```

---

## 5. Protocol Schema Negotiation (Handshake)

Before any cryptographic curve operations occur:
1. **Client Proposal:** In Round 1, the Client includes a cryptographic digest of the schema:
   $$\text{SchemaHash} = \text{SHA-256}(\text{Canonical JSON Representation of Schema})$$
2. **Server Verification:** The Server verifies that its local input dataset is bound to the identical $\text{SchemaHash}$.
3. **Mismatch Handling:** If the schemas differ, the Server immediately aborts the connection with a `SCHEMA_MISMATCH_ERROR`, preventing unintended computational load or protocol failure.
