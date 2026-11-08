"""
SecureMatch — Confidential Record Linkage Application (Streamlit).

A peer-to-peer data collaboration interface between two symmetric organizations
(e.g., Hospital A and Hospital B) to perform Private Set Intersection (PSI):
- Step 1: Upload real databases (any CSV, any columns).
- Step 2: Map the shared primary key (CPF, CNPJ [numeric/alphanumeric], Phone+Region, Custom).
- Step 3: Run the commutative ECDH-PSI protocol (simulated / localhost).
- Step 4: Both hospitals receive their own enriched database tagged with `matched: YES / NO`,
          with options to export the full table or keys-only.
"""

import csv
import io
import os
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure project root is in Python module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import streamlit as st
from src.crypto.curve import Point, generate_private_scalar
from src.crypto.engine import blind_point, hash_and_blind
from src.crypto.hash_to_curve import hash_to_curve
from src.data_pipeline.schema import (
    FieldDefinition,
    Schema,
    create_cnpj_schema,
    create_cpf_schema,
    create_custom_schema,
    create_internal_id_schema,
    create_phone_region_schema,
)

st.set_page_config(
    page_title="SecureMatch — Confidential Record Linkage",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom Styling
st.markdown("""
<style>
    .main-title { font-size: 2.2rem; font-weight: 700; color: #1E3A8A; margin-bottom: 0.1rem; }
    .sub-title { font-size: 1.05rem; color: #4B5563; margin-bottom: 1.2rem; }
    .org-card { background-color: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 10px; padding: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    .org-header-a { color: #1D4ED8; font-weight: 700; font-size: 1.25rem; margin-bottom: 8px; border-bottom: 2px solid #DBEAFE; padding-bottom: 6px; }
    .org-header-b { color: #7E22CE; font-weight: 700; font-size: 1.25rem; margin-bottom: 8px; border-bottom: 2px solid #F3E8FF; padding-bottom: 6px; }
    .step-badge { background-color: #F3F4F6; color: #374151; font-weight: 600; padding: 3px 8px; border-radius: 4px; font-size: 0.85rem; }
    .security-banner { background-color: #ECFDF5; border: 1px solid #10B981; color: #065F46; padding: 12px 16px; border-radius: 8px; margin-top: 15px; margin-bottom: 15px; }
    .cri-preview { background-color: #F9FAFB; border-left: 3px solid #3B82F6; font-family: monospace; font-size: 0.86rem; padding: 6px 10px; border-radius: 3px; word-break: break-all; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🏥 SecureMatch: Confidential Record Linkage</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-title">'
    'Privacy-Preserving Entity Reconciliation between Independent Organizations &bull; Commutative ECDH-PSI &bull; UFMG'
    '</div>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Pre-built Sample Data Generators (for quick 1-click testing)
# ---------------------------------------------------------------------------
DEFAULT_HOSPITAL_A_CSV = (
    "id_paciente,cpf_titular,nome_completo,diagnostico,leito\n"
    "HOSP-001,123.456.789-01,Alice Silva,Diabetes Tipo 2,A-102\n"
    "HOSP-002,234.567.890-12,Bob Santos,Hipertensão,B-205\n"
    "HOSP-003,345.678.901-23,Carol Lima,Asma Grave,C-104\n"
    "HOSP-004,456.789.012-34,Daniel Souza,Fratura Fêmur,A-108\n"
    "HOSP-005,567.890.123-45,Eduardo Rocha,Arritmia,ICU-03\n"
    "HOSP-006,678.901.234-56,Fabiana Mendes,Pneumonia,B-210\n"
)

DEFAULT_HOSPITAL_B_CSV = (
    "reg_atendimento,doc_cpf,data_admissao,procedimento,convenio\n"
    "REG-901,999.888.777-66,2026-01-10,Exame Sangue,Unimed\n"
    "REG-902,23456789012,2026-02-14,Ressonância Magnética,Bradesco\n"  # Match (unformatted)
    "REG-903,12345678901,2026-03-01,Consulta Cardiologia,SulAmerica\n" # Match (unformatted)
    "REG-904,34567890123,2026-03-15,Espirometria,Amil\n"             # Match (unformatted)
    "REG-905,888.777.666-55,2026-04-20,Tomografia,Particular\n"
    "REG-906,56789012345,2026-05-12,Ecocardiograma,Unimed\n"          # Match (unformatted)
)


def load_csv_data(raw_text: str) -> Tuple[List[Dict[str, str]], List[str]]:
    """Parses raw CSV string into list of row dicts and headers."""
    f = io.StringIO(raw_text.strip())
    reader = csv.DictReader(f)
    rows = list(reader)
    headers = reader.fieldnames if reader.fieldnames else []
    return rows, list(headers)


# ---------------------------------------------------------------------------
# Top Controls: Global Agreement on Match Key Pattern
# ---------------------------------------------------------------------------
st.markdown("### 1. Peer Agreement: Shared Primary Key Standard")
st.caption(
    "Both organizations must agree on what kind of identifier they will use to link records "
    "(e.g., CPF, CNPJ, or Phone). Column names in their respective files can be completely different."
)

col_key_type, col_quick_load = st.columns([2, 1])

with col_key_type:
    key_type = st.selectbox(
        "Agreed Matching Key Format:",
        [
            "Brazilian CPF (Individual Tax ID — 11 digits)",
            "Brazilian CNPJ (Corporate Registry — Numeric or Modern Alphanumeric)",
            "Composite: Phone Number + State / Region (E.164 + UF)",
            "Custom Alphanumeric Code / Internal ID",
        ],
        index=0,
    )

with col_quick_load:
    st.write("")
    st.write("")
    if st.button("🔄 Reset / Load Hospital Sample Cohorts"):
        st.session_state["raw_csv_a"] = DEFAULT_HOSPITAL_A_CSV
        st.session_state["raw_csv_b"] = DEFAULT_HOSPITAL_B_CSV
        st.experimental_rerun() if hasattr(st, "experimental_rerun") else st.rerun()

st.markdown("---")

# ---------------------------------------------------------------------------
# Symmetrical Peer Configuration: Hospital A vs. Hospital B
# ---------------------------------------------------------------------------
col_party_a, col_party_b = st.columns(2)

# ===========================================================================
# HOSPITAL A (PARTICIPANT A)
# ===========================================================================
with col_party_a:
    st.markdown('<div class="org-header-a">🏢 Organization A (e.g., Hospital A)</div>', unsafe_allow_html=True)
    st.markdown('<span class="step-badge">Step 1</span> **Upload Local Database**', unsafe_allow_html=True)

    file_a = st.file_uploader(
        "Upload Hospital A CSV file:",
        type=["csv"],
        key="upload_a",
        help="Upload any CSV file. Columns do not need to match Organization B.",
    )

    if file_a is not None:
        raw_content_a = file_a.getvalue().decode("utf-8-sig")
    else:
        raw_content_a = st.session_state.get("raw_csv_a", DEFAULT_HOSPITAL_A_CSV)

    rows_a, headers_a = load_csv_data(raw_content_a)
    st.caption(f"Loaded **{len(rows_a)}** records &bull; Columns: `{', '.join(headers_a[:4])}...`")

    with st.expander("👁️ Preview Hospital A Data", expanded=False):
        st.dataframe(rows_a[:5], use_container_width=True)

    st.markdown('<span class="step-badge">Step 2</span> **Map Your Primary Key Column**', unsafe_allow_html=True)
    if not headers_a:
        st.warning("Please upload a valid CSV with headers for Organization A.")
        mapped_rows_a = []
        schema_a = create_cpf_schema()
    else:
        if "CPF" in key_type:
            def_idx_a = headers_a.index("cpf_titular") if "cpf_titular" in headers_a else 0
            col_a = st.selectbox("Select column containing the CPF:", headers_a, index=def_idx_a, key="col_map_a")
            schema_a = create_cpf_schema()
            mapped_rows_a = [{"cpf": r[col_a]} for r in rows_a]
            key_col_a = col_a

        elif "CNPJ" in key_type:
            def_idx_a = 0
            col_a = st.selectbox("Select column containing the CNPJ:", headers_a, index=def_idx_a, key="col_map_a")
            schema_a = create_cnpj_schema(strict=False)
            mapped_rows_a = [{"cnpj": r[col_a]} for r in rows_a]
            key_col_a = col_a

        elif "Phone" in key_type:
            c1, c2 = st.columns(2)
            col_phone_a = c1.selectbox("Phone column:", headers_a, index=0, key="col_phone_a")
            col_reg_a = c2.selectbox("Region/UF column:", headers_a, index=min(1, len(headers_a) - 1), key="col_reg_a")
            schema_a = create_phone_region_schema()
            mapped_rows_a = [{"phone": r[col_phone_a], "region": r[col_reg_a]} for r in rows_a]
            key_col_a = f"{col_phone_a} + {col_reg_a}"

        else:
            col_a = st.selectbox("Select identifier column:", headers_a, index=0, key="col_map_a")
            schema_a = create_internal_id_schema(id_field_name="id")
            mapped_rows_a = [{"id": r[col_a]} for r in rows_a]
            key_col_a = col_a

        # Live Normalization Preview for Hospital A
        if mapped_rows_a:
            sample_cri_a = schema_a.serialize_record(mapped_rows_a[0]).decode("utf-8")
            st.markdown(
                f"**Normalization Preview (First Record):**<div class='cri-preview'>{sample_cri_a}</div>",
                unsafe_allow_html=True,
            )

# ===========================================================================
# HOSPITAL B (PARTICIPANT B)
# ===========================================================================
with col_party_b:
    st.markdown('<div class="org-header-b">🏥 Organization B (e.g., Hospital B)</div>', unsafe_allow_html=True)
    st.markdown('<span class="step-badge">Step 1</span> **Upload Local Database**', unsafe_allow_html=True)

    file_b = st.file_uploader(
        "Upload Hospital B CSV file:",
        type=["csv"],
        key="upload_b",
        help="Upload any CSV file. Columns do not need to match Organization A.",
    )

    if file_b is not None:
        raw_content_b = file_b.getvalue().decode("utf-8-sig")
    else:
        raw_content_b = st.session_state.get("raw_csv_b", DEFAULT_HOSPITAL_B_CSV)

    rows_b, headers_b = load_csv_data(raw_content_b)
    st.caption(f"Loaded **{len(rows_b)}** records &bull; Columns: `{', '.join(headers_b[:4])}...`")

    with st.expander("👁️ Preview Hospital B Data", expanded=False):
        st.dataframe(rows_b[:5], use_container_width=True)

    st.markdown('<span class="step-badge">Step 2</span> **Map Your Primary Key Column**', unsafe_allow_html=True)
    if not headers_b:
        st.warning("Please upload a valid CSV with headers for Organization B.")
        mapped_rows_b = []
        schema_b = create_cpf_schema()
    else:
        if "CPF" in key_type:
            def_idx_b = headers_b.index("doc_cpf") if "doc_cpf" in headers_b else 0
            col_b = st.selectbox("Select column containing the CPF:", headers_b, index=def_idx_b, key="col_map_b")
            schema_b = create_cpf_schema()
            mapped_rows_b = [{"cpf": r[col_b]} for r in rows_b]
            key_col_b = col_b

        elif "CNPJ" in key_type:
            def_idx_b = 0
            col_b = st.selectbox("Select column containing the CNPJ:", headers_b, index=def_idx_b, key="col_map_b")
            schema_b = create_cnpj_schema(strict=False)
            mapped_rows_b = [{"cnpj": r[col_b]} for r in rows_b]
            key_col_b = col_b

        elif "Phone" in key_type:
            c1, c2 = st.columns(2)
            col_phone_b = c1.selectbox("Phone column:", headers_b, index=0, key="col_phone_b")
            col_reg_b = c2.selectbox("Region/UF column:", headers_b, index=min(1, len(headers_b) - 1), key="col_reg_b")
            schema_b = create_phone_region_schema()
            mapped_rows_b = [{"phone": r[col_phone_b], "region": r[col_reg_b]} for r in rows_b]
            key_col_b = f"{col_phone_b} + {col_reg_b}"

        else:
            col_b = st.selectbox("Select identifier column:", headers_b, index=0, key="col_map_b")
            schema_b = create_internal_id_schema(id_field_name="id")
            mapped_rows_b = [{"id": r[col_b]} for r in rows_b]
            key_col_b = col_b

        # Live Normalization Preview for Hospital B
        if mapped_rows_b:
            sample_cri_b = schema_b.serialize_record(mapped_rows_b[0]).decode("utf-8")
            st.markdown(
                f"**Normalization Preview (First Record):**<div class='cri-preview'>{sample_cri_b}</div>",
                unsafe_allow_html=True,
            )

st.markdown("---")

# ---------------------------------------------------------------------------
# Step 3: Peer-to-Peer Execution & Matching
# ---------------------------------------------------------------------------
st.markdown("### 2. Confidential Linkage Execution")

# Check Schema Handshake Fingerprints
fp_a = schema_a.fingerprint()
fp_b = schema_b.fingerprint()

if fp_a != fp_b:
    st.error(
        f"❌ Handshake Mismatch: Both organizations must agree on the same matching key format. "
        f"Fingerprint A: `{fp_a[:12]}...` vs Fingerprint B: `{fp_b[:12]}...`"
    )
    can_run = False
else:
    st.success(f"✅ Cryptographic Handshake Verified: Both organizations agreed on schema **'{schema_a.schema_id}'** (`{fp_a[:16]}...`)")
    can_run = True

btn_run = st.button(
    "🔒 Run Confidential Record Linkage (Commutative ECDH-PSI)",
    type="primary",
    disabled=not can_run or len(mapped_rows_a) == 0 or len(mapped_rows_b) == 0,
    use_container_width=True,
)


def execute_mutual_psi(
    rows_a_raw: List[Dict[str, Any]],
    rows_b_raw: List[Dict[str, Any]],
    norm_a: List[Dict[str, Any]],
    norm_b: List[Dict[str, Any]],
    schema: Schema,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int, ChannelMetrics]:
    """
    Executes symmetrical Commutative ECDH-PSI:
    Both Hospital A and Hospital B receive their own database with `matched: YES / NO`.
    Zero non-matching rows or plaintext records are revealed to the other party.
    """
    t_start = time.perf_counter()

    # Generate private secret keys for both organizations
    scalar_a = generate_private_scalar()
    scalar_b = generate_private_scalar()

    # 1. Map to CRI bytes
    cri_a = [schema.serialize_record(r) for r in norm_a]
    cri_b = [schema.serialize_record(r) for r in norm_b]

    # 2. Map to curve points and blind locally
    t_c1 = time.perf_counter()
    pt_a = [hash_to_curve(x) for x in cri_a]
    blinded_a = [blind_point(scalar_a, p) for p in pt_a]  # a * H(x_i)
    crypto_time_a = (time.perf_counter() - t_c1) * 1000

    t_s1 = time.perf_counter()
    pt_b = [hash_to_curve(y) for y in cri_b]
    blinded_b = [blind_point(scalar_b, p) for p in pt_b]  # b * H(y_j)
    crypto_time_b = (time.perf_counter() - t_s1) * 1000

    # 3. Exchange & Double-blind
    # Hospital B blinds Hospital A's points: b * (a * H(x_i)) = (ab) * H(x_i)
    doubly_a = [blind_point(scalar_b, p_a) for p_a in blinded_a]

    # Hospital A blinds Hospital B's points: a * (b * H(y_j)) = (ab) * H(y_j)
    doubly_b = [blind_point(scalar_a, p_b) for p_b in blinded_b]

    # 4. Resolve matches on both sides using compressed point representations
    set_doubly_b: Set[bytes] = {p.to_compressed_bytes() for p in doubly_b}
    set_doubly_a: Set[bytes] = {p.to_compressed_bytes() for p in doubly_a}

    # Tag Hospital A's rows with `matched: YES / NO`
    enriched_a: List[Dict[str, Any]] = []
    match_count = 0
    for idx, row in enumerate(rows_a_raw):
        row_copy = dict(row)
        is_match = doubly_a[idx].to_compressed_bytes() in set_doubly_b
        row_copy["matched"] = "YES" if is_match else "NO"
        enriched_a.append(row_copy)
        if is_match:
            match_count += 1

    # Tag Hospital B's rows with `matched: YES / NO`
    enriched_b: List[Dict[str, Any]] = []
    for idx, row in enumerate(rows_b_raw):
        row_copy = dict(row)
        is_match = doubly_b[idx].to_compressed_bytes() in set_doubly_a
        row_copy["matched"] = "YES" if is_match else "NO"
        enriched_b.append(row_copy)

    total_time_ms = (time.perf_counter() - t_start) * 1000
    wire_bytes = (len(cri_a) + len(cri_b) + len(doubly_a) + len(doubly_b)) * 33

    metrics = ChannelMetrics(
        total_bytes_sent_client=len(cri_a) * 33,
        total_bytes_sent_server=len(cri_b) * 33,
        total_bytes_wire=wire_bytes,
        execution_time_ms=total_time_ms,
        client_crypto_time_ms=crypto_time_a,
        server_crypto_time_ms=crypto_time_b,
    )

    return enriched_a, enriched_b, match_count, metrics


if btn_run:
    with st.spinner("Executing Commutative Diffie-Hellman Protocol over secp256k1..."):
        enriched_a, enriched_b, shared_count, metrics = execute_mutual_psi(
            rows_a, rows_b, mapped_rows_a, mapped_rows_b, schema_a
        )

    st.markdown('<div class="security-banner">🔒 <b>Confidential Record Linkage Complete:</b> Matches were identified mathematically. Neither hospital exposed any non-matching patients or other private attributes to the other.</div>', unsafe_allow_html=True)

    # Metrics Overview
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Hospital A Records", len(enriched_a))
    m2.metric("Hospital B Records", len(enriched_b))
    m3.metric("Shared Matches Discovered", f"{shared_count} entities")
    m4.metric("Crypto Latency", f"{metrics.execution_time_ms:.1f} ms")

    st.markdown("---")
    st.markdown("### 3. Symmetrical Results & Export for Both Organizations")

    res_col_a, res_col_b = st.columns(2)

    # -----------------------------
    # HOSPITAL A RESULTS & EXPORT
    # -----------------------------
    with res_col_a:
        st.markdown('<div class="org-header-a">📁 Hospital A: Enriched Database</div>', unsafe_allow_html=True)
        st.caption("Hospital A's private data, tagged with match status against Hospital B.")
        st.dataframe(enriched_a, use_container_width=True)

        st.markdown("**Export Hospital A Data:**")

        # 1. Full database CSV
        full_csv_a = io.StringIO()
        writer_a = csv.DictWriter(full_csv_a, fieldnames=list(enriched_a[0].keys()))
        writer_a.writeheader()
        writer_a.writerows(enriched_a)

        st.download_button(
            label="📥 Download Full Database with 'matched' column (CSV)",
            data=full_csv_a.getvalue(),
            file_name="hospital_a_enriched_full.csv",
            mime="text/csv",
            key="dl_full_a",
        )

        # 2. Key-only CSV [key_column, matched]
        key_only_a = io.StringIO()
        key_writer_a = csv.DictWriter(key_only_a, fieldnames=[key_col_a, "matched"])
        key_writer_a.writeheader()
        for r in enriched_a:
            key_writer_a.writerow({key_col_a: r.get(key_col_a, ""), "matched": r["matched"]})

        st.download_button(
            label="🔑 Download Keys-Only with 'matched' column (CSV)",
            data=key_only_a.getvalue(),
            file_name="hospital_a_keys_only.csv",
            mime="text/csv",
            key="dl_key_a",
        )

    # -----------------------------
    # HOSPITAL B RESULTS & EXPORT
    # -----------------------------
    with res_col_b:
        st.markdown('<div class="org-header-b">📁 Hospital B: Enriched Database</div>', unsafe_allow_html=True)
        st.caption("Hospital B's private data, tagged with match status against Hospital A.")
        st.dataframe(enriched_b, use_container_width=True)

        st.markdown("**Export Hospital B Data:**")

        # 1. Full database CSV
        full_csv_b = io.StringIO()
        writer_b = csv.DictWriter(full_csv_b, fieldnames=list(enriched_b[0].keys()))
        writer_b.writeheader()
        writer_b.writerows(enriched_b)

        st.download_button(
            label="📥 Download Full Database with 'matched' column (CSV)",
            data=full_csv_b.getvalue(),
            file_name="hospital_b_enriched_full.csv",
            mime="text/csv",
            key="dl_full_b",
        )

        # 2. Key-only CSV [key_column, matched]
        key_only_b = io.StringIO()
        key_writer_b = csv.DictWriter(key_only_b, fieldnames=[key_col_b, "matched"])
        key_writer_b.writeheader()
        for r in enriched_b:
            key_writer_b.writerow({key_col_b: r.get(key_col_b, ""), "matched": r["matched"]})

        st.download_button(
            label="🔑 Download Keys-Only with 'matched' column (CSV)",
            data=key_only_b.getvalue(),
            file_name="hospital_b_keys_only.csv",
            mime="text/csv",
            key="dl_key_b",
        )
