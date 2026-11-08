from __future__ import annotations

"""
SecureMatch — Confidential Record Linkage Application (Streamlit).

A peer-to-peer data collaboration interface between two symmetric organizations
(e.g., Hospital A and Hospital B) to perform Private Set Intersection (PSI):
- Upload real databases (any CSV, any columns).
- Select / order columns to build custom composite match keys.
- Import and Export matching patterns (JSON) for seamless bilateral agreement.
- Symmetrical results: download full enriched database or key-only subset.
- Dedicated "Behind the Scenes" inspection panel detailing the cryptographic trace
  of random matched and unmatched records.
"""

import csv
import io
import json
import os
import random
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure project root is in Python module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import streamlit as st
from src.crypto.curve import Point, generate_private_scalar
from src.crypto.engine import blind_point, hash_and_blind
from src.crypto.hash_to_curve import hash_to_curve
from src.data_pipeline.normalizers import NORMALIZER_REGISTRY
from src.data_pipeline.schema import (
    FieldDefinition,
    Schema,
    create_cnpj_schema,
    create_cpf_schema,
    create_custom_schema,
    create_internal_id_schema,
    create_phone_region_schema,
)
from src.transport.memory_channel import ChannelMetrics

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
    .org-header-a { color: #1D4ED8; font-weight: 700; font-size: 1.25rem; margin-bottom: 8px; border-bottom: 2px solid #DBEAFE; padding-bottom: 6px; }
    .org-header-b { color: #7E22CE; font-weight: 700; font-size: 1.25rem; margin-bottom: 8px; border-bottom: 2px solid #F3E8FF; padding-bottom: 6px; }
    .step-badge { background-color: #F3F4F6; color: #374151; font-weight: 600; padding: 3px 8px; border-radius: 4px; font-size: 0.85rem; }
    .security-banner { background-color: #ECFDF5; border: 1px solid #10B981; color: #065F46; padding: 12px 16px; border-radius: 8px; margin-top: 15px; margin-bottom: 15px; }
    .cri-preview { background-color: #F9FAFB; border-left: 3px solid #3B82F6; font-family: monospace; font-size: 0.86rem; padding: 6px 10px; border-radius: 3px; word-break: break-all; }
    .trace-card { background-color: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 8px; padding: 14px; margin-bottom: 12px; }
    .match-tag { background-color: #DEF7EC; color: #03543F; font-weight: 700; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }
    .unmatch-tag { background-color: #FDE8E8; color: #9B1C1C; font-weight: 700; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }
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
# Pre-built Sample Data Generators
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
    "REG-902,23456789012,2026-02-14,Ressonância Magnética,Bradesco\n"  # Match
    "REG-903,12345678901,2026-03-01,Consulta Cardiologia,SulAmerica\n" # Match
    "REG-904,34567890123,2026-03-15,Espirometria,Amil\n"             # Match
    "REG-905,888.777.666-55,2026-04-20,Tomografia,Particular\n"
    "REG-906,56789012345,2026-05-12,Ecocardiograma,Unimed\n"          # Match
)


def load_csv_data(raw_text: str) -> Tuple[List[Dict[str, str]], List[str]]:
    """Parses raw CSV string into list of row dicts and headers."""
    f = io.StringIO(raw_text.strip())
    reader = csv.DictReader(f)
    rows = list(reader)
    headers = reader.fieldnames if reader.fieldnames else []
    return rows, list(headers)


def render_dataframe(data: Any) -> None:
    """Renders dataframe with stretch width, compatible with modern and legacy Streamlit."""
    try:
        st.dataframe(data, width="stretch")
    except (TypeError, ValueError):
        st.dataframe(data, use_container_width=True)


# ---------------------------------------------------------------------------
# Navigation Tabs
# ---------------------------------------------------------------------------
main_tab_linkage, main_tab_behind = st.tabs([
    "🤝 Peer-to-Peer Record Linkage Console",
    "🔬 Behind the Scenes: Cryptographic Inspection",
])


# ===========================================================================
# TAB 1: PEER-TO-PEER RECORD LINKAGE CONSOLE
# ===========================================================================
with main_tab_linkage:
    st.markdown("### 1. Peer Agreement: Primary Key Pattern & Custom Key Builder")
    st.caption(
        "Both organizations must agree on the matching pattern. You can choose a pre-built standard "
        "(CPF, CNPJ) or build a **Custom Composite Key** by selecting and ordering columns. "
        "You can also **Export or Import** agreed patterns as JSON."
    )

    col_key_type, col_pattern_io = st.columns([2, 1])

    with col_key_type:
        key_type = st.selectbox(
            "Agreed Matching Key Format:",
            [
                "Brazilian CPF (Individual Tax ID — 11 digits)",
                "Brazilian CNPJ (Corporate Registry — Numeric or Modern Alphanumeric)",
                "Composite: Phone Number + State / Region (E.164 + UF)",
                "Custom Composite Key (User-Defined Multi-Column)",
            ],
            index=0,
            key="key_type_selector",
        )

    # -----------------------------
    # Pattern Import / Export Panel
    # -----------------------------
    with col_pattern_io:
        st.write("")
        st.write("")
        exp_pattern = st.expander("📁 Import / Export Matching Pattern (JSON)")
        with exp_pattern:
            imported_file = st.file_uploader("Import Pattern (.json)", type=["json"], key="import_pattern_file")
            if imported_file:
                try:
                    pattern_data = json.load(imported_file)
                    st.session_state["imported_pattern"] = pattern_data
                    st.success(f"Loaded pattern: **{pattern_data.get('schema_id', 'custom')}**")
                except Exception as e:
                    st.error(f"Failed to parse JSON: {e}")

            if st.button("🔄 Reset to Default Hospital Cohorts"):
                st.session_state["raw_csv_a"] = DEFAULT_HOSPITAL_A_CSV
                st.session_state["raw_csv_b"] = DEFAULT_HOSPITAL_B_CSV
                st.session_state.pop("imported_pattern", None)
                st.session_state.pop("last_psi_execution", None)
                st.experimental_rerun() if hasattr(st, "experimental_rerun") else st.rerun()

    st.markdown("---")

    # ---------------------------------------------------------------------------
    # Symmetric Peer Configuration: Hospital A vs. Hospital B
    # ---------------------------------------------------------------------------
    col_party_a, col_party_b = st.columns(2)

    # -----------------------------
    # HOSPITAL A
    # -----------------------------
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
        st.caption(f"Loaded **{len(rows_a)}** records &bull; Available columns: `{', '.join(headers_a)}`")

        with st.expander("👁️ Preview Hospital A Data", expanded=False):
            render_dataframe(rows_a[:5])

        st.markdown('<span class="step-badge">Step 2</span> **Configure / Order Matching Key**', unsafe_allow_html=True)

        if not headers_a:
            st.warning("Please upload a valid CSV with headers.")
            mapped_rows_a = []
            schema_a = create_cpf_schema()
            key_col_a = "cpf"
        else:
            # Handle Predefined vs Custom Multi-Column Key
            if "Custom Composite" in key_type or "imported_pattern" in st.session_state:
                st.markdown("**Custom Column Selection & Ordering:**")
                imported_p = st.session_state.get("imported_pattern", {})
                default_schema_id = imported_p.get("schema_id", "custom_composite_v1")
                schema_id_a = st.text_input("Pattern Name / ID:", value=default_schema_id, key="schema_id_a")

                # Column selector
                selected_cols_a = st.multiselect(
                    "Select which columns from Hospital A form the key (in order):",
                    headers_a,
                    default=[headers_a[1]] if len(headers_a) > 1 else [headers_a[0]],
                    key="sel_cols_a",
                )

                field_specs_a = []
                for c_idx, col_name in enumerate(selected_cols_a):
                    c1, c2 = st.columns([1, 1])
                    field_name = c1.text_input(f"Agreed Field Name for '{col_name}':", value=col_name.lower(), key=f"fn_a_{c_idx}")
                    normalizer_name = c2.selectbox(
                        f"Normalizer for '{col_name}':",
                        list(NORMALIZER_REGISTRY.keys()),
                        index=list(NORMALIZER_REGISTRY.keys()).index("cpf") if "cpf" in col_name.lower() else 0,
                        key=f"norm_a_{c_idx}",
                    )
                    field_specs_a.append({"name": field_name, "normalizer": normalizer_name, "source_col": col_name})

                schema_a = create_custom_schema(schema_id_a, field_specs_a)
                mapped_rows_a = [{f["name"]: r.get(f["source_col"], "") for f in field_specs_a} for r in rows_a]
                key_col_a = " + ".join(selected_cols_a) if selected_cols_a else "None"

                # Export Pattern Button
                pattern_json_a = json.dumps(
                    {
                        "schema_id": schema_a.schema_id,
                        "fields": [{"name": f["name"], "normalizer": f["normalizer"]} for f in field_specs_a],
                    },
                    indent=2,
                )
                st.download_button(
                    label="📤 Export Matching Pattern as JSON",
                    data=pattern_json_a,
                    file_name=f"{schema_a.schema_id}.json",
                    mime="application/json",
                    key="dl_pattern_a",
                )

            elif "CPF" in key_type:
                def_idx_a = headers_a.index("cpf_titular") if "cpf_titular" in headers_a else 0
                col_a = st.selectbox("Select column containing CPF:", headers_a, index=def_idx_a, key="col_map_a")
                schema_a = create_cpf_schema()
                mapped_rows_a = [{"cpf": r[col_a]} for r in rows_a]
                key_col_a = col_a

            elif "CNPJ" in key_type:
                col_a = st.selectbox("Select column containing CNPJ:", headers_a, index=0, key="col_map_a")
                schema_a = create_cnpj_schema(strict=False)
                mapped_rows_a = [{"cnpj": r[col_a]} for r in rows_a]
                key_col_a = col_a

            else:  # Phone + Region
                c1, c2 = st.columns(2)
                col_phone_a = c1.selectbox("Phone column:", headers_a, index=0, key="col_phone_a")
                col_reg_a = c2.selectbox("Region/UF column:", headers_a, index=min(1, len(headers_a) - 1), key="col_reg_a")
                schema_a = create_phone_region_schema()
                mapped_rows_a = [{"phone": r[col_phone_a], "region": r[col_reg_a]} for r in rows_a]
                key_col_a = f"{col_phone_a} + {col_reg_a}"

            # Live Normalization Preview for Hospital A
            if mapped_rows_a:
                sample_cri_a = schema_a.serialize_record(mapped_rows_a[0]).decode("utf-8")
                st.markdown(
                    f"**Canonical Format Preview (CRI):**<div class='cri-preview'>{sample_cri_a}</div>",
                    unsafe_allow_html=True,
                )

    # -----------------------------
    # HOSPITAL B
    # -----------------------------
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
        st.caption(f"Loaded **{len(rows_b)}** records &bull; Available columns: `{', '.join(headers_b)}`")

        with st.expander("👁️ Preview Hospital B Data", expanded=False):
            render_dataframe(rows_b[:5])

        st.markdown('<span class="step-badge">Step 2</span> **Configure / Order Matching Key**', unsafe_allow_html=True)

        if not headers_b:
            st.warning("Please upload a valid CSV with headers.")
            mapped_rows_b = []
            schema_b = create_cpf_schema()
            key_col_b = "cpf"
        else:
            if "Custom Composite" in key_type or "imported_pattern" in st.session_state:
                st.markdown("**Custom Column Selection & Ordering:**")
                imported_p = st.session_state.get("imported_pattern", {})
                default_schema_id_b = imported_p.get("schema_id", "custom_composite_v1")
                schema_id_b = st.text_input("Pattern Name / ID:", value=default_schema_id_b, key="schema_id_b")

                selected_cols_b = st.multiselect(
                    "Select which columns from Hospital B form the key (in order):",
                    headers_b,
                    default=[headers_b[1]] if len(headers_b) > 1 else [headers_b[0]],
                    key="sel_cols_b",
                )

                field_specs_b = []
                for c_idx, col_name in enumerate(selected_cols_b):
                    c1, c2 = st.columns([1, 1])
                    # If imported pattern has field names, suggest them
                    suggested_name = col_name.lower()
                    if imported_p and "fields" in imported_p and c_idx < len(imported_p["fields"]):
                        suggested_name = imported_p["fields"][c_idx]["name"]

                    field_name = c1.text_input(f"Agreed Field Name for '{col_name}':", value=suggested_name, key=f"fn_b_{c_idx}")
                    normalizer_name = c2.selectbox(
                        f"Normalizer for '{col_name}':",
                        list(NORMALIZER_REGISTRY.keys()),
                        index=list(NORMALIZER_REGISTRY.keys()).index("cpf") if "cpf" in col_name.lower() else 0,
                        key=f"norm_b_{c_idx}",
                    )
                    field_specs_b.append({"name": field_name, "normalizer": normalizer_name, "source_col": col_name})

                schema_b = create_custom_schema(schema_id_b, field_specs_b)
                mapped_rows_b = [{f["name"]: r.get(f["source_col"], "") for f in field_specs_b} for r in rows_b]
                key_col_b = " + ".join(selected_cols_b) if selected_cols_b else "None"

                # Export Pattern Button
                pattern_json_b = json.dumps(
                    {
                        "schema_id": schema_b.schema_id,
                        "fields": [{"name": f["name"], "normalizer": f["normalizer"]} for f in field_specs_b],
                    },
                    indent=2,
                )
                st.download_button(
                    label="📤 Export Matching Pattern as JSON",
                    data=pattern_json_b,
                    file_name=f"{schema_b.schema_id}.json",
                    mime="application/json",
                    key="dl_pattern_b",
                )

            elif "CPF" in key_type:
                def_idx_b = headers_b.index("doc_cpf") if "doc_cpf" in headers_b else 0
                col_b = st.selectbox("Select column containing CPF:", headers_b, index=def_idx_b, key="col_map_b")
                schema_b = create_cpf_schema()
                mapped_rows_b = [{"cpf": r[col_b]} for r in rows_b]
                key_col_b = col_b

            elif "CNPJ" in key_type:
                col_b = st.selectbox("Select column containing CNPJ:", headers_b, index=0, key="col_map_b")
                schema_b = create_cnpj_schema(strict=False)
                mapped_rows_b = [{"cnpj": r[col_b]} for r in rows_b]
                key_col_b = col_b

            else:  # Phone + Region
                c1, c2 = st.columns(2)
                col_phone_b = c1.selectbox("Phone column:", headers_b, index=0, key="col_phone_b")
                col_reg_b = c2.selectbox("Region/UF column:", headers_b, index=min(1, len(headers_b) - 1), key="col_reg_b")
                schema_b = create_phone_region_schema()
                mapped_rows_b = [{"phone": r[col_phone_b], "region": r[col_reg_b]} for r in rows_b]
                key_col_b = f"{col_phone_b} + {col_reg_b}"

            # Live Normalization Preview for Hospital B
            if mapped_rows_b:
                sample_cri_b = schema_b.serialize_record(mapped_rows_b[0]).decode("utf-8")
                st.markdown(
                    f"**Canonical Format Preview (CRI):**<div class='cri-preview'>{sample_cri_b}</div>",
                    unsafe_allow_html=True,
                )

    st.markdown("---")

    # ---------------------------------------------------------------------------
    # Step 3: Peer-to-Peer Execution & Matching
    # ---------------------------------------------------------------------------
    st.markdown("### 2. Confidential Linkage Execution")

    fp_a = schema_a.fingerprint()
    fp_b = schema_b.fingerprint()

    if fp_a != fp_b:
        st.error(
            f"❌ Handshake Mismatch: Both organizations must agree on the same matching key format and field names. "
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
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int, ChannelMetrics, Dict[str, Any]]:
        """
        Executes symmetrical Commutative ECDH-PSI:
        Both Hospital A and Hospital B receive their own database with `matched: YES / NO`.
        Zero non-matching rows or plaintext records are revealed to the other party.
        Also returns detailed intermediate cryptographic trace for the Behind the Scenes tab.
        """
        t_start = time.perf_counter()

        scalar_a = generate_private_scalar()
        scalar_b = generate_private_scalar()

        # 1. Map to CRI bytes
        cri_a = [schema.serialize_record(r) for r in norm_a]
        cri_b = [schema.serialize_record(r) for r in norm_b]

        # 2. Map to curve points and blind locally
        t_c1 = time.perf_counter()
        pt_a = [hash_to_curve(x) for x in cri_a]
        blinded_a = [blind_point(scalar_a, p) for p in pt_a]
        crypto_time_a = (time.perf_counter() - t_c1) * 1000

        t_s1 = time.perf_counter()
        pt_b = [hash_to_curve(y) for y in cri_b]
        blinded_b = [blind_point(scalar_b, p) for p in pt_b]
        crypto_time_b = (time.perf_counter() - t_s1) * 1000

        # 3. Exchange & Double-blind
        doubly_a = [blind_point(scalar_b, p_a) for p_a in blinded_a]
        doubly_b = [blind_point(scalar_a, p_b) for p_b in blinded_b]

        # 4. Resolve matches on both sides
        set_doubly_b: Set[bytes] = {p.to_compressed_bytes() for p in doubly_b}
        set_doubly_a: Set[bytes] = {p.to_compressed_bytes() for p in doubly_a}

        enriched_a: List[Dict[str, Any]] = []
        match_count = 0
        matched_indices_a: List[int] = []
        unmatched_indices_a: List[int] = []

        for idx, row in enumerate(rows_a_raw):
            row_copy = dict(row)
            is_match = doubly_a[idx].to_compressed_bytes() in set_doubly_b
            row_copy["matched"] = "YES" if is_match else "NO"
            enriched_a.append(row_copy)
            if is_match:
                match_count += 1
                matched_indices_a.append(idx)
            else:
                unmatched_indices_a.append(idx)

        enriched_b: List[Dict[str, Any]] = []
        matched_indices_b: List[int] = []
        unmatched_indices_b: List[int] = []

        for idx, row in enumerate(rows_b_raw):
            row_copy = dict(row)
            is_match = doubly_b[idx].to_compressed_bytes() in set_doubly_a
            row_copy["matched"] = "YES" if is_match else "NO"
            enriched_b.append(row_copy)
            if is_match:
                matched_indices_b.append(idx)
            else:
                unmatched_indices_b.append(idx)

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

        # Store trace for behind-the-scenes tab
        trace_data = {
            "scalar_a": scalar_a,
            "scalar_b": scalar_b,
            "rows_a": rows_a_raw,
            "rows_b": rows_b_raw,
            "cri_a": cri_a,
            "cri_b": cri_b,
            "pt_a": pt_a,
            "pt_b": pt_b,
            "blinded_a": blinded_a,
            "blinded_b": blinded_b,
            "doubly_a": doubly_a,
            "doubly_b": doubly_b,
            "matched_indices_a": matched_indices_a,
            "unmatched_indices_a": unmatched_indices_a,
            "matched_indices_b": matched_indices_b,
            "unmatched_indices_b": unmatched_indices_b,
            "key_col_a": key_col_a,
            "key_col_b": key_col_b,
        }

        return enriched_a, enriched_b, match_count, metrics, trace_data


    if btn_run:
        with st.spinner("Executing Commutative Diffie-Hellman Protocol over secp256k1..."):
            enriched_a, enriched_b, shared_count, metrics, trace = execute_mutual_psi(
                rows_a, rows_b, mapped_rows_a, mapped_rows_b, schema_a
            )
            st.session_state["last_psi_execution"] = {
                "enriched_a": enriched_a,
                "enriched_b": enriched_b,
                "shared_count": shared_count,
                "metrics": metrics,
                "trace": trace,
            }

    # If results exist in session
    if "last_psi_execution" in st.session_state:
        exec_data = st.session_state["last_psi_execution"]
        enriched_a = exec_data["enriched_a"]
        enriched_b = exec_data["enriched_b"]
        shared_count = exec_data["shared_count"]
        metrics = exec_data["metrics"]

        st.markdown('<div class="security-banner">🔒 <b>Confidential Record Linkage Complete:</b> Matches were identified mathematically. Neither hospital exposed any non-matching patients or other private attributes to the other.</div>', unsafe_allow_html=True)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Hospital A Records", len(enriched_a))
        m2.metric("Hospital B Records", len(enriched_b))
        m3.metric("Shared Matches Discovered", f"{shared_count} entities")
        m4.metric("Crypto Latency", f"{metrics.execution_time_ms:.1f} ms")

        st.markdown("---")
        st.markdown("### 3. Symmetrical Results & Export Options")

        res_col_a, res_col_b = st.columns(2)

        # -----------------------------
        # HOSPITAL A RESULTS & EXPORT
        # -----------------------------
        with res_col_a:
            st.markdown('<div class="org-header-a">📁 Hospital A: Enriched Database</div>', unsafe_allow_html=True)
            render_dataframe(enriched_a)

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
            render_dataframe(enriched_b)

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


# ===========================================================================
# TAB 2: BEHIND THE SCENES — CRYPTOGRAPHIC INSPECTION
# ===========================================================================
with main_tab_behind:
    st.markdown("### 🔬 Behind the Scenes: Cryptographic Execution Trace")
    st.markdown(
        "This panel demonstrates exactly what happened to **random records** during the protocol, "
        "comparing a **Matched Record** against an **Unmatched Record** to prove why the math works "
        "and why privacy is strictly preserved."
    )

    if "last_psi_execution" not in st.session_state:
        st.info("ℹ️ Please run a record linkage in the first tab to view the live cryptographic trace of your actual records.")
    else:
        trace = st.session_state["last_psi_execution"]["trace"]

        col_trace_matched, col_trace_unmatched = st.columns(2)

        # -------------------------------------------------------------------
        # CASE 1: TRACE OF A RANDOM MATCHED RECORD
        # -------------------------------------------------------------------
        with col_trace_matched:
            st.markdown('<div class="trace-card">', unsafe_allow_html=True)
            st.markdown('<h4>Case 1: Trace of a <span class="match-tag">MATCHED RECORD</span></h4>', unsafe_allow_html=True)

            if not trace["matched_indices_a"]:
                st.warning("No matched records occurred in the last run to trace.")
            else:
                # Pick a sample matched index
                idx_a = trace["matched_indices_a"][0]
                # Find corresponding match index in B
                matched_target = trace["doubly_a"][idx_a].to_compressed_bytes()
                idx_b = next(
                    i for i, pt in enumerate(trace["doubly_b"]) if pt.to_compressed_bytes() == matched_target
                )

                st.markdown("**1. Raw Input Records:**")
                st.json({
                    "Hospital A Input": trace["rows_a"][idx_a],
                    "Hospital B Input": trace["rows_b"][idx_b],
                })

                st.markdown("**2. Canonical Record Identifiers (CRI):**")
                st.code(
                    f"Hospital A CRI: {trace['cri_a'][idx_a].decode('utf-8')}\n"
                    f"Hospital B CRI: {trace['cri_b'][idx_b].decode('utf-8')}\n"
                    f"Canonical bytes identical? {trace['cri_a'][idx_a] == trace['cri_b'][idx_b]}",
                    language="text",
                )

                st.markdown("**3. Mapping to secp256k1 Curve Point $P = H(x)$:**")
                st.code(
                    f"Point x: {hex(trace['pt_a'][idx_a].x)[:32]}...\n"
                    f"Point y: {hex(trace['pt_a'][idx_a].y)[:32]}...",
                    language="text",
                )

                st.markdown("**4. Local Blinding:**")
                st.code(
                    f"Hospital A computes P_A = a * P:\n  {trace['blinded_a'][idx_a].to_compressed_bytes().hex()[:32]}...\n"
                    f"Hospital B computes P_B = b * P:\n  {trace['blinded_b'][idx_b].to_compressed_bytes().hex()[:32]}...",
                    language="text",
                )

                st.markdown("**5. The Commutative Result:**")
                p_ba_hex = trace["doubly_a"][idx_a].to_compressed_bytes().hex()
                p_ab_hex = trace["doubly_b"][idx_b].to_compressed_bytes().hex()
                st.code(
                    f"Hospital B double-blinds P_A with key b -> P_BA:\n  {p_ba_hex}\n"
                    f"Hospital A double-blinds P_B with key a -> P_AB:\n  {p_ab_hex}\n"
                    f"Do the 33-byte points match? {p_ba_hex == p_ab_hex} ✅",
                    language="text",
                )
                st.caption(
                    "Mathematical Proof: a * (b * P) == b * (a * P). Both hospitals agree this record matched "
                    "without either party revealing their private keys or other row attributes!"
                )
            st.markdown('</div>', unsafe_allow_html=True)

        # -------------------------------------------------------------------
        # CASE 2: TRACE OF A RANDOM UNMATCHED RECORD
        # -------------------------------------------------------------------
        with col_trace_unmatched:
            st.markdown('<div class="trace-card">', unsafe_allow_html=True)
            st.markdown('<h4>Case 2: Trace of an <span class="unmatch-tag">UNMATCHED RECORD</span></h4>', unsafe_allow_html=True)

            if not trace["unmatched_indices_a"]:
                st.info("No unmatched records in Hospital A for the last run.")
            else:
                idx_un_a = trace["unmatched_indices_a"][0]
                idx_un_b = trace["unmatched_indices_b"][0] if trace["unmatched_indices_b"] else 0

                st.markdown("**1. Raw Input Records (Different Patients):**")
                st.json({
                    "Hospital A Record": trace["rows_a"][idx_un_a],
                    "Hospital B Record": trace["rows_b"][idx_un_b],
                })

                st.markdown("**2. Canonical Record Identifiers (CRI):**")
                st.code(
                    f"Hospital A CRI: {trace['cri_a'][idx_un_a].decode('utf-8')}\n"
                    f"Hospital B CRI: {trace['cri_b'][idx_un_b].decode('utf-8')}\n"
                    f"Canonical bytes identical? False",
                    language="text",
                )

                st.markdown("**3. Mapping to secp256k1 Curve Points:**")
                st.code(
                    f"Point P_A = H(x_A):\n  x = {hex(trace['pt_a'][idx_un_a].x)[:30]}...\n"
                    f"Point P_B = H(y_B):\n  x = {hex(trace['pt_b'][idx_un_b].x)[:30]}...",
                    language="text",
                )

                st.markdown("**4. Local Blinding:**")
                st.code(
                    f"Hospital A computes P_A = a * H(x_A):\n  {trace['blinded_a'][idx_un_a].to_compressed_bytes().hex()[:32]}...\n"
                    f"Hospital B computes P_B = b * H(y_B):\n  {trace['blinded_b'][idx_un_b].to_compressed_bytes().hex()[:32]}...",
                    language="text",
                )

                st.markdown("**5. The Commutative Result:**")
                p_ba_un = trace["doubly_a"][idx_un_a].to_compressed_bytes().hex()
                p_ab_un = trace["doubly_b"][idx_un_b].to_compressed_bytes().hex()
                st.code(
                    f"Hospital B double-blinds P_A with key b -> P_BA:\n  {p_ba_un}\n"
                    f"Hospital A double-blinds P_B with key a -> P_AB:\n  {p_ab_un}\n"
                    f"Do the 33-byte points match? {p_ba_un == p_ab_un} ❌ (NO MATCH)",
                    language="text",
                )
                st.caption(
                    "Zero-Knowledge Protection: The resulting points are pseudorandom. Under the CDH assumption, "
                    "neither party can invert or determine what patient identity produced the unmatched point!"
                )
            st.markdown('</div>', unsafe_allow_html=True)
