from __future__ import annotations

"""
SecureMatch — Confidential Record Linkage Application (Streamlit).

A peer-to-peer data collaboration interface between two symmetric organizations
(e.g., Hospital A and Hospital B) to perform Private Set Intersection (PSI):
1. Peer-to-Peer Linkage Console:
   - Upload any CSV or generate test datasets (CPF, CNPJ, Phone+Region, Custom 2-4 cols).
   - Custom composite key builder with explicit column ordering.
   - Import and Export matching patterns (JSON) for seamless bilateral agreement.
   - Symmetrical results: download full enriched database or key-only subset.
2. Behind the Scenes Cryptographic Trace:
   - Random record selector / inspection of matched and unmatched records.
   - Step-by-step cryptographic transformations (Raw -> CRI -> Hash-to-Curve -> Blinding -> Commutative match).
3. Empirical Benchmark & Security Analytics:
   - Executive metrics from 500,000-record scaling and 3-hour secp256k1 exhaustion attack (1.411 billion attempts).
   - High-resolution evaluation figures and interactive live SHA-256 vulnerability cracker.
"""

import csv
import io
import json
import math
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
    create_phone_region_schema,
)
from src.transport.memory_channel import ChannelMetrics
from benchmark.generate_synthetic import generate_dataset_pair
from benchmark.security_cracker import crack_naive_sha256_cpf, crack_naive_sha256_cnpj

st.set_page_config(
    page_title="SecureMatch — Confidential Record Linkage",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom Styling (Theme-Adaptive for Light & Dark Mode)
st.markdown("""
<style>
    .hero-banner {
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.14) 0%, rgba(168, 85, 247, 0.12) 100%);
        border: 1px solid rgba(128, 128, 128, 0.25);
        border-left: 5px solid #3B82F6;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 1.4rem;
    }
    .hero-title {
        font-size: 2.25rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: var(--text-color);
        margin: 0 0 6px 0;
        line-height: 1.15;
    }
    .hero-accent {
        background: linear-gradient(90deg, #60A5FA, #C084FC);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .hero-subtitle {
        font-size: 1.02rem;
        color: var(--text-color);
        opacity: 0.85;
        margin: 0 0 12px 0;
    }
    .hero-pills {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
    }
    .hero-pill {
        background-color: var(--secondary-background-color);
        color: var(--text-color);
        border: 1px solid rgba(128, 128, 128, 0.28);
        border-radius: 999px;
        padding: 4px 12px;
        font-size: 0.82rem;
        font-weight: 600;
    }
    .org-header-a { color: #60A5FA; font-weight: 700; font-size: 1.25rem; margin-bottom: 8px; border-bottom: 2px solid rgba(96, 165, 250, 0.35); padding-bottom: 6px; }
    .org-header-b { color: #C084FC; font-weight: 700; font-size: 1.25rem; margin-bottom: 8px; border-bottom: 2px solid rgba(192, 132, 252, 0.35); padding-bottom: 6px; }
    .step-badge { background-color: var(--secondary-background-color); color: var(--text-color); border: 1px solid rgba(128, 128, 128, 0.3); font-weight: 600; padding: 3px 8px; border-radius: 4px; font-size: 0.85rem; }
    .security-banner { background-color: rgba(16, 185, 129, 0.15); border: 1px solid #10B981; color: var(--text-color); padding: 12px 16px; border-radius: 8px; margin-top: 15px; margin-bottom: 15px; }
    .cri-preview { background-color: var(--secondary-background-color); color: var(--text-color); border-left: 3px solid #3B82F6; font-family: monospace; font-size: 0.86rem; padding: 6px 10px; border-radius: 3px; word-break: break-all; }
    .trace-card { background-color: var(--secondary-background-color); color: var(--text-color); border: 1px solid rgba(128, 128, 128, 0.25); border-radius: 8px; padding: 16px; margin-bottom: 14px; }
    .match-tag { background-color: rgba(16, 185, 129, 0.2); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.4); font-weight: 700; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }
    .unmatch-tag { background-color: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.4); font-weight: 700; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }
    .metric-card { background-color: var(--secondary-background-color); color: var(--text-color); border: 1px solid rgba(128, 128, 128, 0.25); border-radius: 8px; padding: 14px 12px; text-align: center; }
    .metric-card h4 { margin: 0 0 6px 0; color: #60A5FA; font-size: 1.45rem; }
    .metric-card p { margin: 0; font-size: 0.9rem; opacity: 0.85; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero-banner">
    <div class="hero-title">🏥 <span class="hero-accent">SecureMatch</span> &mdash; Confidential Record Linkage</div>
    <div class="hero-subtitle">
        Bilateral Privacy-Preserving Entity Reconciliation between independent organizations without exposing non-matching records.
    </div>
    <div class="hero-pills">
        <span class="hero-pill">🔒 Commutative ECDH-PSI</span>
        <span class="hero-pill">📐 secp256k1 Curve</span>
        <span class="hero-pill">🧬 Canonical Normalization</span>
        <span class="hero-pill">🎓 DCC / ICEx / UFMG</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Default Hospital Sample Data
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


def dict_list_to_csv(data: List[Dict[str, Any]]) -> str:
    """Converts a list of dicts to a CSV string."""
    if not data:
        return ""
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(data[0].keys()))
    writer.writeheader()
    writer.writerows(data)
    return out.getvalue()


def render_dataframe(data: Any) -> None:
    """Renders dataframe with stretch width, compatible with modern and legacy Streamlit."""
    try:
        st.dataframe(data, width="stretch")
    except (TypeError, ValueError):
        st.dataframe(data, use_container_width=True)


# ---------------------------------------------------------------------------
# Navigation Tabs
# ---------------------------------------------------------------------------
main_tab_linkage, main_tab_behind, main_tab_analytics = st.tabs([
    "🤝 Peer-to-Peer Record Linkage Console",
    "🔬 Behind the Scenes: Cryptographic Inspection",
    "📊 Empirical Benchmark & Security Analytics",
])


# ===========================================================================
# TAB 1: PEER-TO-PEER RECORD LINKAGE CONSOLE
# ===========================================================================
with main_tab_linkage:
    # -----------------------------------------------------------------------
    # Section A: Synthetic Test Database Generator Expander
    # -----------------------------------------------------------------------
    with st.expander("🎲 Synthetic Test Database Generator (Create Test Pairs with 1 Click)", expanded=False):
        st.caption(
            "Quickly synthesize test database pairs with exact controllable overlaps, "
            "realistic dirty-data variations, and diverse primary key structures."
        )

        g_col1, g_col2, g_col3 = st.columns(3)
        gen_mode_choice = g_col1.radio(
            "Overlap Mode:",
            ["With Match (Controllable Shared Records)", "No Match (0% Disjoint Pairs)"],
            index=0,
            key="gen_mode_choice",
        )
        gen_key_choice = g_col2.selectbox(
            "Key Type:",
            [
                "CPF (Brazilian Individual Tax ID)",
                "CNPJ (Numeric & Alphanumeric Corporate ID)",
                "Phone + Region (Composite E.164 + UF)",
                "Custom Composite (Random 2 to 4 Columns)",
            ],
            index=0,
            key="gen_key_choice",
        )
        gen_size = g_col3.slider(
            "Records per Hospital:",
            min_value=5,
            max_value=200,
            value=15,
            step=5,
            key="gen_size_slider",
        )

        gen_match_count = None
        if "With Match" in gen_mode_choice:
            gen_match_count = st.slider(
                "Number of Shared Matches:",
                min_value=1,
                max_value=gen_size,
                value=min(6, gen_size),
                key="gen_match_count_slider",
            )

        btn_generate = st.button("🚀 Generate & Load into Workspaces", type="primary", key="btn_gen_load")

        if btn_generate:
            mode_kw = "with_match" if "With Match" in gen_mode_choice else "no_match"
            if "CPF" in gen_key_choice:
                key_kw = "cpf"
                target_key_type = "Brazilian CPF (Individual Tax ID — 11 digits)"
            elif "CNPJ" in gen_key_choice:
                key_kw = "cnpj"
                target_key_type = "Brazilian CNPJ (Corporate Registry — Numeric or Modern Alphanumeric)"
            elif "Phone" in gen_key_choice:
                key_kw = "phone_region"
                target_key_type = "Composite: Phone Number + State / Region (E.164 + UF)"
            else:
                key_kw = "custom_random"
                target_key_type = "Custom Composite Key (User-Defined Multi-Column)"

            data_a, data_b, meta = generate_dataset_pair(
                key_type=key_kw,
                n_a=gen_size,
                n_b=gen_size,
                match_mode=mode_kw,
                match_count=gen_match_count,
            )

            st.session_state["raw_csv_a"] = dict_list_to_csv(data_a)
            st.session_state["raw_csv_b"] = dict_list_to_csv(data_b)
            st.session_state["key_type_override"] = target_key_type
            st.session_state["key_type_selector"] = target_key_type
            for stale_key in [
                "last_psi_execution", "col_map_a", "col_map_b",
                "col_phone_a", "col_reg_a", "col_phone_b", "col_reg_b",
                "sel_cols_a", "sel_cols_b", "selected_match_idx", "selected_unmatch_idx",
            ]:
                st.session_state.pop(stale_key, None)

            if key_kw == "custom_random":
                st.session_state["imported_pattern"] = {
                    "schema_id": meta["schema_id"],
                    "fields": meta["chosen_fields"],
                    "key_columns_a": meta["key_columns_a"],
                    "key_columns_b": meta["key_columns_b"],
                }
            else:
                st.session_state.pop("imported_pattern", None)

            st.success(
                f"Generated **{len(data_a)}** records for Hospital A and **{len(data_b)}** records for Hospital B. "
                f"Expected shared overlap: **{meta.get('expected_matches', 0)}** entities."
            )
            st.rerun()

    st.markdown("---")

    # -----------------------------------------------------------------------
    # Section B: Primary Key Pattern Agreement & Custom Key Builder
    # -----------------------------------------------------------------------
    st.markdown("### 1. Peer Agreement: Primary Key Pattern & Custom Key Builder")
    st.caption(
        "Both organizations must agree on the matching pattern. You can choose a pre-built standard "
        "(CPF, CNPJ, Phone+Region) or build a **Custom Composite Key** by selecting and ordering columns. "
        "You can also **Export or Import** agreed patterns as JSON."
    )

    col_key_type, col_pattern_io = st.columns([2, 1])

    available_key_options = [
        "Brazilian CPF (Individual Tax ID — 11 digits)",
        "Brazilian CNPJ (Corporate Registry — Numeric or Modern Alphanumeric)",
        "Composite: Phone Number + State / Region (E.164 + UF)",
        "Custom Composite Key (User-Defined Multi-Column)",
    ]

    # Handle generator override if present
    default_key_idx = 0
    if "key_type_override" in st.session_state and st.session_state["key_type_override"] in available_key_options:
        default_key_idx = available_key_options.index(st.session_state["key_type_override"])

    with col_key_type:
        key_type = st.selectbox(
            "Agreed Matching Key Format:",
            available_key_options,
            index=default_key_idx,
            key="key_type_selector",
        )

    # Pattern Import / Export Panel
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
                    st.session_state["key_type_override"] = "Custom Composite Key (User-Defined Multi-Column)"
                    st.success(f"Loaded pattern: **{pattern_data.get('schema_id', 'custom')}**")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to parse JSON: {e}")

            if st.button("🔄 Reset to Default Hospital Cohorts"):
                st.session_state["raw_csv_a"] = DEFAULT_HOSPITAL_A_CSV
                st.session_state["raw_csv_b"] = DEFAULT_HOSPITAL_B_CSV
                st.session_state.pop("imported_pattern", None)
                st.session_state.pop("key_type_override", None)
                st.session_state.pop("last_psi_execution", None)
                st.rerun()

    st.markdown("---")

    # ---------------------------------------------------------------------------
    # Section C: Symmetric Peer Configuration: Hospital A vs. Hospital B
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
            st.session_state["raw_csv_a"] = raw_content_a
        else:
            raw_content_a = st.session_state.get("raw_csv_a", DEFAULT_HOSPITAL_A_CSV)

        rows_a, headers_a = load_csv_data(raw_content_a)
        st.caption(f"Loaded **{len(rows_a)}** records &bull; Columns: `{', '.join(headers_a)}`")

        with st.expander("👁️ Preview Hospital A Data", expanded=False):
            render_dataframe(rows_a[:5])

        st.markdown('<span class="step-badge">Step 2</span> **Configure / Order Matching Key**', unsafe_allow_html=True)

        if not headers_a:
            st.warning("Please upload a valid CSV with headers.")
            mapped_rows_a = []
            schema_a = create_cpf_schema()
            key_col_a = "cpf"
        else:
            # 1. Custom Composite Key Builder
            if "Custom Composite" in key_type or "imported_pattern" in st.session_state:
                st.markdown("**Custom Column Selection & Ordering:**")
                imported_p = st.session_state.get("imported_pattern", {})
                default_schema_id_a = imported_p.get("schema_id", "custom_composite_v1")
                schema_id_a = st.text_input("Pattern Name / ID:", value=default_schema_id_a, key="schema_id_a")

                # Suggest default columns from imported pattern or first 2 headers
                default_cols_a = [headers_a[0]]
                if "key_columns_a" in imported_p:
                    default_cols_a = [c for c in imported_p["key_columns_a"] if c in headers_a]
                elif len(headers_a) > 1:
                    default_cols_a = [headers_a[1]]

                selected_cols_a = st.multiselect(
                    "Select columns from Hospital A that form the composite key (order matters):",
                    headers_a,
                    default=default_cols_a,
                    key="sel_cols_a",
                )

                st.caption(f"📌 Key Sequence: **{' ➔ '.join(selected_cols_a) if selected_cols_a else 'None'}**")

                field_specs_a = []
                for c_idx, col_name in enumerate(selected_cols_a):
                    c1, c2 = st.columns([1, 1])
                    suggested_fn = col_name.lower()
                    suggested_norm = "text_nfkd"

                    if imported_p and "fields" in imported_p and c_idx < len(imported_p["fields"]):
                        suggested_fn = imported_p["fields"][c_idx].get("name", suggested_fn)
                        suggested_norm = imported_p["fields"][c_idx].get("normalizer", suggested_norm)
                    elif "cpf" in col_name.lower():
                        suggested_norm = "cpf"
                    elif "cnpj" in col_name.lower():
                        suggested_norm = "cnpj"
                    elif "data" in col_name.lower() or "birth" in col_name.lower():
                        suggested_norm = "date_iso"
                    elif "phone" in col_name.lower() or "tel" in col_name.lower():
                        suggested_norm = "phone_e164"

                    field_name = c1.text_input(f"Pos {c_idx+1} Field Name for '{col_name}':", value=suggested_fn, key=f"fn_a_{c_idx}")
                    norm_opts = list(NORMALIZER_REGISTRY.keys())
                    norm_idx = norm_opts.index(suggested_norm) if suggested_norm in norm_opts else 0
                    normalizer_name = c2.selectbox(
                        f"Pos {c_idx+1} Normalizer for '{col_name}':",
                        norm_opts,
                        index=norm_idx,
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
                    label="📤 Export Pattern as JSON",
                    data=pattern_json_a,
                    file_name=f"{schema_a.schema_id}.json",
                    mime="application/json",
                    key="dl_pattern_a",
                )

            # 2. Standard CPF
            elif "CPF" in key_type:
                def_idx_a = 0
                for cand in ["cpf_titular", "cpf", "doc_cpf", "tax_id"]:
                    if cand in headers_a:
                        def_idx_a = headers_a.index(cand)
                        break
                col_a = st.selectbox("Select column containing CPF:", headers_a, index=def_idx_a, key="col_map_a")
                schema_a = create_cpf_schema()
                mapped_rows_a = [{"cpf": r[col_a]} for r in rows_a]
                key_col_a = col_a

            # 3. Standard CNPJ
            elif "CNPJ" in key_type:
                def_idx_a = 0
                for cand in ["cnpj_fornecedor", "cnpj", "tax_id", "empresa_cnpj"]:
                    if cand in headers_a:
                        def_idx_a = headers_a.index(cand)
                        break
                col_a = st.selectbox("Select column containing CNPJ:", headers_a, index=def_idx_a, key="col_map_a")
                schema_a = create_cnpj_schema(strict=False)
                mapped_rows_a = [{"cnpj": r[col_a]} for r in rows_a]
                key_col_a = col_a

            # 4. Composite Phone + Region
            else:
                c1, c2 = st.columns(2)
                p_idx = 0
                for cand in ["telefone_contato", "telefone", "phone", "celular"]:
                    if cand in headers_a:
                        p_idx = headers_a.index(cand)
                        break
                r_idx = next((i for i in range(len(headers_a)) if i != p_idx), 0)
                for cand in ["uf_estado", "estado_uf", "uf", "regiao", "region"]:
                    if cand in headers_a:
                        r_idx = headers_a.index(cand)
                        break
                col_phone_a = c1.selectbox("Phone column:", headers_a, index=p_idx, key="col_phone_a")
                col_reg_a = c2.selectbox("Region/UF column:", headers_a, index=r_idx, key="col_reg_a")
                schema_a = create_phone_region_schema()
                mapped_rows_a = [{"phone": r[col_phone_a], "region": r[col_reg_a]} for r in rows_a]
                key_col_a = f"{col_phone_a} + {col_reg_a}"

            # Canonical Preview
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
            st.session_state["raw_csv_b"] = raw_content_b
        else:
            raw_content_b = st.session_state.get("raw_csv_b", DEFAULT_HOSPITAL_B_CSV)

        rows_b, headers_b = load_csv_data(raw_content_b)
        st.caption(f"Loaded **{len(rows_b)}** records &bull; Columns: `{', '.join(headers_b)}`")

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

                default_cols_b = [headers_b[0]]
                if "key_columns_b" in imported_p:
                    default_cols_b = [c for c in imported_p["key_columns_b"] if c in headers_b]
                elif len(headers_b) > 1:
                    default_cols_b = [headers_b[1]]

                selected_cols_b = st.multiselect(
                    "Select columns from Hospital B that form the composite key (order matters):",
                    headers_b,
                    default=default_cols_b,
                    key="sel_cols_b",
                )

                st.caption(f"📌 Key Sequence: **{' ➔ '.join(selected_cols_b) if selected_cols_b else 'None'}**")

                field_specs_b = []
                for c_idx, col_name in enumerate(selected_cols_b):
                    c1, c2 = st.columns([1, 1])
                    suggested_fn = col_name.lower()
                    suggested_norm = "text_nfkd"

                    if imported_p and "fields" in imported_p and c_idx < len(imported_p["fields"]):
                        suggested_fn = imported_p["fields"][c_idx].get("name", suggested_fn)
                        suggested_norm = imported_p["fields"][c_idx].get("normalizer", suggested_norm)
                    elif "cpf" in col_name.lower():
                        suggested_norm = "cpf"
                    elif "cnpj" in col_name.lower():
                        suggested_norm = "cnpj"
                    elif "data" in col_name.lower() or "birth" in col_name.lower():
                        suggested_norm = "date_iso"
                    elif "phone" in col_name.lower() or "tel" in col_name.lower():
                        suggested_norm = "phone_e164"

                    field_name = c1.text_input(f"Pos {c_idx+1} Field Name for '{col_name}':", value=suggested_fn, key=f"fn_b_{c_idx}")
                    norm_opts = list(NORMALIZER_REGISTRY.keys())
                    norm_idx = norm_opts.index(suggested_norm) if suggested_norm in norm_opts else 0
                    normalizer_name = c2.selectbox(
                        f"Pos {c_idx+1} Normalizer for '{col_name}':",
                        norm_opts,
                        index=norm_idx,
                        key=f"norm_b_{c_idx}",
                    )
                    field_specs_b.append({"name": field_name, "normalizer": normalizer_name, "source_col": col_name})

                schema_b = create_custom_schema(schema_id_b, field_specs_b)
                mapped_rows_b = [{f["name"]: r.get(f["source_col"], "") for f in field_specs_b} for r in rows_b]
                key_col_b = " + ".join(selected_cols_b) if selected_cols_b else "None"

                pattern_json_b = json.dumps(
                    {
                        "schema_id": schema_b.schema_id,
                        "fields": [{"name": f["name"], "normalizer": f["normalizer"]} for f in field_specs_b],
                    },
                    indent=2,
                )
                st.download_button(
                    label="📤 Export Pattern as JSON",
                    data=pattern_json_b,
                    file_name=f"{schema_b.schema_id}.json",
                    mime="application/json",
                    key="dl_pattern_b",
                )

            elif "CPF" in key_type:
                def_idx_b = 0
                for cand in ["doc_cpf", "cpf", "cpf_titular", "tax_id"]:
                    if cand in headers_b:
                        def_idx_b = headers_b.index(cand)
                        break
                col_b = st.selectbox("Select column containing CPF:", headers_b, index=def_idx_b, key="col_map_b")
                schema_b = create_cpf_schema()
                mapped_rows_b = [{"cpf": r[col_b]} for r in rows_b]
                key_col_b = col_b

            elif "CNPJ" in key_type:
                def_idx_b = 0
                for cand in ["tax_id", "cnpj", "cnpj_fornecedor", "empresa_cnpj"]:
                    if cand in headers_b:
                        def_idx_b = headers_b.index(cand)
                        break
                col_b = st.selectbox("Select column containing CNPJ:", headers_b, index=def_idx_b, key="col_map_b")
                schema_b = create_cnpj_schema(strict=False)
                mapped_rows_b = [{"cnpj": r[col_b]} for r in rows_b]
                key_col_b = col_b

            else:
                c1, c2 = st.columns(2)
                p_idx = 0
                for cand in ["celular", "telefone", "phone", "telefone_contato"]:
                    if cand in headers_b:
                        p_idx = headers_b.index(cand)
                        break
                r_idx = next((i for i in range(len(headers_b)) if i != p_idx), 0)
                for cand in ["regiao", "uf_residencia", "uf_estado", "estado_uf", "uf", "region"]:
                    if cand in headers_b:
                        r_idx = headers_b.index(cand)
                        break
                col_phone_b = c1.selectbox("Phone column:", headers_b, index=p_idx, key="col_phone_b")
                col_reg_b = c2.selectbox("Region/UF column:", headers_b, index=r_idx, key="col_reg_b")
                schema_b = create_phone_region_schema()
                mapped_rows_b = [{"phone": r[col_phone_b], "region": r[col_reg_b]} for r in rows_b]
                key_col_b = f"{col_phone_b} + {col_reg_b}"

            if mapped_rows_b:
                sample_cri_b = schema_b.serialize_record(mapped_rows_b[0]).decode("utf-8")
                st.markdown(
                    f"**Canonical Format Preview (CRI):**<div class='cri-preview'>{sample_cri_b}</div>",
                    unsafe_allow_html=True,
                )

    st.markdown("---")

    # ---------------------------------------------------------------------------
    # Section D: Bilateral Handshake & Confidential Execution
    # ---------------------------------------------------------------------------
    st.markdown("### 2. Confidential Linkage Execution")

    fp_a = schema_a.fingerprint()
    fp_b = schema_b.fingerprint()

    if fp_a != fp_b:
        st.error(
            f"❌ Handshake Mismatch: Both organizations must agree on the same schema format, field names, and sequence. "
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
        key="btn_run_psi",
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

    # ---------------------------------------------------------------------------
    # Section E: Symmetrical Results & Export Options
    # ---------------------------------------------------------------------------
    if "last_psi_execution" in st.session_state:
        exec_data = st.session_state["last_psi_execution"]
        enriched_a = exec_data["enriched_a"]
        enriched_b = exec_data["enriched_b"]
        shared_count = exec_data["shared_count"]
        metrics = exec_data["metrics"]

        st.markdown(
            '<div class="security-banner">🔒 <b>Confidential Record Linkage Complete:</b> '
            'Matches were identified mathematically. Neither hospital exposed any non-matching patients '
            'or other private attributes to the other.</div>',
            unsafe_allow_html=True,
        )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Hospital A Records", len(enriched_a))
        m2.metric("Hospital B Records", len(enriched_b))
        m3.metric("Shared Matches Discovered", f"{shared_count} entities")
        m4.metric("Crypto Latency", f"{metrics.execution_time_ms:.1f} ms")

        st.markdown("---")
        st.markdown("### 3. Symmetrical Results & Export Options")

        res_col_a, res_col_b = st.columns(2)

        # Hospital A Export
        with res_col_a:
            st.markdown('<div class="org-header-a">📁 Hospital A: Enriched Database</div>', unsafe_allow_html=True)
            render_dataframe(enriched_a)

            st.markdown("**Export Hospital A Data:**")
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

            key_cols_list_a = [c.strip() for c in key_col_a.split("+") if c.strip() and c.strip() != "None"]
            if not key_cols_list_a:
                key_cols_list_a = [list(enriched_a[0].keys())[0]]
            key_only_a = io.StringIO()
            key_writer_a = csv.DictWriter(key_only_a, fieldnames=key_cols_list_a + ["matched"])
            key_writer_a.writeheader()
            for r in enriched_a:
                row_out = {c: r.get(c, "") for c in key_cols_list_a}
                row_out["matched"] = r["matched"]
                key_writer_a.writerow(row_out)

            st.download_button(
                label="🔑 Download Keys-Only with 'matched' column (CSV)",
                data=key_only_a.getvalue(),
                file_name="hospital_a_keys_only.csv",
                mime="text/csv",
                key="dl_key_a",
            )

        # Hospital B Export
        with res_col_b:
            st.markdown('<div class="org-header-b">📁 Hospital B: Enriched Database</div>', unsafe_allow_html=True)
            render_dataframe(enriched_b)

            st.markdown("**Export Hospital B Data:**")
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

            key_cols_list_b = [c.strip() for c in key_col_b.split("+") if c.strip() and c.strip() != "None"]
            if not key_cols_list_b:
                key_cols_list_b = [list(enriched_b[0].keys())[0]]
            key_only_b = io.StringIO()
            key_writer_b = csv.DictWriter(key_only_b, fieldnames=key_cols_list_b + ["matched"])
            key_writer_b.writeheader()
            for r in enriched_b:
                row_out = {c: r.get(c, "") for c in key_cols_list_b}
                row_out["matched"] = r["matched"]
                key_writer_b.writerow(row_out)

            st.download_button(
                label="🔑 Download Keys-Only with 'matched' column (CSV)",
                data=key_only_b.getvalue(),
                file_name="hospital_b_keys_only.csv",
                mime="text/csv",
                key="dl_key_b",
            )

        # -------------------------------------------------------------------
        # Section 4: Matched Keys Table (Plaintext vs Encrypted Points)
        # -------------------------------------------------------------------
        st.markdown("---")
        st.markdown("### 4. Matched Keys Table (Decrypted / Plaintext vs. Encrypted Curve Points)")
        st.caption(
            "Displays every discovered match alongside its canonical plaintext identifier, each hospital's "
            "singly-encrypted curve point ($a \\cdot H(x)$ and $b \\cdot H(y)$), and the resulting identical "
            "double-blinded commutative token ($ab \\cdot P$)."
        )
        trace = exec_data["trace"]
        if not trace["matched_indices_a"]:
            st.info("No matched records were found in this run.")
        else:
            matched_table = []
            for idx_a in trace["matched_indices_a"]:
                shared_pt_bytes = trace["doubly_a"][idx_a].to_compressed_bytes()
                idx_b = next(
                    i for i, pt in enumerate(trace["doubly_b"]) if pt.to_compressed_bytes() == shared_pt_bytes
                )
                matched_table.append({
                    "Decrypted / Canonical Key (CRI)": trace["cri_a"][idx_a].decode("utf-8"),
                    "Hospital A Raw Key": " | ".join(
                        str(trace["rows_a"][idx_a].get(c.strip(), "")) for c in trace["key_col_a"].split("+")
                    ),
                    "Hospital B Raw Key": " | ".join(
                        str(trace["rows_b"][idx_b].get(c.strip(), "")) for c in trace["key_col_b"].split("+")
                    ),
                    "Encrypted A (a·P)": trace["blinded_a"][idx_a].to_compressed_bytes().hex()[:20] + "...",
                    "Encrypted B (b·P)": trace["blinded_b"][idx_b].to_compressed_bytes().hex()[:20] + "...",
                    "Shared Token (ab·P)": shared_pt_bytes.hex()[:24] + "...",
                })
            render_dataframe(matched_table)


# ===========================================================================
# TAB 2: BEHIND THE SCENES — CRYPTOGRAPHIC INSPECTION
# ===========================================================================
with main_tab_behind:
    st.markdown("### 🔬 Behind the Scenes: Cryptographic Execution Trace")
    st.markdown(
        "Inspect the step-by-step cryptographic transformations on **actual patient records** from the protocol run. "
        "Compare a **Matched Record** against an **Unmatched Record** to understand why the commutative double-lock works "
        "and why zero plaintext information is leaked."
    )

    if "last_psi_execution" not in st.session_state:
        st.info("ℹ️ Please run a record linkage in the first tab to view the live cryptographic trace of your actual records.")
    else:
        trace = st.session_state["last_psi_execution"]["trace"]

        c_top1, c_top2 = st.columns([2, 1])
        with c_top1:
            st.caption("Inspect how each stage transforms the data from plain text to pseudorandom curve points.")
        with c_top2:
            reroll = st.button("🎲 Pick Random Pair to Inspect", key="btn_reroll_pair")

        col_trace_matched, col_trace_unmatched = st.columns(2)

        # -------------------------------------------------------------------
        # CASE 1: TRACE OF A MATCHED RECORD
        # -------------------------------------------------------------------
        with col_trace_matched:
            st.markdown('<div class="trace-card">', unsafe_allow_html=True)
            st.markdown('<h4>Case 1: Trace of a <span class="match-tag">MATCHED RECORD</span></h4>', unsafe_allow_html=True)

            if not trace["matched_indices_a"]:
                st.warning("No matched records occurred in the last run to trace.")
            else:
                # Random or selected matched record
                matched_opts = trace["matched_indices_a"]
                if reroll or "selected_match_idx" not in st.session_state:
                    st.session_state["selected_match_idx"] = random.choice(matched_opts)

                idx_a = st.session_state["selected_match_idx"]
                if idx_a not in matched_opts:
                    idx_a = matched_opts[0]

                matched_target = trace["doubly_a"][idx_a].to_compressed_bytes()
                idx_b = next(
                    i for i, pt in enumerate(trace["doubly_b"]) if pt.to_compressed_bytes() == matched_target
                )

                st.markdown(f"**1. Raw Input Records (Patient index #{idx_a}):**")
                st.json({
                    "Hospital A Input": trace["rows_a"][idx_a],
                    "Hospital B Input": trace["rows_b"][idx_b],
                })

                st.markdown("**2. Canonical Record Identifiers (CRI):**")
                st.code(
                    f"Hospital A CRI: {trace['cri_a'][idx_a].decode('utf-8')}\n"
                    f"Hospital B CRI: {trace['cri_b'][idx_b].decode('utf-8')}\n"
                    f"Are canonical bytes identical? {trace['cri_a'][idx_a] == trace['cri_b'][idx_b]} ✅",
                    language="text",
                )

                st.markdown(r"**3. Hash-to-Curve Mapping ($P = H(x) \in E(\mathbb{F}_p)$):**")
                st.code(
                    f"Affine X: {hex(trace['pt_a'][idx_a].x)[:34]}...\n"
                    f"Affine Y: {hex(trace['pt_a'][idx_a].y)[:34]}...",
                    language="text",
                )

                st.markdown("**4. First Local Point Blinding:**")
                st.code(
                    f"Hospital A computes P_A = a * P:\n  {trace['blinded_a'][idx_a].to_compressed_bytes().hex()}\n"
                    f"Hospital B computes P_B = b * P:\n  {trace['blinded_b'][idx_b].to_compressed_bytes().hex()}",
                    language="text",
                )

                st.markdown("**5. The Commutative Double-Lock Result:**")
                p_ba_hex = trace["doubly_a"][idx_a].to_compressed_bytes().hex()
                p_ab_hex = trace["doubly_b"][idx_b].to_compressed_bytes().hex()
                st.code(
                    f"Hospital B double-blinds P_A with b -> P_BA:\n  {p_ba_hex}\n\n"
                    f"Hospital A double-blinds P_B with a -> P_AB:\n  {p_ab_hex}\n\n"
                    f"Exact 33-byte Point Match: {p_ba_hex == p_ab_hex} ✅",
                    language="text",
                )
                st.caption(
                    "Mathematical Proof: a * (b * P) == b * (a * P). Both hospitals discover this record matched "
                    "without exposing their private scalar keys or other sensitive record fields."
                )
            st.markdown('</div>', unsafe_allow_html=True)

        # -------------------------------------------------------------------
        # CASE 2: TRACE OF AN UNMATCHED RECORD
        # -------------------------------------------------------------------
        with col_trace_unmatched:
            st.markdown('<div class="trace-card">', unsafe_allow_html=True)
            st.markdown('<h4>Case 2: Trace of an <span class="unmatch-tag">UNMATCHED RECORD</span></h4>', unsafe_allow_html=True)

            if not trace["unmatched_indices_a"]:
                st.info("No unmatched records in Hospital A for the last run.")
            else:
                unmatched_opts = trace["unmatched_indices_a"]
                if reroll or "selected_unmatch_idx" not in st.session_state:
                    st.session_state["selected_unmatch_idx"] = random.choice(unmatched_opts)

                idx_un_a = st.session_state["selected_unmatch_idx"]
                if idx_un_a not in unmatched_opts:
                    idx_un_a = unmatched_opts[0]

                idx_un_b = trace["unmatched_indices_b"][0] if trace["unmatched_indices_b"] else 0

                st.markdown(f"**1. Raw Input Records (Hospital A index #{idx_un_a}):**")
                st.json({
                    "Hospital A Input (Unmatched)": trace["rows_a"][idx_un_a],
                    "Hospital B Sample": trace["rows_b"][idx_un_b],
                })

                st.markdown("**2. Canonical Record Identifiers (CRI):**")
                st.code(
                    f"Hospital A CRI: {trace['cri_a'][idx_un_a].decode('utf-8')}\n"
                    f"Hospital B CRI: {trace['cri_b'][idx_un_b].decode('utf-8')}\n"
                    f"Are canonical bytes identical? False ❌",
                    language="text",
                )

                st.markdown("**3. Hash-to-Curve Points ($P_A \neq P_B$):**")
                st.code(
                    f"Point P_A = H(x_A):\n  x = {hex(trace['pt_a'][idx_un_a].x)[:32]}...\n"
                    f"Point P_B = H(y_B):\n  x = {hex(trace['pt_b'][idx_un_b].x)[:32]}...",
                    language="text",
                )

                st.markdown("**4. First Local Point Blinding:**")
                st.code(
                    f"Hospital A computes P_A = a * H(x_A):\n  {trace['blinded_a'][idx_un_a].to_compressed_bytes().hex()}\n"
                    f"Hospital B computes P_B = b * H(y_B):\n  {trace['blinded_b'][idx_un_b].to_compressed_bytes().hex()}",
                    language="text",
                )

                st.markdown("**5. The Commutative Result:**")
                p_ba_un = trace["doubly_a"][idx_un_a].to_compressed_bytes().hex()
                p_ab_un = trace["doubly_b"][idx_un_b].to_compressed_bytes().hex()
                st.code(
                    f"Hospital B double-blinds P_A with b -> P_BA:\n  {p_ba_un}\n\n"
                    f"Hospital A double-blinds P_B with a -> P_AB:\n  {p_ab_un}\n\n"
                    f"Exact 33-byte Point Match: {p_ba_un == p_ab_un} ❌ (NO MATCH)",
                    language="text",
                )
                st.caption(
                    "Zero-Knowledge Protection: Under the Computational Diffie-Hellman (CDH) assumption, "
                    "the resulting point is indistinguishable from random noise. Neither hospital can reverse-engineer "
                    "or infer the identity of unmatched records."
                )
            st.markdown('</div>', unsafe_allow_html=True)


# ===========================================================================
# TAB 3: EMPIRICAL BENCHMARK & SECURITY ANALYTICS
# ===========================================================================
with main_tab_analytics:
    st.markdown("### 📊 Empirical Benchmark & Security Analytics Dashboard")
    st.caption(
        "Rigorous performance evaluation, scalability up to **500,000 records per party (1,000,000 total)**, "
        "and empirical cryptanalysis including the **3-Hour secp256k1 Exhaustion Attack (1.411 billion attempts)**."
    )

    # Executive Metric Cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown('<div class="metric-card"><h4>1,000,000</h4><p>Max Records Tested<br>(500k per Party)</p></div>', unsafe_allow_html=True)
    with k2:
        st.markdown('<div class="metric-card"><h4>1.411 Billion</h4><p>secp256k1 Points Checked<br>(3-Hour Attack)</p></div>', unsafe_allow_html=True)
    with k3:
        st.markdown('<div class="metric-card"><h4>2.81 × 10⁶⁴ Years</h4><p>Time to Exhaust secp256k1<br>(2.04 × 10⁵⁴ Universes)</p></div>', unsafe_allow_html=True)
    with k4:
        st.markdown('<div class="metric-card"><h4>100.0% Recall</h4><p>SecureMatch Pipeline<br>(vs 51.4% Raw Decay)</p></div>', unsafe_allow_html=True)

    st.markdown("---")

    # Interactive Sub-Tabs for Figures and Analysis
    sub_tab_figs, sub_tab_asymm, sub_tab_cracker = st.tabs([
        "📈 Publication Evaluation Figures",
        "⚖️ Asymmetric Scale Dilemma Analysis",
        "⚡ Live SHA-256 Preimage Cracker Demo",
    ])

    # 1. Figures Tab
    with sub_tab_figs:
        results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../benchmark/results"))

        fig_files = [
            ("Figure 1: Scalability & The Privacy Tax (N up to 500k)", "fig1_scalability_privacy_tax.png"),
            ("Figure 2: Component Runtime Breakdown (Blinding = 85.9%)", "fig2_component_breakdown.png"),
            ("Figure 3: Asymmetric Scale Dilemma (|A|=500 vs |B| up to 500k)", "fig3_asymmetric_scale.png"),
            ("Figure 4: Transport Channel Overhead (In-Memory vs TCP Socket)", "fig4_cpu_vs_network.png"),
            ("Figure 5: Record Linkage Recall vs Noise (Normalization Gain)", "fig5_data_decay_fnr.png"),
            ("Figure 6: Cryptanalytic Vulnerability vs Discrete Log Hardness", "fig6_security_cryptanalysis.png"),
        ]

        f_choice = st.selectbox("Select Evaluation Figure to Inspect:", [name for name, _ in fig_files])
        chosen_filename = next(fn for name, fn in fig_files if name == f_choice)
        chosen_path = os.path.join(results_dir, chosen_filename)

        if os.path.exists(chosen_path):
            st.image(chosen_path, caption=f_choice, use_container_width=True)
        else:
            st.warning(f"Figure file not found at: `{chosen_path}`. Run `python benchmark/run_orchestrator.py` to regenerate.")

    # 2. Asymmetric Scale Analysis Tab
    with sub_tab_asymm:
        st.markdown(r"#### Real-World Asymmetry: Specialized Clinic ($|A|=500$) vs Regional Hospital ($|B| \le 500{,}000$)")
        st.markdown(
            "In healthcare linkage, a rare-disease clinic or specialized oncology registry often has a small cohort "
            "that needs to be reconciled against a massive state-wide or national hospital database. "
            "These empirical measurements quantify the exact computational and bandwidth distribution:"
        )

        asymm_data = [
            {"Hospital B Size": "1,000", "Scale Ratio": "2x", "Protocol Time": "2.75 s", "Clinic Outbound": "16.7 KB", "Hospital Outbound": "49.7 KB", "Total Wire": "66.4 KB"},
            {"Hospital B Size": "10,000", "Scale Ratio": "20x", "Protocol Time": "17.17 s", "Clinic Outbound": "16.7 KB", "Hospital Outbound": "346.7 KB", "Total Wire": "363.4 KB"},
            {"Hospital B Size": "50,000", "Scale Ratio": "100x", "Protocol Time": "1 min 20 s (79.6 s)", "Clinic Outbound": "16.7 KB", "Hospital Outbound": "1.67 MB", "Total Wire": "1.68 MB"},
            {"Hospital B Size": "100,000", "Scale Ratio": "200x", "Protocol Time": "2 min 41 s (160.9 s)", "Clinic Outbound": "16.7 KB", "Hospital Outbound": "3.32 MB", "Total Wire": "3.33 MB"},
            {"Hospital B Size": "500,000", "Scale Ratio": "1,000x", "Protocol Time": "13 min 05 s (785.5 s)", "Clinic Outbound": "16.7 KB", "Hospital Outbound": "16.52 MB", "Total Wire": "16.53 MB"},
        ]
        render_dataframe(asymm_data)

        st.info(
            "💡 **Key Insight:** Clinic A's outbound wire bandwidth remains strictly **constant at 16.7 KB** "
            "regardless of whether Hospital B has 1,000 or 500,000 records. Computation scales strictly as "
            "$O(|A| + |B|)$ because both parties perform symmetric commutative double-blinding."
        )

    # 3. Live SHA-256 Cracker Demo Tab
    with sub_tab_cracker:
        st.markdown("#### Live Cryptanalytic Demonstration: Why Naive Hashing Fails")
        st.markdown(
            "Low-entropy identifiers like Brazilian CPFs (11 digits, ~10⁹ space) or CNPJs (14 digits) "
            "are completely vulnerable to dictionary attacks and rainbow tables when hashed with plain SHA-256. "
            "Test the preimage search speed below:"
        )

        sc_col1, sc_col2 = st.columns([1, 1])

        with sc_col1:
            st.markdown("##### 1. Test CPF Cracking")
            sample_cpf = st.text_input("CPF to Hash & Crack:", value="12345678909", key="input_crack_cpf")
            prefix_hint = st.text_input("Attacker Prefix Hint (e.g., regional band '123'):", value="1234", key="input_prefix_cpf")

            if st.button("🔨 Crack Naive SHA-256 CPF", key="btn_crack_cpf"):
                import hashlib
                h_target = hashlib.sha256(sample_cpf.encode("utf-8")).hexdigest()
                st.code(f"Target SHA-256 Digest:\n{h_target}", language="text")

                with st.spinner("Executing dictionary preimage attack..."):
                    res = crack_naive_sha256_cpf(h_target, cpf_prefix_hint=prefix_hint)

                if res["success"]:
                    st.success(f"🔓 **Cracked Plaintext:** `{res['cracked_plaintext']}`")
                    st.write(f"- **Time Taken:** {res['elapsed_seconds']:.3f} seconds")
                    st.write(f"- **Attempts Evaluated:** {res['attempts']:,}")
                    st.write(f"- **Throughput:** {res['hash_rate_ops_per_sec']:,.0f} hashes/sec")
                else:
                    st.warning("Not found within attempt budget.")

        with sc_col2:
            st.markdown("##### 2. Test CNPJ Cracking")
            sample_cnpj = st.text_input("CNPJ to Hash & Crack:", value="12345678000195", key="input_crack_cnpj")
            prefix_cnpj = st.text_input("Attacker Root Prefix Hint:", value="12345", key="input_prefix_cnpj")

            if st.button("🔨 Crack Naive SHA-256 CNPJ", key="btn_crack_cnpj"):
                import hashlib
                h_cnpj = hashlib.sha256(sample_cnpj.encode("utf-8")).hexdigest()
                st.code(f"Target SHA-256 Digest:\n{h_cnpj}", language="text")

                with st.spinner("Executing dictionary preimage attack..."):
                    res_c = crack_naive_sha256_cnpj(h_cnpj, branch="0001", cnpj_prefix_hint=prefix_cnpj)

                if res_c["success"]:
                    st.success(f"🔓 **Cracked Plaintext:** `{res_c['cracked_plaintext']}`")
                    st.write(f"- **Time Taken:** {res_c['elapsed_seconds']:.3f} seconds")
                    st.write(f"- **Attempts Evaluated:** {res_c['attempts']:,}")
                    st.write(f"- **Throughput:** {res_c['hash_rate_ops_per_sec']:,.0f} hashes/sec")
                else:
                    st.warning("Not found within attempt budget.")
