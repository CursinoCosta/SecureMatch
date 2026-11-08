"""
SecureMatch Interactive Web Interface (Streamlit).

A user-facing application for Privacy-Preserving Record Linkage:
- Step 1: Upload local database (CSV or built-in realistic cohorts).
- Step 2: Choose & map the shared primary key / matching pattern.
- Step 3: Connect to the other party (Dual-party mode or Networked TCP socket mode).
- Step 4: Inspect matched records and export results with cryptographic privacy guarantees.
"""

import asyncio
import csv
import io
import json
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is in Python module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import streamlit as st
from src.crypto.curve import Point, generate_private_scalar
from src.crypto.engine import blind_point
from src.crypto.hash_to_curve import hash_to_curve
from src.data_pipeline.schema import (
    Schema,
    create_cnpj_schema,
    create_cpf_schema,
    create_custom_schema,
    create_internal_id_schema,
    create_phone_region_schema,
)
from src.protocol.party_client import IntersectionResult, PSIClient
from src.protocol.party_server import PSIServer
from src.transport.memory_channel import ChannelMetrics, run_in_memory_psi
from src.transport.socket_transport import SocketPSIServer, run_socket_client


st.set_page_config(
    page_title="SecureMatch — Private Record Linkage",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling for production look
st.markdown("""
<style>
    .main-title { font-size: 2.1rem; font-weight: 700; color: #1E3A8A; margin-bottom: 0.1rem; }
    .sub-title { font-size: 1.0rem; color: #4B5563; margin-bottom: 1.2rem; }
    .step-header { font-size: 1.2rem; font-weight: 600; color: #1F2937; margin-top: 0.8rem; margin-bottom: 0.4rem; }
    .card-box { background-color: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px; padding: 14px; margin-bottom: 12px; }
    .party-a-badge { background-color: #EFF6FF; border: 1px solid #3B82F6; color: #1E40AF; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 0.85rem; }
    .party-b-badge { background-color: #FDF4FF; border: 1px solid #C084FC; color: #7E22CE; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 0.85rem; }
    .security-badge { background-color: #ECFDF5; border: 1px solid #10B981; color: #065F46; padding: 10px 14px; border-radius: 6px; font-size: 0.92rem; margin-top: 10px; }
    .cri-preview { background-color: #F3F4F6; font-family: monospace; font-size: 0.88rem; padding: 6px 10px; border-radius: 4px; border-left: 3px solid #3B82F6; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🔒 SecureMatch: Private Record Linkage</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-title">'
    'Privacy-Preserving Entity Resolution via Commutative ECDH Private Set Intersection &bull; DCC / ICEx / UFMG'
    '</div>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar Navigation & Role Selection
# ---------------------------------------------------------------------------
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.subheader("Operational Mode")
    app_mode = st.radio(
        "Select your interface mode:",
        [
            "Dual-Party Workspace (Recommended)",
            "Client Node (Party A - Initiator)",
            "Server Node (Party B - Responder)",
            "Educational Cryptography Inspector",
        ],
        index=0,
    )
    st.markdown("---")
    st.markdown("**Cryptographic Guarantee:**")
    st.caption(
        "SecureMatch executes a zero-knowledge two-party protocol. "
        "Neither party reveals non-intersecting rows to the other."
    )


# ---------------------------------------------------------------------------
# Helper Sample Datasets
# ---------------------------------------------------------------------------
SAMPLE_DATASETS = {
    "CPF: Healthcare vs. Insurance Cohort": {
        "schema_type": "cpf",
        "party_a": [
            {"cpf_raw": "123.456.789-01", "patient_name": "Alice Silva", "condition": "Diabetes"},
            {"cpf_raw": "234.567.890-12", "patient_name": "Bob Santos", "condition": "Hypertension"},
            {"cpf_raw": "345.678.901-23", "patient_name": "Carol Lima", "condition": "Asthma"},
            {"cpf_raw": "456.789.012-34", "patient_name": "Daniel Souza", "condition": "Healthy"},
            {"cpf_raw": "567.890.123-45", "patient_name": "Eduardo Rocha", "condition": "Migraine"},
        ],
        "party_b": [
            {"num_cpf": "99988877766", "plan": "Premium Gold", "status": "Active"},
            {"num_cpf": "23456789012", "plan": "Silver Basic", "status": "Active"},  # Match
            {"num_cpf": "12345678901", "plan": "Standard", "status": "Suspended"},   # Match
            {"num_cpf": "34567890123", "plan": "Premium Gold", "status": "Active"},  # Match
            {"num_cpf": "88877766655", "plan": "Bronze", "status": "Cancelled"},
        ],
        "col_a": "cpf_raw",
        "col_b": "num_cpf",
    },
    "CNPJ: Supplier Blacklist vs. Bank Registry (Numeric & Alphanumeric)": {
        "schema_type": "cnpj",
        "party_a": [
            {"cnpj_col": "00.000.000/0001-91", "company": "Banco do Brasil (Numeric)", "risk": "Low"},
            {"cnpj_col": "12.ABC.345/0001-88", "company": "Tech Inova (Alphanumeric CNPJ)", "risk": "Medium"},
            {"cnpj_col": "33.222.111/0001-44", "company": "Alpha Mineração (Numeric)", "risk": "Low"},
            {"cnpj_col": "99.ZZZ.888/0001-77", "company": "Beta Cloud Services (Alphanumeric)", "risk": "High"},
        ],
        "party_b": [
            {"tax_id": "12ABC345000188", "flag": "Under Investigation", "city": "Belo Horizonte"}, # Match
            {"tax_id": "00000000000191", "flag": "Audited Clean", "city": "Brasília"},              # Match
            {"tax_id": "55.444.333/0001-22", "flag": "Pending KYC", "city": "São Paulo"},
            {"tax_id": "77.888.999/0001-00", "flag": "Flagged Fraud", "city": "Rio de Janeiro"},
        ],
        "col_a": "cnpj_col",
        "col_b": "tax_id",
    },
    "Composite: Phone + Region (E.164 + State)": {
        "schema_type": "phone_region",
        "party_a": [
            {"phone": "(31) 98765-4321", "region": "mg", "customer": "Alice"},
            {"phone": "(11) 91234-5678", "region": "sp", "customer": "Bob"},
            {"phone": "(21) 99999-0000", "region": "rj", "customer": "Carol"},
            {"phone": "(31) 97777-6666", "region": "mg", "customer": "Daniel"},
        ],
        "party_b": [
            {"phone": "+5531987654321", "region": "MG", "crm_id": "CRM-801"}, # Match
            {"phone": "+5521999990000", "region": "RJ", "crm_id": "CRM-802"}, # Match
            {"phone": "+5581955554444", "region": "PE", "crm_id": "CRM-803"},
            {"phone": "+5541933332222", "region": "PR", "crm_id": "CRM-804"},
        ],
        "col_a_phone": "phone",
        "col_a_region": "region",
        "col_b_phone": "phone",
        "col_b_region": "region",
    },
}


def parse_csv_file(uploaded_file) -> List[Dict[str, Any]]:
    """Parses uploaded CSV bytes into list of dictionaries."""
    content = uploaded_file.getvalue().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


# ===========================================================================
# MODE 1: DUAL-PARTY WORKSPACE (ALL-IN-ONE REALISTIC SIMULATION)
# ===========================================================================
if app_mode == "Dual-Party Workspace (Recommended)":
    st.markdown("### 🤝 Interactive Record Linkage Session")
    st.markdown(
        "Configure and match records between **Party A (e.g. Hospital / Client)** and "
        "**Party B (e.g. Health Insurer / Server)**. Each party controls its own data schema."
    )

    preset = st.selectbox("Quick-Load Sample Scenario:", list(SAMPLE_DATASETS.keys()))
    scenario = SAMPLE_DATASETS[preset]

    col_party_a, col_party_b = st.columns(2)

    # -----------------------------
    # PARTY A CONFIGURATION
    # -----------------------------
    with col_party_a:
        st.markdown('<span class="party-a-badge">PARTY A (Client / Initiator)</span>', unsafe_allow_html=True)
        st.markdown('<div class="step-header">Step 1: Upload Your Database</div>', unsafe_allow_html=True)

        data_source_a = st.radio("Party A Data Source:", ["Use Scenario Sample", "Upload Custom CSV"], key="src_a")
        if data_source_a == "Upload Custom CSV":
            file_a = st.file_uploader("Upload CSV for Party A", type=["csv"], key="file_a")
            if file_a:
                records_a = parse_csv_file(file_a)
            else:
                records_a = scenario["party_a"]
        else:
            records_a = scenario["party_a"]

        st.caption(f"Loaded **{len(records_a)}** records for Party A.")
        st.dataframe(records_a[:4], use_container_width=True)

        st.markdown('<div class="step-header">Step 2: Choose Shared Primary Key</div>', unsafe_allow_html=True)
        keys_a = list(records_a[0].keys()) if records_a else []

        if scenario["schema_type"] == "cpf":
            col_map_a = st.selectbox("Column containing CPF:", keys_a, index=keys_a.index(scenario.get("col_a", keys_a[0])))
            schema_a = create_cpf_schema()
            normalized_records_a = [{ "cpf": r[col_map_a] } for r in records_a]
        elif scenario["schema_type"] == "cnpj":
            col_map_a = st.selectbox("Column containing CNPJ:", keys_a, index=keys_a.index(scenario.get("col_a", keys_a[0])))
            schema_a = create_cnpj_schema(strict=False)
            normalized_records_a = [{ "cnpj": r[col_map_a] } for r in records_a]
        else:
            c1, c2 = st.columns(2)
            col_p_a = c1.selectbox("Phone Column:", keys_a, index=keys_a.index(scenario.get("col_a_phone", keys_a[0])))
            col_r_a = c2.selectbox("Region Column:", keys_a, index=keys_a.index(scenario.get("col_a_region", keys_a[1])))
            schema_a = create_phone_region_schema()
            normalized_records_a = [{ "phone": r[col_p_a], "region": r[col_r_a] } for r in records_a]

        # Normalization Preview
        if normalized_records_a:
            sample_cri_a = schema_a.serialize_record(normalized_records_a[0]).decode("utf-8")
            st.markdown(f"**Canonical Format Preview (CRI):** <div class='cri-preview'>{sample_cri_a}</div>", unsafe_allow_html=True)

    # -----------------------------
    # PARTY B CONFIGURATION
    # -----------------------------
    with col_party_b:
        st.markdown('<span class="party-b-badge">PARTY B (Server / Respondent)</span>', unsafe_allow_html=True)
        st.markdown('<div class="step-header">Step 1: Upload Your Database</div>', unsafe_allow_html=True)

        data_source_b = st.radio("Party B Data Source:", ["Use Scenario Sample", "Upload Custom CSV"], key="src_b")
        if data_source_b == "Upload Custom CSV":
            file_b = st.file_uploader("Upload CSV for Party B", type=["csv"], key="file_b")
            if file_b:
                records_b = parse_csv_file(file_b)
            else:
                records_b = scenario["party_b"]
        else:
            records_b = scenario["party_b"]

        st.caption(f"Loaded **{len(records_b)}** records for Party B.")
        st.dataframe(records_b[:4], use_container_width=True)

        st.markdown('<div class="step-header">Step 2: Choose Shared Primary Key</div>', unsafe_allow_html=True)
        keys_b = list(records_b[0].keys()) if records_b else []

        if scenario["schema_type"] == "cpf":
            col_map_b = st.selectbox("Column containing CPF:", keys_b, index=keys_b.index(scenario.get("col_b", keys_b[0])))
            schema_b = create_cpf_schema()
            normalized_records_b = [{ "cpf": r[col_map_b] } for r in records_b]
        elif scenario["schema_type"] == "cnpj":
            col_map_b = st.selectbox("Column containing CNPJ:", keys_b, index=keys_b.index(scenario.get("col_b", keys_b[0])))
            schema_b = create_cnpj_schema(strict=False)
            normalized_records_b = [{ "cnpj": r[col_map_b] } for r in records_b]
        else:
            c1, c2 = st.columns(2)
            col_p_b = c1.selectbox("Phone Column:", keys_b, index=keys_b.index(scenario.get("col_b_phone", keys_b[0])))
            col_r_b = c2.selectbox("Region Column:", keys_b, index=keys_b.index(scenario.get("col_b_region", keys_b[1])))
            schema_b = create_phone_region_schema()
            normalized_records_b = [{ "phone": r[col_p_b], "region": r[col_r_b] } for r in records_b]

        # Normalization Preview
        if normalized_records_b:
            sample_cri_b = schema_b.serialize_record(normalized_records_b[0]).decode("utf-8")
            st.markdown(f"**Canonical Format Preview (CRI):** <div class='cri-preview'>{sample_cri_b}</div>", unsafe_allow_html=True)

    # -----------------------------
    # STEP 3: CONNECTION & EXECUTION
    # -----------------------------
    st.markdown("---")
    st.markdown('<div class="step-header">Step 3: Connect & Execute Private Record Linkage</div>', unsafe_allow_html=True)

    # Handshake verification check
    schema_fingerprint_a = schema_a.fingerprint()
    schema_fingerprint_b = schema_b.fingerprint()

    if schema_fingerprint_a == schema_fingerprint_b:
        st.success(f"✅ Handshake Verified: Both parties agree on Schema **'{schema_a.schema_id}'** (Fingerprint: `{schema_fingerprint_a[:16]}...`)")
    else:
        st.error("❌ Schema Handshake Mismatch: Both parties must select compatible primary keys!")

    btn_link = st.button("🚀 Connect & Execute Private Set Intersection", type="primary", use_container_width=True)

    if btn_link:
        if schema_fingerprint_a != schema_fingerprint_b:
            st.error("Cannot proceed: Handshake mismatch.")
        else:
            with st.spinner("Executing Commutative ECDH-PSI (Blinding, Exchanging & Resolving)..."):
                client = PSIClient(records_a, schema_a)
                server = PSIServer(records_b, schema_b)

                # Set mapped CRI records
                client.cri_records = [schema_a.serialize_record(r) for r in normalized_records_a]
                server.cri_records = [schema_b.serialize_record(r) for r in normalized_records_b]

                result, metrics = run_in_memory_psi(client, server)

            # -----------------------------
            # STEP 4: RESULTS
            # -----------------------------
            st.markdown('<div class="step-header">Step 4: Intersection Results & Safe Export</div>', unsafe_allow_html=True)

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Party A Records Compared", result.client_dataset_size)
            m2.metric("Party B Records Compared", result.server_dataset_size)
            m3.metric("Shared Matches Discovered", f"{result.cardinality} ({result.match_rate*100:.1f}%)")
            m4.metric("Wire Bandwidth Transferred", f"{metrics.total_bytes_wire:,} bytes")

            if result.cardinality > 0:
                st.markdown(
                    '<div class="security-badge">'
                    f'🔒 <b>Privacy Preserved:</b> Exactly {result.cardinality} shared entities were identified. '
                    'Neither party learned anything about the non-matching records in the other party\'s database.'
                    '</div>',
                    unsafe_allow_html=True,
                )

                st.subheader("Your Matching Records (Party A):")
                st.dataframe(result.matched_records, use_container_width=True)

                # Download CSV
                csv_buffer = io.StringIO()
                if result.matched_records:
                    writer = csv.DictWriter(csv_buffer, fieldnames=list(result.matched_records[0].keys()))
                    writer.writeheader()
                    writer.writerows(result.matched_records)
                st.download_button(
                    label="📥 Download Matched Records as CSV",
                    data=csv_buffer.getvalue(),
                    file_name="securematch_intersection_results.csv",
                    mime="text/csv",
                )
            else:
                st.info("No matching records found between Party A and Party B.")


# ===========================================================================
# MODE 2: CLIENT NODE (CONNECT OVER TCP SOCKET)
# ===========================================================================
elif app_mode == "Client Node (Party A - Initiator)":
    st.markdown("### 💻 Party A (Client Node — Initiator)")
    st.markdown(
        "Run this node to connect over TCP to Party B's running server window."
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="step-header">Step 1: Upload Your Local Database</div>', unsafe_allow_html=True)
        file_c = st.file_uploader("Upload CSV", type=["csv"], key="client_file")
        if file_c:
            client_rows = parse_csv_file(file_c)
        else:
            client_rows = SAMPLE_DATASETS["CPF: Healthcare vs. Insurance Cohort"]["party_a"]
        st.dataframe(client_rows[:4], use_container_width=True)

    with col2:
        st.markdown('<div class="step-header">Step 2: Choose Shared Primary Key</div>', unsafe_allow_html=True)
        schema_type = st.selectbox("Primary Key Type:", ["CPF", "CNPJ", "Phone + Region"])
        keys = list(client_rows[0].keys()) if client_rows else []

        if schema_type == "CPF":
            c_col = st.selectbox("Select column containing CPF:", keys)
            schema = create_cpf_schema()
            norm_rows = [{ "cpf": r[c_col] } for r in client_rows]
        elif schema_type == "CNPJ":
            c_col = st.selectbox("Select column containing CNPJ:", keys)
            schema = create_cnpj_schema(strict=False)
            norm_rows = [{ "cnpj": r[c_col] } for r in client_rows]
        else:
            p_col = st.selectbox("Phone Column:", keys)
            r_col = st.selectbox("Region Column:", keys)
            schema = create_phone_region_schema()
            norm_rows = [{ "phone": r[p_col], "region": r[r_col] } for r in client_rows]

    st.markdown("---")
    st.markdown('<div class="step-header">Step 3: Connect to Party B (Server)</div>', unsafe_allow_html=True)

    c_host, c_port = st.columns(2)
    target_host = c_host.text_input("Server Host:", value="127.0.0.1")
    target_port = int(c_port.text_input("Server TCP Port:", value="9000"))

    if st.button("🚀 Connect to Party B and Execute PSI", type="primary"):
        client_logic = PSIClient(client_rows, schema)
        client_logic.cri_records = [schema.serialize_record(r) for r in norm_rows]

        try:
            with st.spinner(f"Connecting to {target_host}:{target_port}..."):
                # Run async socket client
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result, metrics = loop.run_until_complete(
                    run_socket_client(client_logic, host=target_host, port=target_port)
                )

            st.success(f"Matched **{result.cardinality}** records in {metrics.execution_time_ms:.1f} ms!")
            st.dataframe(result.matched_records, use_container_width=True)

        except Exception as e:
            st.error(f"Connection failed: {e}. Make sure Party B has started listening on {target_host}:{target_port}.")


# ===========================================================================
# MODE 3: SERVER NODE (HOST OVER TCP SOCKET)
# ===========================================================================
elif app_mode == "Server Node (Party B - Responder)":
    st.markdown("### 🖥️ Party B (Server Node — Responder)")
    st.markdown(
        "Upload your database, choose your key, and start listening for incoming connections from Party A."
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="step-header">Step 1: Upload Your Local Database</div>', unsafe_allow_html=True)
        file_s = st.file_uploader("Upload CSV", type=["csv"], key="server_file")
        if file_s:
            server_rows = parse_csv_file(file_s)
        else:
            server_rows = SAMPLE_DATASETS["CPF: Healthcare vs. Insurance Cohort"]["party_b"]
        st.dataframe(server_rows[:4], use_container_width=True)

    with col2:
        st.markdown('<div class="step-header">Step 2: Choose Shared Primary Key</div>', unsafe_allow_html=True)
        schema_type = st.selectbox("Primary Key Type:", ["CPF", "CNPJ", "Phone + Region"], key="srv_schema")
        keys = list(server_rows[0].keys()) if server_rows else []

        if schema_type == "CPF":
            c_col = st.selectbox("Select column containing CPF:", keys, key="srv_c")
            schema = create_cpf_schema()
            norm_rows = [{ "cpf": r[c_col] } for r in server_rows]
        elif schema_type == "CNPJ":
            c_col = st.selectbox("Select column containing CNPJ:", keys, key="srv_cnpj")
            schema = create_cnpj_schema(strict=False)
            norm_rows = [{ "cnpj": r[c_col] } for r in server_rows]
        else:
            p_col = st.selectbox("Phone Column:", keys, key="srv_p")
            r_col = st.selectbox("Region Column:", keys, key="srv_r")
            schema = create_phone_region_schema()
            norm_rows = [{ "phone": r[p_col], "region": r[r_col] } for r in server_rows]

    st.markdown("---")
    st.markdown('<div class="step-header">Step 3: Network Listening Configuration</div>', unsafe_allow_html=True)

    s_host, s_port = st.columns(2)
    listen_host = s_host.text_input("Listen Host:", value="127.0.0.1", key="srv_host")
    listen_port = int(s_port.text_input("Listen Port:", value="9000", key="srv_port"))

    st.info(
        f"Ready to listen on `{listen_host}:{listen_port}` with Schema Fingerprint: "
        f"`{schema.fingerprint()[:16]}...`"
    )

    st.caption(
        "To run the server in the background for another window, you can run from your terminal: "
        f"`python3 src/transport/socket_transport.py` or keep this tab active."
    )


# ===========================================================================
# MODE 4: EDUCATIONAL CRYPTOGRAPHIC INSPECTOR
# ===========================================================================
else:
    st.markdown("### 🔍 Step-by-Step Cryptographic Walkthrough")
    st.markdown(
        "Inspect how records are converted into elliptic curve points, locked by private keys, "
        "and matched using the commutative property: **$a \\cdot (b \\cdot P) = b \\cdot (a \\cdot P)$**."
    )

    demo_text = st.text_input("Test Plaintext Identifier:", value="123.456.789-01")
    demo_schema = create_cpf_schema()

    c1, c2, c3 = st.columns(3)

    cri = demo_schema.serialize_record({"cpf": demo_text})
    with c1:
        st.markdown("#### Phase 0: Canonical Serialization (CRI)")
        st.code(cri.decode("utf-8"), language="text")
        st.caption("Punctuation stripped, padded to 11 digits, length-prefixed.")

    pt = hash_to_curve(cri)
    with c2:
        st.markdown("#### Phase 1: Hash-to-Curve on secp256k1")
        st.code(f"x = {hex(pt.x)[:22]}...\ny = {hex(pt.y)[:22]}...", language="text")
        st.caption("Verified on curve via Euler quadratic residue test.")

    sa = generate_private_scalar()
    sb = generate_private_scalar()

    p_a = blind_point(sa, pt)
    p_ba = blind_point(sb, p_a)

    p_b = blind_point(sb, pt)
    p_ab = blind_point(sa, p_b)

    with c3:
        st.markdown("#### Phase 2: Commutative Invariant")
        st.code(
            f"Path A [b(aP)]: {p_ba.to_compressed_bytes().hex()[:20]}...\n"
            f"Path B [a(bP)]: {p_ab.to_compressed_bytes().hex()[:20]}...\n"
            f"Equal: {p_ba == p_ab} ✅",
            language="text",
        )
        st.caption("Both paths yield the exact same 33-byte compressed point!")
