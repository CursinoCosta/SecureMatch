"""
SecureMatch Interactive Web Interface (Streamlit).

Provides an accessible, visual demonstration of Commutative ECDH-PSI:
1. Interactive PSI Playground (test matching across real & synthetic datasets).
2. Step-by-Step Educational Protocol Walkthrough (see point blinding in real time).
3. Custom Schema Designer & CRI Inspector.
"""

import sys
import os
import time

# Ensure project root is in Python module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import streamlit as st
from src.crypto.curve import Point, generate_private_scalar
from src.crypto.engine import blind_point, hash_and_blind
from src.crypto.hash_to_curve import hash_to_curve
from src.data_pipeline.schema import (
    create_cnpj_schema,
    create_cpf_schema,
    create_custom_schema,
    create_demographic_schema,
    create_phone_region_schema,
)
from src.protocol.party_client import PSIClient
from src.protocol.party_server import PSIServer
from src.transport.memory_channel import run_in_memory_psi


st.set_page_config(
    page_title="SecureMatch — Commutative ECDH-PSI",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown("""
<style>
    .main-header { font-size: 2.2rem; font-weight: 700; color: #1E3A8A; margin-bottom: 0.2rem; }
    .sub-header { font-size: 1.05rem; color: #4B5563; margin-bottom: 1.5rem; }
    .metric-card { background-color: #F3F4F6; border-radius: 8px; padding: 12px; border-left: 4px solid #3B82F6; }
    .security-badge { background-color: #ECFDF5; border: 1px solid #10B981; color: #065F46; padding: 8px 12px; border-radius: 6px; font-size: 0.9rem; }
    .alert-box { background-color: #FEF2F2; border: 1px solid #EF4444; color: #991B1B; padding: 8px 12px; border-radius: 6px; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-header">🔒 SecureMatch: Commutative ECDH-PSI</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">'
    'Configurable Privacy-Preserving Record Linkage via Elliptic Curve Diffie-Hellman &bull; DCC / ICEx / UFMG (2026/2)'
    '</div>',
    unsafe_allow_html=True,
)

tab_playground, tab_walkthrough, tab_schema = st.tabs([
    "🚀 Interactive PSI Playground",
    "🔍 Step-by-Step Mathematical Walkthrough",
    "📐 Schema Designer & CRI Inspector",
])


# ===========================================================================
# TAB 1: INTERACTIVE PSI PLAYGROUND
# ===========================================================================
with tab_playground:
    st.markdown("### Two-Party Private Record Linkage")
    st.markdown(
        "Party A (Client) and Party B (Server) discover which records they share without revealing "
        "any non-matching records to each other or any third party."
    )

    col_conf1, col_conf2 = st.columns([1, 2])

    with col_conf1:
        st.subheader("1. Match Key Configuration")
        schema_choice = st.selectbox(
            "Select Matching Schema:",
            [
                "Brazilian CPF (National Tax ID)",
                "Brazilian CNPJ (Numeric or Alphanumeric)",
                "Composite: Phone + Region (E.164 + State)",
                "Composite: Demographic Trio (DOB + Name + Region)",
            ],
            index=0,
        )

        sample_overlap = st.slider("Target Intersection Overlap:", 0, 100, 50, format="%d%%")
        show_points = st.checkbox("Show Raw Elliptic Curve Points (Hex)", value=False)

    # Prepare datasets based on chosen schema
    if "CPF" in schema_choice:
        active_schema = create_cpf_schema()
        client_sample = [
            {"cpf": "123.456.789-01", "name": "Alice Silva"},
            {"cpf": "234.567.890-12", "name": "Bob Santos"},
            {"cpf": "345.678.901-23", "name": "Carol Lima"},
            {"cpf": "456.789.012-34", "name": "Daniel Souza"},
            {"cpf": "567.890.123-45", "name": "Eduardo Rocha"},
        ]
        server_sample = [
            {"cpf": "999.888.777-66", "org": "Hospital Central"},
            {"cpf": "23456789012", "org": "Clinica Sul"},      # Match (unformatted)
            {"cpf": "12345678901", "org": "Hospital Central"}, # Match (unformatted)
            {"cpf": "34567890123", "org": "Laboratorio X"},    # Match (unformatted)
            {"cpf": "888.777.666-55", "org": "Hospital Norte"},
        ]
    elif "CNPJ" in schema_choice:
        active_schema = create_cnpj_schema(strict=False)
        client_sample = [
            {"cnpj": "00.000.000/0001-91", "company": "Banco do Brasil (Numeric)"},
            {"cnpj": "12.ABC.345/0001-88", "company": "Tech Inova (Alphanumeric CNPJ)"},
            {"cnpj": "33.222.111/0001-44", "company": "Alpha Corp (Numeric)"},
            {"cnpj": "99.ZZZ.888/0001-77", "company": "Beta AI (Alphanumeric CNPJ)"},
        ]
        server_sample = [
            {"cnpj": "12ABC345000188", "status": "Active Partner"},  # Match
            {"cnpj": "00000000000191", "status": "Registered Vendor"},# Match
            {"cnpj": "55.444.333/0001-22", "status": "Lead"},
            {"cnpj": "77.888.999/0001-00", "status": "Supplier"},
        ]
    elif "Phone" in schema_choice:
        active_schema = create_phone_region_schema()
        client_sample = [
            {"phone": "(31) 98765-4321", "region": "mg", "contact": "Alice"},
            {"phone": "(11) 91234-5678", "region": "sp", "contact": "Bob"},
            {"phone": "(21) 99999-0000", "region": "rj", "contact": "Carol"},
            {"phone": "(31) 97777-6666", "region": "mg", "contact": "Daniel"},
        ]
        server_sample = [
            {"phone": "+5531987654321", "region": "MG", "account": "ACC-101"}, # Match
            {"phone": "+5521999990000", "region": "RJ", "account": "ACC-102"}, # Match
            {"phone": "+5581955554444", "region": "PE", "account": "ACC-103"},
            {"phone": "+5541933332222", "region": "PR", "account": "ACC-104"},
        ]
    else:
        active_schema = create_demographic_schema()
        client_sample = [
            {"dob": "15/08/1995", "name": "João da Silva", "region": "MG"},
            {"dob": "20/01/1990", "name": "Maria Oliveira", "region": "SP"},
            {"dob": "10/11/1988", "name": "Carlos Souza", "region": "RJ"},
        ]
        server_sample = [
            {"dob": "1995-08-15", "name": "JOAO DA SILVA", "region": "mg"}, # Match
            {"dob": "1992-05-30", "name": "Fernanda Lima", "region": "BA"},
            {"dob": "1988-11-10", "name": "Carlos Souza", "region": "RJ"},  # Match
        ]

    with col_conf2:
        st.subheader("2. Dataset Preview (Raw Records)")
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            st.markdown(f"**Party A (Client)** — {len(client_sample)} records")
            st.dataframe(client_sample, use_container_width=True)
        with col_d2:
            st.markdown(f"**Party B (Server)** — {len(server_sample)} records")
            st.dataframe(server_sample, use_container_width=True)

    st.markdown("---")
    btn_run = st.button("🚀 Run Private Set Intersection (ECDH-PSI)", type="primary", use_container_width=True)

    if btn_run:
        client = PSIClient(client_sample, active_schema)
        server = PSIServer(server_sample, active_schema)

        result, metrics = run_in_memory_psi(client, server)

        st.success(f"Protocol completed successfully in **{metrics.execution_time_ms:.2f} ms**!")

        col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
        col_m1.metric("Party A Records", result.client_dataset_size)
        col_m2.metric("Party B Records", result.server_dataset_size)
        col_m3.metric("Intersection Matches", result.cardinality)
        col_m4.metric("Wire Bytes Transferred", f"{metrics.total_bytes_wire:,} B")
        col_m5.metric("Crypto Latency", f"{metrics.client_crypto_time_ms + metrics.server_crypto_time_ms:.1f} ms")

        st.subheader("3. Discovered Intersection (Shared Records)")
        if result.cardinality > 0:
            st.markdown(
                '<div class="security-badge">'
                f'✅ <b>{result.cardinality} shared entities identified!</b> Neither party learned anything about the non-matching records.'
                '</div>',
                unsafe_allow_html=True,
            )
            st.table(result.matched_records)
        else:
            st.info("No matching records found in this exchange.")

        if show_points:
            st.subheader("4. Cryptographic Proof & Compressed Point Tables")
            col_p1, col_p2 = st.columns(2)
            with col_p1:
                st.markdown("**Party A Blinded Points ($a \\cdot H(x_i)$):**")
                pt_a_hex = [pt.to_compressed_bytes().hex() for pt in client.client_blinded_points]
                st.code("\n".join(pt_a_hex[:5]), language="text")
            with col_p2:
                st.markdown("**Doubly-Blinded Target Points ($a \\cdot b \\cdot H(x_i)$):**")
                target_hex = [cri.decode("utf-8") for cri in result.matched_cris]
                st.code("\n".join(target_hex) if target_hex else "No matches", language="text")


# ===========================================================================
# TAB 2: STEP-BY-STEP MATHEMATICAL WALKTHROUGH
# ===========================================================================
with tab_walkthrough:
    st.markdown("### Step-by-Step Cryptographic Walkthrough")
    st.markdown(
        "Observe how raw data transforms into elliptic curve points, gets locked by secret keys, "
        "and matches via the commutative property: **$a \\cdot (b \\cdot P) = b \\cdot (a \\cdot P)$**."
    )

    demo_text = st.text_input("Enter a sample record to track:", value="123.456.789-01")
    demo_schema = create_cpf_schema()

    col_s1, col_s2, col_s3 = st.columns(3)

    # Step 0: Normalization
    cri_bytes = demo_schema.serialize_record({"cpf": demo_text})
    with col_s1:
        st.markdown("#### Phase 0: Normalization")
        st.markdown("Cleans formatting & builds length-prefixed CRI:")
        st.code(cri_bytes.decode("utf-8"), language="text")
        st.caption("Length prefix prevents delimiter injection attacks.")

    # Step 1: Hash to Curve
    pt = hash_to_curve(cri_bytes)
    with col_s2:
        st.markdown("#### Phase 1: Hash-to-Curve")
        st.markdown("Maps string to valid point $P(x, y) \\in E(\\mathbb{F}_p)$:")
        st.code(f"x = {hex(pt.x)[:20]}...\ny = {hex(pt.y)[:20]}...", language="text")
        st.caption("secp256k1 verified via Euler's quadratic residue test.")

    # Step 2: Commutative Blinding
    scalar_a = generate_private_scalar()
    scalar_b = generate_private_scalar()

    p_a = blind_point(scalar_a, pt)
    p_ba = blind_point(scalar_b, p_a)

    p_b = blind_point(scalar_b, pt)
    p_ab = blind_point(scalar_a, p_b)

    with col_s3:
        st.markdown("#### Phase 2: Commutative Equality")
        st.markdown("Verifying $b \\cdot (a \\cdot P) == a \\cdot (b \\cdot P)$:")
        st.code(
            f"Path 1 [ba]: {p_ba.to_compressed_bytes().hex()[:24]}...\n"
            f"Path 2 [ab]: {p_ab.to_compressed_bytes().hex()[:24]}...\n"
            f"EQUAL? {p_ba == p_ab} ✅",
            language="text",
        )
        st.caption("Both paths yield the exact same 33-byte compressed point!")


# ===========================================================================
# TAB 3: SCHEMA DESIGNER & CRI INSPECTOR
# ===========================================================================
with tab_schema:
    st.markdown("### Interactive Schema Designer")
    st.markdown(
        "Design custom matching agreements between organizations and inspect the canonical "
        "handshake fingerprint."
    )

    col_sc1, col_sc2 = st.columns([1, 1])

    with col_sc1:
        custom_id = st.text_input("Schema Identifier:", value="consortium_fraud_v1")
        st.markdown("**Add Schema Fields:**")

        f1_name = st.text_input("Field 1 Name:", value="org_id")
        f1_norm = st.selectbox("Field 1 Normalizer:", ["alphanumeric", "text_nfkd", "digits_only"])

        f2_name = st.text_input("Field 2 Name:", value="tax_code")
        f2_norm = st.selectbox("Field 2 Normalizer:", ["cnpj", "cpf", "digits_only"])

        custom_schema = create_custom_schema(
            schema_id=custom_id,
            field_specs=[
                {"name": f1_name, "normalizer": f1_norm},
                {"name": f2_name, "normalizer": f2_norm},
            ],
        )

    with col_sc2:
        st.markdown("#### Schema Handshake Fingerprint")
        st.markdown("This SHA-256 fingerprint is verified during the session handshake:")
        st.code(custom_schema.fingerprint(), language="text")

        st.markdown("#### Test Record CRI Serialization")
        val1 = st.text_input(f"Value for {f1_name}:", value=" bank-br-01 ")
        val2 = st.text_input(f"Value for {f2_name}:", value=" 12.ABC.345/0001-88 ")

        if val1 and val2:
            test_cri = custom_schema.serialize_record({f1_name: val1, f2_name: val2})
            st.markdown("**Generated Canonical Record Identifier (CRI):**")
            st.code(test_cri.decode("utf-8"), language="text")
            st.caption("Sorted alphabetically: field_name:length:normalized_value")
