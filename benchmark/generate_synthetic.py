"""
Synthetic Database Generator for SecureMatch testing and benchmarking.

Generates realistic dataset pairs for Party A and Party B with:
1. Configurable match modes:
   - 'with_match': Datasets share a controllable subset of records.
   - 'no_match': Disjoint datasets (0% overlap).
2. Key types:
   - 'cpf': Brazilian Individual Tax ID (with dirty punctuation/spaces).
   - 'cnpj': Brazilian Corporate ID (mixing traditional numeric & modern alphanumeric CNPJs).
   - 'phone_region': Composite key (E.164 phone + Brazilian UF).
   - 'custom_random': Randomly synthesizes a 2 to 4 column composite key.
3. Realistic dirty-data injection (casing, diacritics, format differences)
   to test canonical normalization resilience.
"""

from __future__ import annotations
import argparse
import csv
import io
import os
import random
import string
from typing import Any, Dict, List, Optional, Tuple

# Sample pools for realistic synthetic demographic and clinical data
FIRST_NAMES = [
    "João", "Maria", "José", "Ana", "Carlos", "Fernanda", "Paulo", "Mariana",
    "Lucas", "Beatriz", "Gabriel", "Juliana", "Rodrigo", "Camila", "Mateus",
    "Larissa", "Felipe", "Aline", "Guilherme", "Patrícia", "Thiago", "Letícia"
]

LAST_NAMES = [
    "Silva", "Santos", "Oliveira", "Souza", "Rodrigues", "Ferreira", "Alves",
    "Pereira", "Lima", "Gomes", "Costa", "Ribeiro", "Martins", "Carvalho",
    "Almeida", "Lopes", "Soares", "Fernandes", "Vieira", "Barbosa", "Rocha"
]

DIAGNOSES = [
    "Diabetes Tipo 2", "Hipertensão Essencial", "Asma Brônquica", "Arritmia Cardíaca",
    "Fratura de Fêmur", "Pneumonia Viral", "Enxaqueca Crônica", "Gastrite Aguda",
    "Dermatite Atópica", "Insuficiência Cardíaca", "Hipotireoidismo", "COVID-19 Leve"
]

INSURANCES = [
    "Unimed", "Bradesco Saúde", "SulAmérica", "Amil", "NotreDame Intermédica",
    "Porto Seguro", "Allianz Saúde", "Golden Cross", "Particular"
]

BRAZILIAN_UFS = [
    "MG", "SP", "RJ", "ES", "BA", "PR", "SC", "RS", "PE", "CE", "GO", "DF"
]

COMPANIES = [
    "Alpha Tecnologia", "Beta Consultoria", "Gama Logística", "Delta Serviços",
    "Inova Soluções", "Minas Mineração", "Brasil Distribuidora", "Norte Alimentos"
]

STATUSES = ["Ativo", "Pendente", "Auditoria", "Regular", "Investigação", "Bloqueado"]


def generate_valid_cpf_digits(seed_int: int) -> str:
    """Generates an 11-digit CPF with valid MOD-11 check digits based on an integer seed."""
    rng = random.Random(seed_int)
    base_9 = [rng.randint(0, 9) for _ in range(9)]
    # Check digit 1
    s1 = sum(base_9[i] * (10 - i) for i in range(9))
    r1 = (s1 * 10) % 11
    d1 = 0 if r1 == 10 else r1
    # Check digit 2
    s2 = sum(base_9[i] * (11 - i) for i in range(9)) + (d1 * 2)
    r2 = (s2 * 10) % 11
    d2 = 0 if r2 == 10 else r2
    return "".join(map(str, base_9)) + str(d1) + str(d2)


def generate_valid_cnpj_digits(seed_int: int, alphanumeric: bool = False) -> str:
    """
    Generates a 14-character CNPJ with valid MOD-11 check digits.
    Supports traditional numeric or Receita Federal alphanumeric format.
    """
    rng = random.Random(seed_int)
    if alphanumeric:
        # Characters 1-12 can be letters A-Z or digits 0-9
        chars_pool = string.digits + string.ascii_uppercase
        base_12 = "".join(rng.choice(chars_pool) for _ in range(12))
    else:
        base_12 = "".join(str(rng.randint(0, 9)) for _ in range(12))

    def _val(ch: str) -> int:
        return ord(ch) - 48

    weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]

    s1 = sum(_val(base_12[i]) * weights_1[i] for i in range(12))
    r1 = s1 % 11
    d1 = 0 if r1 in (0, 1) else (11 - r1)

    s2 = sum(_val(base_12[i]) * weights_2[i] for i in range(12)) + (d1 * 2)
    r2 = s2 % 11
    d2 = 0 if r2 in (0, 1) else (11 - r2)

    return f"{base_12}{d1}{d2}"


def inject_dirty_cpf(cpf_11: str, style: int) -> str:
    """Injects formatting discrepancies into a CPF string."""
    if style == 0:
        # Formatted: 123.456.789-01
        return f"{cpf_11[:3]}.{cpf_11[3:6]}.{cpf_11[6:9]}-{cpf_11[9:]}"
    elif style == 1:
        # Extra whitespace: ' 12345678901 '
        return f"  {cpf_11}  "
    elif style == 2:
        # Dash only: 123456789-01
        return f"{cpf_11[:9]}-{cpf_11[9:]}"
    return cpf_11


def inject_dirty_cnpj(cnpj_14: str, style: int) -> str:
    """Injects formatting discrepancies into a CNPJ string."""
    if style == 0:
        # Standard mask: 12.345.678/0001-95
        return f"{cnpj_14[:2]}.{cnpj_14[2:5]}.{cnpj_14[5:8]}/{cnpj_14[8:12]}-{cnpj_14[12:]}"
    elif style == 1:
        return f" {cnpj_14} "
    return cnpj_14


def generate_dataset_pair(
    key_type: str = "cpf",
    n_a: int = 15,
    n_b: int = 15,
    match_mode: str = "with_match",
    match_count: Optional[int] = None,
    random_seed: int = 42,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Generates a pair of synthetic datasets for Organization A and Organization B.

    Args:
        key_type: 'cpf', 'cnpj', 'phone_region', or 'custom_random'.
        n_a: Number of records for Organization A.
        n_b: Number of records for Organization B.
        match_mode: 'with_match' or 'no_match'.
        match_count: Number of shared records if match_mode is 'with_match'.
        random_seed: Reproducibility seed.

    Returns:
        Tuple of (dataset_a, dataset_b, metadata_dict).
    """
    rng = random.Random(random_seed)

    if match_mode == "no_match":
        actual_matches = 0
    else:
        if match_count is None:
            actual_matches = min(n_a, n_b) // 2
        else:
            actual_matches = min(match_count, n_a, n_b)

    metadata: Dict[str, Any] = {
        "key_type": key_type,
        "match_mode": match_mode,
        "expected_matches": actual_matches,
        "size_a": n_a,
        "size_b": n_b,
    }

    # -----------------------------------------------------------------------
    # 1. STANDARD CPF MODE
    # -----------------------------------------------------------------------
    if key_type == "cpf":
        total_unique = n_a + n_b - actual_matches
        all_cpfs = [generate_valid_cpf_digits(random_seed * 1000 + i) for i in range(total_unique)]

        shared_pool = all_cpfs[:actual_matches]
        only_a_pool = all_cpfs[actual_matches : n_a]
        only_b_pool = all_cpfs[n_a : total_unique]

        list_a_cpfs = shared_pool + only_a_pool
        list_b_cpfs = shared_pool + only_b_pool

        rng.shuffle(list_a_cpfs)
        rng.shuffle(list_b_cpfs)

        data_a = [
            {
                "id_paciente": f"HOSP-A-{i+1:03d}",
                "cpf_titular": inject_dirty_cpf(c, i % 3),
                "nome_paciente": f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}",
                "diagnostico": rng.choice(DIAGNOSES),
                "leito": f"A-{rng.randint(100, 399)}",
            }
            for i, c in enumerate(list_a_cpfs)
        ]

        data_b = [
            {
                "reg_atendimento": f"REG-B-{j+1:03d}",
                "doc_cpf": inject_dirty_cpf(c, (j + 1) % 3),
                "data_admissao": f"2026-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
                "convenio": rng.choice(INSURANCES),
                "custo_estimado": f"R$ {rng.randint(250, 4800)},00",
            }
            for j, c in enumerate(list_b_cpfs)
        ]

        metadata["key_columns_a"] = ["cpf_titular"]
        metadata["key_columns_b"] = ["doc_cpf"]
        metadata["schema_id"] = "br_cpf_v1"
        return data_a, data_b, metadata

    # -----------------------------------------------------------------------
    # 2. STANDARD CNPJ MODE (Numeric & Alphanumeric)
    # -----------------------------------------------------------------------
    elif key_type == "cnpj":
        total_unique = n_a + n_b - actual_matches
        all_cnpjs = [
            generate_valid_cnpj_digits(random_seed * 2000 + i, alphanumeric=(i % 2 == 1))
            for i in range(total_unique)
        ]

        shared_pool = all_cnpjs[:actual_matches]
        only_a_pool = all_cnpjs[actual_matches : n_a]
        only_b_pool = all_cnpjs[n_a : total_unique]

        list_a_cnpjs = shared_pool + only_a_pool
        list_b_cnpjs = shared_pool + only_b_pool

        rng.shuffle(list_a_cnpjs)
        rng.shuffle(list_b_cnpjs)

        data_a = [
            {
                "fornecedor_id": f"FORN-{i+1:03d}",
                "cnpj_fornecedor": inject_dirty_cnpj(c, i % 2),
                "razao_social": f"{rng.choice(COMPANIES)} LTDA",
                "categoria": "Contratado",
                "score": rng.randint(400, 990),
            }
            for i, c in enumerate(list_a_cnpjs)
        ]

        data_b = [
            {
                "auditoria_cod": f"AUD-B-{j+1:03d}",
                "tax_id": inject_dirty_cnpj(c, (j + 1) % 2),
                "cidade": rng.choice(["Belo Horizonte", "São Paulo", "Rio de Janeiro", "Curitiba"]),
                "status_compliance": rng.choice(STATUSES),
                "limite_credito": f"R$ {rng.randint(10, 500) * 1000},00",
            }
            for j, c in enumerate(list_b_cnpjs)
        ]

        metadata["key_columns_a"] = ["cnpj_fornecedor"]
        metadata["key_columns_b"] = ["tax_id"]
        metadata["schema_id"] = "br_cnpj_v1"
        return data_a, data_b, metadata

    # -----------------------------------------------------------------------
    # 3. COMPOSITE: PHONE + REGION MODE
    # -----------------------------------------------------------------------
    elif key_type == "phone_region":
        total_unique = n_a + n_b - actual_matches
        all_pairs = [
            (f"319{rng.randint(10000000, 99999999)}", rng.choice(BRAZILIAN_UFS))
            for _ in range(total_unique)
        ]

        shared_pool = all_pairs[:actual_matches]
        only_a_pool = all_pairs[actual_matches : n_a]
        only_b_pool = all_pairs[n_a : total_unique]

        list_a = shared_pool + only_a_pool
        list_b = shared_pool + only_b_pool

        rng.shuffle(list_a)
        rng.shuffle(list_b)

        data_a = [
            {
                "cliente_id": f"CLI-A-{i+1:03d}",
                "telefone_contato": f"({p[:2]}) {p[2:7]}-{p[7:]}" if i % 2 == 0 else f"+55{p}",
                "uf_estado": u.lower() if i % 2 == 0 else u,  # dirty case
                "nome_titular": f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}",
                "saldo": f"R$ {rng.randint(50, 1500)},00",
            }
            for i, (p, u) in enumerate(list_a)
        ]

        data_b = [
            {
                "lead_num": f"LEAD-B-{j+1:03d}",
                "celular": f"+55{p}" if j % 2 == 0 else f"({p[:2]}) {p[2:7]}-{p[7:]}",
                "regiao": u,
                "canal": rng.choice(["WhatsApp", "Email", "App", "Presencial"]),
                "campanha": "Campanha 2026/2",
            }
            for j, (p, u) in enumerate(list_b)
        ]

        metadata["key_columns_a"] = ["telefone_contato", "uf_estado"]
        metadata["key_columns_b"] = ["celular", "regiao"]
        metadata["schema_id"] = "phone_region_v1"
        return data_a, data_b, metadata

    # -----------------------------------------------------------------------
    # 4. RANDOM CUSTOM COMPOSITE KEY MODE (2 to 4 COLUMNS)
    # -----------------------------------------------------------------------
    else:
        # Candidate pool of possible fields
        available_fields = [
            {"name": "birth_date", "type": "date_iso", "gen": lambda: f"19{rng.randint(60,99)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"},
            {"name": "full_name", "type": "text_nfkd", "gen": lambda: f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"},
            {"name": "postal_code", "type": "digits_only", "gen": lambda: f"30{rng.randint(100, 999)}-{rng.randint(100, 999)}"},
            {"name": "patient_category", "type": "alphanumeric", "gen": lambda: f"CAT-{rng.randint(10, 99)}"},
        ]

        # Choose 2 to 4 random fields
        num_fields = rng.randint(2, 4)
        chosen_fields = rng.sample(available_fields, num_fields)
        schema_id = f"random_custom_{num_fields}cols_v1"

        total_unique = n_a + n_b - actual_matches
        all_tuples = [
            tuple(f["gen"]() for f in chosen_fields)
            for _ in range(total_unique)
        ]

        shared_pool = all_tuples[:actual_matches]
        only_a_pool = all_tuples[actual_matches : n_a]
        only_b_pool = all_tuples[n_a : total_unique]

        list_a = shared_pool + only_a_pool
        list_b = shared_pool + only_b_pool

        rng.shuffle(list_a)
        rng.shuffle(list_b)

        # Field names in Organization A CSV vs Organization B CSV
        col_names_a = [f["name"] + "_col_a" for f in chosen_fields]
        col_names_b = [f["name"] + "_col_b" for f in chosen_fields]

        data_a = []
        for i, tup in enumerate(list_a):
            row = {"id_org_a": f"ORG-A-{i+1:03d}"}
            for f_idx, val in enumerate(tup):
                row[col_names_a[f_idx]] = val
            row["obs_clinica"] = rng.choice(DIAGNOSES)
            data_a.append(row)

        data_b = []
        for j, tup in enumerate(list_b):
            row = {"id_org_b": f"ORG-B-{j+1:03d}"}
            for f_idx, val in enumerate(tup):
                # Inject dirty casing on text fields for Organization B
                raw_v = tup[f_idx]
                if chosen_fields[f_idx]["type"] == "text_nfkd":
                    raw_v = raw_v.upper() if j % 2 == 0 else f"  {raw_v}  "
                row[col_names_b[f_idx]] = raw_v
            row["tipo_atendimento"] = rng.choice(INSURANCES)
            data_b.append(row)

        metadata["key_columns_a"] = col_names_a
        metadata["key_columns_b"] = col_names_b
        metadata["chosen_fields"] = [{"name": f["name"], "normalizer": f["type"]} for f in chosen_fields]
        metadata["schema_id"] = schema_id
        return data_a, data_b, metadata


def save_dataset_to_csv_string(records: List[Dict[str, Any]]) -> str:
    """Serializes a list of dictionaries to a CSV string."""
    if not records:
        return ""
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(records[0].keys()))
    writer.writeheader()
    writer.writerows(records)
    return out.getvalue()


# ---------------------------------------------------------------------------
# CLI Runner for Automated Tests & Benchmarks
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureMatch Synthetic Database Generator")
    parser.add_argument("--key-type", choices=["cpf", "cnpj", "phone_region", "custom_random"], default="cpf")
    parser.add_argument("--match-mode", choices=["with_match", "no_match"], default="with_match")
    parser.add_argument("--size-a", type=int, default=20)
    parser.add_argument("--size-b", type=int, default=20)
    parser.add_argument("--matches", type=int, default=10)
    parser.add_argument("--out-dir", type=str, default=".")

    args = parser.parse_args()

    da, db, meta = generate_dataset_pair(
        key_type=args.key_type,
        n_a=args.size_a,
        n_b=args.size_b,
        match_mode=args.match_mode,
        match_count=args.matches,
    )

    file_a = os.path.join(args.out_dir, f"hospital_a_{args.key_type}_{args.match_mode}.csv")
    file_b = os.path.join(args.out_dir, f"hospital_b_{args.key_type}_{args.match_mode}.csv")

    with open(file_a, "w", encoding="utf-8") as fa:
        fa.write(save_dataset_to_csv_string(da))
    with open(file_b, "w", encoding="utf-8") as fb:
        fb.write(save_dataset_to_csv_string(db))

    print(f"Generated synthetic dataset pair:")
    print(f"  Party A: {file_a} ({len(da)} rows)")
    print(f"  Party B: {file_b} ({len(db)} rows)")
    print(f"  Mode: {args.match_mode} (Expected matches: {meta['expected_matches']})")
