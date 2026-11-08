"""
Schema specification, field normalization, and canonical record identification.
"""

from .normalizers import (
    normalize_text_nfkd,
    normalize_digits_only,
    normalize_alphanumeric,
    normalize_cpf,
    validate_cpf_checksum,
    normalize_cnpj,
    validate_cnpj_checksum,
    normalize_phone_e164,
    normalize_region_code,
    normalize_date_iso,
    get_normalizer,
    NORMALIZER_REGISTRY,
)
from .schema import (
    FieldDefinition,
    Schema,
    create_cpf_schema,
    create_cnpj_schema,
    create_phone_region_schema,
    create_demographic_schema,
    create_internal_id_schema,
    create_custom_schema,
)
from .ingestion import (
    ingest_records,
    ingest_csv,
    ingest_json,
)

__all__ = [
    "normalize_text_nfkd",
    "normalize_digits_only",
    "normalize_alphanumeric",
    "normalize_cpf",
    "validate_cpf_checksum",
    "normalize_cnpj",
    "validate_cnpj_checksum",
    "normalize_phone_e164",
    "normalize_region_code",
    "normalize_date_iso",
    "get_normalizer",
    "NORMALIZER_REGISTRY",
    "FieldDefinition",
    "Schema",
    "create_cpf_schema",
    "create_cnpj_schema",
    "create_phone_region_schema",
    "create_demographic_schema",
    "create_internal_id_schema",
    "create_custom_schema",
    "ingest_records",
    "ingest_csv",
    "ingest_json",
]
