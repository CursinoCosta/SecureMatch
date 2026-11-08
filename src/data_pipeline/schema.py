"""
Declarative Match Key Schema and Canonical Record Identifier (CRI) Engine.

Enables parties to define, negotiate, and agree upon custom single or composite
matching keys (e.g. CPF, CNPJ [numeric or alphanumeric], Phone + Region, Internal Codes).
Implements length-prefixed serialization to eliminate delimiter injection attacks.
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union
from .normalizers import get_normalizer, NORMALIZER_REGISTRY


@dataclass(frozen=True)
class FieldDefinition:
    """Defines a single attribute in a match key schema."""
    name: str
    normalizer: Union[str, List[str]] = "text_nfkd"
    required: bool = True
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").isalnum():
            raise ValueError(f"Field name must be alphanumeric with underscores, got '{self.name}'.")

    def clean_value(self, raw_value: Any) -> str:
        """Applies configured normalizers sequentially to raw field value."""
        if raw_value is None or str(raw_value).strip() == "":
            if self.required:
                raise ValueError(f"Missing required field: '{self.name}'.")
            return ""

        val_str = str(raw_value)
        normalizers_list = [self.normalizer] if isinstance(self.normalizer, str) else self.normalizer
        for norm_name in normalizers_list:
            norm_func = get_normalizer(norm_name)
            val_str = norm_func(val_str)
        return val_str


@dataclass
class Schema:
    """
    Defines a complete matching agreement schema between two parties.
    Can represent single-field IDs or composite multi-attribute tuples.
    """
    schema_id: str
    fields: List[FieldDefinition]
    description: str = ""

    def __post_init__(self) -> None:
        if not self.fields:
            raise ValueError("Schema must contain at least one field definition.")
        # Ensure field names are unique
        field_names = [f.name for f in self.fields]
        if len(field_names) != len(set(field_names)):
            raise ValueError(f"Duplicate field names detected in schema: {field_names}")

    def get_field_map(self) -> Dict[str, FieldDefinition]:
        """Returns map of field_name -> FieldDefinition."""
        return {f.name: f for f in self.fields}

    def canonical_dict(self) -> Dict[str, Any]:
        """
        Returns a sorted, deterministic dictionary representation
        used for schema fingerprinting and protocol negotiation.
        """
        sorted_fields = sorted(self.fields, key=lambda f: f.name)
        return {
            "schema_id": self.schema_id,
            "fields": [
                {
                    "name": f.name,
                    "normalizer": [f.normalizer] if isinstance(f.normalizer, str) else f.normalizer,
                    "required": f.required,
                }
                for f in sorted_fields
            ],
        }

    def fingerprint(self) -> str:
        """
        Computes SHA-256 hexadecimal digest of canonical schema definition.
        Both parties verify this hash during session handshake.
        """
        canonical_json = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def serialize_record(self, record: Dict[str, Any]) -> bytes:
        """
        Serializes a record dictionary into a length-prefixed Canonical Record Identifier (CRI).

        Grammar:
        field_1:len_1:val_1|field_2:len_2:val_2

        Rules:
        1. Fields are strictly sorted in alphabetical order by name.
        2. Values are normalized.
        3. Byte lengths are prefixed to prevent delimiter collision attacks.
        """
        # Sort fields alphabetically to ensure determinism across parties
        sorted_field_defs = sorted(self.fields, key=lambda f: f.name)
        cri_parts: List[str] = []

        for fdef in sorted_field_defs:
            raw_val = record.get(fdef.name)
            cleaned_val = fdef.clean_value(raw_val)

            # Measure length in UTF-8 bytes (not character count)
            val_bytes = cleaned_val.encode("utf-8")
            val_len = len(val_bytes)

            cri_parts.append(f"{fdef.name}:{val_len}:{cleaned_val}")

        canonical_str = "|".join(cri_parts)
        return canonical_str.encode("utf-8")

    def is_compatible(self, other: "Schema") -> bool:
        """
        Verifies if another schema is cryptographically compatible
        (has identical fields, normalizers, and requirements).
        """
        return self.fingerprint() == other.fingerprint()


# ---------------------------------------------------------------------------
# Pre-Built Standard Schema Factories
# ---------------------------------------------------------------------------

def create_cpf_schema(schema_id: str = "br_cpf_v1", strict: bool = False) -> Schema:
    """Pre-built schema for Brazilian CPF."""
    norm = "cpf_strict" if strict else "cpf"
    return Schema(
        schema_id=schema_id,
        fields=[FieldDefinition(name="cpf", normalizer=norm, required=True, description="Brazilian CPF")],
        description="Standard single-key Brazilian CPF schema.",
    )


def create_cnpj_schema(schema_id: str = "br_cnpj_v1", strict: bool = False) -> Schema:
    """Pre-built schema for Brazilian CNPJ (accepts numeric and alphanumeric CNPJs)."""
    norm = "cnpj_strict" if strict else "cnpj"
    return Schema(
        schema_id=schema_id,
        fields=[
            FieldDefinition(
                name="cnpj",
                normalizer=norm,
                required=True,
                description="Brazilian CNPJ (numeric or alphanumeric)",
            )
        ],
        description="Standard Brazilian CNPJ schema accepting numeric or alphanumeric formats.",
    )


def create_phone_region_schema(schema_id: str = "phone_region_v1") -> Schema:
    """Pre-built composite schema: Standardized E.164 phone + Geographic Region (UF)."""
    return Schema(
        schema_id=schema_id,
        fields=[
            FieldDefinition(name="phone", normalizer="phone_e164", required=True, description="E.164 Phone"),
            FieldDefinition(name="region", normalizer="region", required=True, description="State/Region code"),
        ],
        description="Composite key matching phone number and geographic state.",
    )


def create_demographic_schema(schema_id: str = "demographic_trio_v1") -> Schema:
    """Pre-built composite schema: Date of Birth + Full Name + Region."""
    return Schema(
        schema_id=schema_id,
        fields=[
            FieldDefinition(name="dob", normalizer="date_iso", required=True, description="Date of birth YYYY-MM-DD"),
            FieldDefinition(name="name", normalizer="text_nfkd", required=True, description="Normalized full name"),
            FieldDefinition(name="region", normalizer="region", required=True, description="Geographic region"),
        ],
        description="Composite demographic trio key.",
    )


def create_internal_id_schema(
    id_field_name: str = "account_id",
    schema_id: str = "internal_id_v1",
) -> Schema:
    """Pre-built schema for proprietary internal account / customer codes."""
    return Schema(
        schema_id=schema_id,
        fields=[
            FieldDefinition(
                name=id_field_name,
                normalizer="alphanumeric",
                required=True,
                description=f"Internal ID: {id_field_name}",
            )
        ],
        description="Proprietary alphanumeric account/customer code schema.",
    )


def create_custom_schema(
    schema_id: str,
    field_specs: List[Dict[str, Any]],
    description: str = "",
) -> Schema:
    """
    Constructs a custom schema dynamically from dictionary specifications.
    Example field_specs:
    [
        {"name": "org_code", "normalizer": "alphanumeric"},
        {"name": "user_hash", "normalizer": "text_nfkd"}
    ]
    """
    field_defs: List[FieldDefinition] = []
    for spec in field_specs:
        field_defs.append(
            FieldDefinition(
                name=spec["name"],
                normalizer=spec.get("normalizer", "text_nfkd"),
                required=spec.get("required", True),
                description=spec.get("description", ""),
            )
        )
    return Schema(schema_id=schema_id, fields=field_defs, description=description)
