"""
Tabular data ingestion adapters for SecureMatch.

Reads structured datasets (Python dicts, CSV files, JSON payloads) and converts
rows into Canonical Record Identifier (CRI) byte arrays ready for cryptographic operations.
"""

from __future__ import annotations
import csv
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple
from .schema import Schema


def ingest_records(
    records: Iterable[Dict[str, Any]],
    schema: Schema,
    skip_invalid: bool = False,
) -> Tuple[List[bytes], List[Tuple[int, str]]]:
    """
    Transforms an iterable of dictionary records into CRI byte payloads.

    Args:
        records: Stream of dictionary records.
        schema: Target Schema specification.
        skip_invalid: If True, skips records that fail validation instead of raising an error.

    Returns:
        Tuple of (list of CRI byte payloads, list of (row_index, error_message) for failed rows).
    """
    cri_list: List[bytes] = []
    errors: List[Tuple[int, str]] = []

    for idx, row in enumerate(records):
        try:
            cri_bytes = schema.serialize_record(row)
            cri_list.append(cri_bytes)
        except Exception as e:
            if skip_invalid:
                errors.append((idx, str(e)))
            else:
                raise ValueError(f"Error at record index {idx}: {e}") from e

    return cri_list, errors


def ingest_csv(
    file_path: str,
    schema: Schema,
    field_mapping: Optional[Dict[str, str]] = None,
    delimiter: str = ",",
    skip_invalid: bool = False,
) -> Tuple[List[bytes], List[Tuple[int, str]]]:
    """
    Ingests records from a CSV file.

    Args:
        file_path: Path to CSV file.
        schema: Target Schema specification.
        field_mapping: Optional mapping from CSV column header to schema field name.
                       Example: {"CPF_CLIENTE": "cpf"}
        delimiter: CSV field delimiter (default ',').
        skip_invalid: Whether to skip rows failing validation.

    Returns:
        Tuple of (list of valid CRI byte payloads, list of failed row errors).
    """
    records: List[Dict[str, Any]] = []

    with open(file_path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        for row in reader:
            if field_mapping:
                mapped_row = {field_mapping.get(k, k): v for k, v in row.items()}
            else:
                mapped_row = row
            records.append(mapped_row)

    return ingest_records(records, schema, skip_invalid=skip_invalid)


def ingest_json(
    file_path: str,
    schema: Schema,
    skip_invalid: bool = False,
) -> Tuple[List[bytes], List[Tuple[int, str]]]:
    """
    Ingests records from a JSON file (expecting a JSON array of record objects).
    """
    with open(file_path, mode="r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Expected JSON root to be a list of records, got {type(data).__name__}.")

    return ingest_records(data, schema, skip_invalid=skip_invalid)
