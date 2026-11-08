"""
Data normalization and validation engine for SecureMatch.

Ensures that typographical variations, diacritics, punctuation, and format differences
in input records normalize to identical canonical representations to prevent false negatives.
"""

from __future__ import annotations
import re
import unicodedata
from typing import Callable, Dict, Optional


def normalize_text_nfkd(text: str) -> str:
    """
    Applies Unicode NFKD (Compatibility Decomposition), strips diacritics/accents,
    folds case to lowercase, and collapses contiguous whitespace to a single space.
    Example: '  São   PAULO  ' -> 'sao paulo'
    """
    if text is None:
        return ""
    # Normalize unicode to decomposed form (accents separated from base glyphs)
    decomposed = unicodedata.normalize("NFKD", str(text))
    # Strip non-spacing mark characters (accents / diacritics)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    # Convert to lowercase
    lowered = stripped.lower()
    # Collapse multiple whitespace characters into a single space and strip edges
    collapsed = re.sub(r"\s+", " ", lowered).strip()
    return collapsed


def normalize_digits_only(value: str) -> str:
    """Strips all non-digit characters from string. Example: '123.456-78' -> '12345678'."""
    if value is None:
        return ""
    return re.sub(r"\D", "", str(value))


def normalize_alphanumeric(value: str) -> str:
    """
    Strips punctuation and whitespace, preserving only alphanumeric ASCII characters in uppercase.
    Example: 'acc-9988_a ' -> 'ACC9988A'
    """
    if value is None:
        return ""
    cleaned = re.sub(r"[^a-zA-Z0-9]", "", str(value))
    return cleaned.upper()


# ---------------------------------------------------------------------------
# Brazilian CPF Normalization & MOD-11 Checksum Validation
# ---------------------------------------------------------------------------

def validate_cpf_checksum(cpf_digits: str) -> bool:
    """
    Validates standard Brazilian CPF MOD-11 check digits.
    Input must be exactly 11 digits.
    """
    if len(cpf_digits) != 11 or not cpf_digits.isdigit():
        return False
    # Reject repeated sequences like '11111111111'
    if cpf_digits == cpf_digits[0] * 11:
        return False

    # First check digit
    s1 = sum(int(cpf_digits[i]) * (10 - i) for i in range(9))
    r1 = (s1 * 10) % 11
    d1 = 0 if r1 == 10 else r1
    if int(cpf_digits[9]) != d1:
        return False

    # Second check digit
    s2 = sum(int(cpf_digits[i]) * (11 - i) for i in range(10))
    r2 = (s2 * 10) % 11
    d2 = 0 if r2 == 10 else r2
    return int(cpf_digits[10]) == d2


def normalize_cpf(value: str, validate_checksum: bool = False) -> str:
    """
    Normalizes a CPF string: strips non-digits and left-pads with zeros to 11 digits.
    Example: '123.456.789-01' -> '12345678901'
    """
    digits = normalize_digits_only(value)
    if not digits:
        raise ValueError("CPF value cannot be empty.")
    if len(digits) > 11:
        raise ValueError(f"CPF exceeds 11 digits: {digits}")
    # Left-pad to 11 digits if leading zeros were omitted
    padded = digits.zfill(11)
    if validate_checksum and not validate_cpf_checksum(padded):
        raise ValueError(f"Invalid CPF checksum for digits: {padded}")
    return padded


# ---------------------------------------------------------------------------
# Brazilian CNPJ Normalization & MOD-11 Checksum (Numeric & Alphanumeric)
# ---------------------------------------------------------------------------

def _cnpj_char_val(char: str) -> int:
    """
    Computes character value for CNPJ MOD-11:
    ASCII value minus 48 (conforming to Receita Federal Alphanumeric CNPJ spec).
    Digits 0-9 have values 0-9; Letters A-Z have values 17-42.
    """
    return ord(char) - 48


def validate_cnpj_checksum(cnpj_14: str) -> bool:
    """
    Validates MOD-11 checksum for Brazilian CNPJ, supporting BOTH:
    1. Traditional numeric CNPJ (14 digits)
    2. Receita Federal alphanumeric CNPJ (positions 1-12 alphanumeric, 13-14 numeric)
    """
    if len(cnpj_14) != 14:
        return False
    cnpj_upper = cnpj_14.upper()

    # Digits 13 and 14 must be numeric
    if not (cnpj_upper[12].isdigit() and cnpj_upper[13].isdigit()):
        return False

    # Positions 1 to 12 must be alphanumeric (0-9 or A-Z)
    if not all(c.isalnum() for c in cnpj_upper[:12]):
        return False

    # Reject repeated identical characters (e.g. 00000000000000)
    if cnpj_upper == cnpj_upper[0] * 14:
        return False

    weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]

    # First check digit
    s1 = sum(_cnpj_char_val(cnpj_upper[i]) * weights_1[i] for i in range(12))
    r1 = s1 % 11
    d1 = 0 if r1 in (0, 1) else (11 - r1)
    if int(cnpj_upper[12]) != d1:
        return False

    # Second check digit
    s2 = sum(_cnpj_char_val(cnpj_upper[i]) * weights_2[i] for i in range(13))
    r2 = s2 % 11
    d2 = 0 if r2 in (0, 1) else (11 - r2)
    return int(cnpj_upper[13]) == d2


def normalize_cnpj(value: str, validate_checksum: bool = False) -> str:
    """
    Normalizes a CNPJ string supporting BOTH traditional numeric and alphanumeric formats:
    - Strips '.', '/', '-', and spaces.
    - Converts letters to uppercase.
    - Validates length of exactly 14 characters.
    - Checks MOD-11 checksum if requested.
    Example: '12.345.678/0001-95' -> '12345678000195'
             '12.ABC.678/0001-91' -> '12ABC678000191'
    """
    if value is None:
        raise ValueError("CNPJ value cannot be empty.")
    # Strip common formatting punctuation: '.', '/', '-', whitespace
    cleaned = re.sub(r"[\.\/\-\s]", "", str(value)).upper()
    if len(cleaned) != 14:
        raise ValueError(f"CNPJ must be exactly 14 characters, got {len(cleaned)} ('{cleaned}').")
    if not all(c.isalnum() for c in cleaned):
        raise ValueError(f"CNPJ contains invalid non-alphanumeric characters: '{cleaned}'.")
    if validate_checksum and not validate_cnpj_checksum(cleaned):
        raise ValueError(f"Invalid CNPJ checksum for: '{cleaned}'.")
    return cleaned


# ---------------------------------------------------------------------------
# Phone & Geographic Region Normalizers
# ---------------------------------------------------------------------------

def normalize_phone_e164(phone: str, default_country_code: str = "+55") -> str:
    """
    Normalizes phone numbers to standard E.164 international format (+<country><area><number>).
    Example: '(31) 98765-4321' -> '+5531987654321'
             '+55 31 987654321' -> '+5531987654321'
    """
    if phone is None:
        raise ValueError("Phone number cannot be empty.")
    has_plus = str(phone).strip().startswith("+")
    digits = normalize_digits_only(phone)
    if not digits:
        raise ValueError(f"No digits found in phone number: '{phone}'.")

    if has_plus:
        return f"+{digits}"

    # If 10 or 11 digits (Brazilian DDD + number), prepend default country code
    if len(digits) in (10, 11) and default_country_code:
        cc = default_country_code if default_country_code.startswith("+") else f"+{default_country_code}"
        return f"{cc}{digits}"

    return f"+{digits}"


def normalize_region_code(region: str) -> str:
    """
    Normalizes a geographic state or region code (e.g. Brazilian UF 'MG', 'SP', 'RJ').
    Strips whitespace and converts to uppercase ASCII.
    Example: ' mg ' -> 'MG'
    """
    if region is None:
        raise ValueError("Region code cannot be empty.")
    cleaned = re.sub(r"[^a-zA-Z0-9\-]", "", str(region)).upper()
    if not cleaned:
        raise ValueError(f"Invalid region code: '{region}'.")
    return cleaned


# ---------------------------------------------------------------------------
# Date Normalizer
# ---------------------------------------------------------------------------

def normalize_date_iso(date_str: str) -> str:
    """
    Normalizes various date formats into standard ISO-8601 (YYYY-MM-DD).
    Supports 'DD/MM/YYYY', 'DD-MM-YYYY', 'YYYY/MM/DD', 'YYYY-MM-DD'.
    Example: '15/08/1995' -> '1995-08-15'
    """
    if date_str is None:
        raise ValueError("Date string cannot be empty.")
    s = str(date_str).strip()
    # Check YYYY-MM-DD or YYYY/MM/DD
    m_iso = re.match(r"^(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})$", s)
    if m_iso:
        y, m, d = m_iso.groups()
        return f"{int(y):04d}-{int(m):02d}-{int(d):02d}"

    # Check DD/MM/YYYY or DD-MM-YYYY
    m_br = re.match(r"^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})$", s)
    if m_br:
        d, m, y = m_br.groups()
        return f"{int(y):04d}-{int(m):02d}-{int(d):02d}"

    # Fallback to digits only if YYYYMMDD
    digits = normalize_digits_only(s)
    if len(digits) == 8:
        # Assume YYYYMMDD if first 4 digits > 1900
        if int(digits[:4]) > 1900:
            return f"{digits[:4]}-{digits[4:6]}-{digits[6:8]}"
        # Otherwise assume DDMMYYYY
        return f"{digits[4:8]}-{digits[2:4]}-{digits[0:2]}"

    raise ValueError(f"Unrecognized date format: '{date_str}'. Expected YYYY-MM-DD or DD/MM/YYYY.")


# ---------------------------------------------------------------------------
# Normalizer Registry
# ---------------------------------------------------------------------------

NORMALIZER_REGISTRY: Dict[str, Callable[[str], str]] = {
    "text_nfkd": normalize_text_nfkd,
    "digits_only": normalize_digits_only,
    "alphanumeric": normalize_alphanumeric,
    "cpf": lambda v: normalize_cpf(v, validate_checksum=False),
    "cpf_strict": lambda v: normalize_cpf(v, validate_checksum=True),
    "cnpj": lambda v: normalize_cnpj(v, validate_checksum=False),
    "cnpj_strict": lambda v: normalize_cnpj(v, validate_checksum=True),
    "phone_e164": normalize_phone_e164,
    "region": normalize_region_code,
    "date_iso": normalize_date_iso,
}


def get_normalizer(name: str) -> Callable[[str], str]:
    """Retrieves a registered normalizer by name."""
    if name not in NORMALIZER_REGISTRY:
        raise KeyError(
            f"Unknown normalizer '{name}'. Registered options: {list(NORMALIZER_REGISTRY.keys())}"
        )
    return NORMALIZER_REGISTRY[name]
