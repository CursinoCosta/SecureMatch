"""
Unit tests for the SecureMatch data normalization and schema pipeline.
"""

import os
import tempfile
import unittest
from src.data_pipeline.normalizers import (
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
)
from src.data_pipeline.schema import (
    FieldDefinition,
    Schema,
    create_cpf_schema,
    create_cnpj_schema,
    create_phone_region_schema,
    create_demographic_schema,
    create_internal_id_schema,
    create_custom_schema,
)
from src.data_pipeline.ingestion import (
    ingest_records,
    ingest_csv,
    ingest_json,
)


class TestNormalizers(unittest.TestCase):
    """Tests for individual field normalization functions."""

    def test_text_nfkd_cleaning(self):
        """Tests that accents, mixed casing, and messy spacing normalize canonically."""
        raw_samples = [
            "  São   PAULO  ",
            "sao paulo",
            "SÃO PAULO",
            "  sÃo  paulo\n",
        ]
        expected = "sao paulo"
        for sample in raw_samples:
            self.assertEqual(normalize_text_nfkd(sample), expected)

        # Complex accents and names
        self.assertEqual(normalize_text_nfkd("João d'Ávila & Açaí"), "joao d'avila & acai")

    def test_cpf_normalization(self):
        """Tests standard Brazilian CPF formatting and padding."""
        self.assertEqual(normalize_cpf("123.456.789-01"), "12345678901")
        self.assertEqual(normalize_cpf("  12345678901  "), "12345678901")
        # Leading zero padding
        self.assertEqual(normalize_cpf("12345678"), "00012345678")

        # Invalid CPF length
        with self.assertRaises(ValueError):
            normalize_cpf("12345678901234")

    def test_cpf_checksum_validation(self):
        """Tests MOD-11 checksum on valid and invalid CPFs."""
        valid_cpf = "52998224725"
        self.assertTrue(validate_cpf_checksum(valid_cpf))
        self.assertEqual(normalize_cpf("529.982.247-25", validate_checksum=True), valid_cpf)

        invalid_cpf = "52998224726"
        self.assertFalse(validate_cpf_checksum(invalid_cpf))
        with self.assertRaises(ValueError):
            normalize_cpf(invalid_cpf, validate_checksum=True)

    def test_cnpj_normalization_numeric(self):
        """Tests standard numeric CNPJ normalization and checksum."""
        # Valid standard numeric CNPJ (Banco do Brasil: 00.000.000/0001-91)
        valid_numeric = "00.000.000/0001-91"
        cleaned = normalize_cnpj(valid_numeric, validate_checksum=True)
        self.assertEqual(cleaned, "00000000000191")

    def test_cnpj_normalization_alphanumeric(self):
        """
        Tests modern Receita Federal Alphanumeric CNPJ normalization and checksum.
        Alphanumeric CNPJ format: 12 alphanumeric characters + 2 numeric check digits.
        """
        # Test cleaning of formatted alphanumeric CNPJ
        raw_alphanumeric = "12.ABC.345/0001-08"
        cleaned = normalize_cnpj(raw_alphanumeric, validate_checksum=False)
        self.assertEqual(cleaned, "12ABC345000108")
        self.assertEqual(len(cleaned), 14)

        # Checksum algorithm validation test vector
        # With base '12ABC3450001':
        # Weights_1 = [5,4,3,2,9,8,7,6,5,4,3,2]
        # Char values (ASCII - 48):
        # '1'->1, '2'->2, 'A'->17, 'B'->18, 'C'->19, '3'->3, '4'->4, '5'->5, '0'->0, '0'->0, '0'->0, '1'->1
        # Sum1 = 1*5 + 2*4 + 17*3 + 18*2 + 19*9 + 3*8 + 4*7 + 5*6 + 0*5 + 0*4 + 0*3 + 1*2
        # Sum1 = 5 + 8 + 51 + 36 + 171 + 24 + 28 + 30 + 0 + 0 + 0 + 2 = 355
        # 355 % 11 = 3 -> d1 = 11 - 3 = 8.
        # Now with 13 chars including d1=8:
        # Weights_2 = [6,5,4,3,2,9,8,7,6,5,4,3,2]
        # Sum2 = 1*6 + 2*5 + 17*4 + 18*3 + 19*2 + 3*9 + 4*8 + 5*7 + 0*6 + 0*5 + 0*4 + 1*3 + 8*2
        # Sum2 = 6 + 10 + 68 + 54 + 38 + 27 + 32 + 35 + 0 + 0 + 0 + 3 + 16 = 289
        # 289 % 11 = 3 -> d2 = 11 - 3 = 8.
        valid_alpha_cnpj = "12ABC345000188"
        self.assertTrue(validate_cnpj_checksum(valid_alpha_cnpj))
        self.assertEqual(normalize_cnpj("12.ABC.345/0001-88", validate_checksum=True), valid_alpha_cnpj)

        # Invalid checksum rejection
        invalid_alpha_cnpj = "12ABC345000199"
        self.assertFalse(validate_cnpj_checksum(invalid_alpha_cnpj))
        with self.assertRaises(ValueError):
            normalize_cnpj(invalid_alpha_cnpj, validate_checksum=True)

    def test_phone_normalization(self):
        """Tests Brazilian phone normalization to E.164."""
        self.assertEqual(normalize_phone_e164("(31) 98765-4321"), "+5531987654321")
        self.assertEqual(normalize_phone_e164("+55 11 91234 5678"), "+5511912345678")
        self.assertEqual(normalize_phone_e164("+1 415 555 2671"), "+14155552671")

    def test_region_normalization(self):
        """Tests geographic region code normalization."""
        self.assertEqual(normalize_region_code(" mg "), "MG")
        self.assertEqual(normalize_region_code("SP"), "SP")

    def test_date_iso_normalization(self):
        """Tests date string conversion to YYYY-MM-DD."""
        self.assertEqual(normalize_date_iso("15/08/1995"), "1995-08-15")
        self.assertEqual(normalize_date_iso("1995-08-15"), "1995-08-15")
        self.assertEqual(normalize_date_iso("19950815"), "1995-08-15")


class TestSchemaAndCRI(unittest.TestCase):
    """Tests for Schema specification, CRI serialization, and negotiation."""

    def test_single_key_cri_serialization(self):
        """Single key schema produces deterministic length-prefixed bytes."""
        schema = create_cpf_schema()
        record = {"cpf": "123.456.789-01"}
        cri_bytes = schema.serialize_record(record)
        expected = b"cpf:11:12345678901"
        self.assertEqual(cri_bytes, expected)

    def test_composite_key_deterministic_sorting(self):
        """
        Composite keys MUST be sorted alphabetically by field name
        regardless of input dictionary key order.
        """
        schema = create_phone_region_schema()
        # Order 1: phone first
        rec1 = {"phone": "(31) 98765-4321", "region": "mg"}
        # Order 2: region first
        rec2 = {"region": "MG", "phone": "31987654321"}

        cri1 = schema.serialize_record(rec1)
        cri2 = schema.serialize_record(rec2)

        # Alphabetical: 'phone' comes before 'region'
        expected = b"phone:14:+5531987654321|region:2:MG"
        self.assertEqual(cri1, expected)
        self.assertEqual(cri2, expected)
        self.assertEqual(cri1, cri2)

    def test_delimiter_injection_resistance(self):
        """
        Input values containing delimiters ':' or '|' must NOT alter
        field parsing because byte lengths are prefixed.
        """
        schema = create_custom_schema(
            "custom_security_test",
            [
                {"name": "company", "normalizer": "text_nfkd"},
                {"name": "tag", "normalizer": "alphanumeric"},
            ],
        )
        # Malicious injection attempt inside company name
        malicious_record = {
            "company": "Fake Corp | tag:5:HACKED",
            "tag": "VALID",
        }
        cri_bytes = schema.serialize_record(malicious_record)
        # Length of "fake corp | tag:5:hacked" is 24 bytes
        expected = b"company:24:fake corp | tag:5:hacked|tag:5:VALID"
        self.assertEqual(cri_bytes, expected)

    def test_schema_fingerprint_and_compatibility(self):
        """Compatible schemas have identical fingerprints; modified ones differ."""
        schema_a = create_cpf_schema(strict=False)
        schema_b = create_cpf_schema(strict=False)
        schema_c = create_cpf_schema(strict=True)

        self.assertEqual(schema_a.fingerprint(), schema_b.fingerprint())
        self.assertTrue(schema_a.is_compatible(schema_b))

        self.assertNotEqual(schema_a.fingerprint(), schema_c.fingerprint())
        self.assertFalse(schema_a.is_compatible(schema_c))


class TestIngestion(unittest.TestCase):
    """Tests for CSV, JSON, and in-memory tabular data ingestion."""

    def test_ingest_records_memory(self):
        """Ingests list of dictionary records."""
        schema = create_cpf_schema()
        records = [
            {"cpf": "111.222.333-44"},
            {"cpf": "555.666.777-88"},
        ]
        cri_list, errors = ingest_records(records, schema)
        self.assertEqual(len(cri_list), 2)
        self.assertEqual(len(errors), 0)
        self.assertEqual(cri_list[0], b"cpf:11:11122233344")
        self.assertEqual(cri_list[1], b"cpf:11:55566677788")

    def test_ingest_csv_with_mapping(self):
        """Ingests a temporary CSV file with column name mapping."""
        schema = create_cpf_schema()
        csv_content = "CLIENT_ID,DOC_CPF,NAME\n1,123.456.789-01,Alice\n2,987.654.321-09,Bob\n"

        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".csv") as tmp:
            tmp.write(csv_content)
            tmp_path = tmp.name

        try:
            # Map CSV header 'DOC_CPF' -> schema field 'cpf'
            cri_list, errors = ingest_csv(
                tmp_path,
                schema,
                field_mapping={"DOC_CPF": "cpf"},
            )
            self.assertEqual(len(cri_list), 2)
            self.assertEqual(len(errors), 0)
            self.assertEqual(cri_list[0], b"cpf:11:12345678901")
            self.assertEqual(cri_list[1], b"cpf:11:98765432109")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
