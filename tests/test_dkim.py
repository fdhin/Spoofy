# tests/test_dkim.py

"""Tests for DKIM module RFC 6376 + RFC 8463 compliance.

Covers:
  - Key record version validation (§3.6.1) including positional v= check
  - Revoked key detection (empty p= tag)
  - Hash algorithm parsing (h= tag)
  - Service type validation (s= tag)
  - Testing flag detection (t=y flag)
  - Strict subdomain flag detection (t=s flag)
  - Duplicate tag rejection (§3.2) with case-sensitive tag names
  - Ed25519 key type handling (RFC 8463)
  - FWS whitespace stripping in p= tag (§2.8)
  - Base64 padding recovery
  - Regex-based TXT pre-filter robustness
  - Key size analysis
  - DKIMSelector properties (is_usable, is_sha1_only, etc.)
"""

import unittest
from modules.dkim import DKIMSelector


class TestDKIMSelectorAnalysis(unittest.TestCase):
    """Test DKIMSelector key record analysis against RFC 6376 §3.6.1."""

    def _make_selector(self, raw_value, selector="test", domain="example.com"):
        """Helper to create a DKIMSelector without DNS lookups."""
        return DKIMSelector(selector, domain, raw_value, source="test")

    # --- Version validation (§3.6.1 v= tag) ---

    def test_valid_version_dkim1(self):
        """v=DKIM1 is the only valid version."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_valid_version)
        self.assertTrue(sel.is_usable)

    def test_version_absent_is_valid(self):
        """v= tag is RECOMMENDED but not REQUIRED — absence is valid."""
        sel = self._make_selector("k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_valid_version)

    def test_invalid_version_dkim2(self):
        """v=DKIM2 MUST be discarded per RFC 6376 §3.6.1."""
        sel = self._make_selector("v=DKIM2; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_valid_version)
        self.assertFalse(sel.is_usable)

    def test_invalid_version_dkim10(self):
        """v=DKIM10 is not DKIM1."""
        sel = self._make_selector("v=DKIM10; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_valid_version)

    def test_invalid_version_empty(self):
        """v= with empty value is not 'DKIM1'."""
        sel = self._make_selector("v=; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_valid_version)

    # --- v= ordering constraint (§3.6.1) ---

    def test_version_must_be_first_tag(self):
        """v= MUST be the first tag if present. k=rsa; v=DKIM1 is invalid."""
        sel = self._make_selector("k=rsa; v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_valid_version)
        self.assertFalse(sel.is_usable)

    def test_version_first_tag_valid(self):
        """v=DKIM1 as the first tag is valid."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_valid_version)

    def test_version_second_tag_invalid(self):
        """p= first, v=DKIM1 second — positionally invalid."""
        sel = self._make_selector("p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==; v=DKIM1; k=rsa")
        self.assertFalse(sel.is_valid_version)

    # --- Revoked key detection (§3.6.1 p= tag) ---

    def test_revoked_key_empty_p(self):
        """Empty p= tag means key is revoked per RFC 6376 §3.6.1."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=")
        self.assertTrue(sel.is_revoked)
        self.assertFalse(sel.is_usable)
        self.assertIsNone(sel.key_bits)

    def test_revoked_key_whitespace_p(self):
        """p= with only whitespace is effectively empty = revoked."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=   ")
        self.assertTrue(sel.is_revoked)

    def test_revoked_key_tab_whitespace_p(self):
        """p= with tab whitespace is revoked (FWS includes tabs)."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=\t  \t")
        self.assertTrue(sel.is_revoked)

    def test_valid_key_not_revoked(self):
        """A normal key record is not revoked."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_revoked)

    def test_missing_p_tag(self):
        """Record without p= tag is malformed — must be marked invalid."""
        sel = self._make_selector("v=DKIM1; k=rsa")
        self.assertIsNone(sel.key_bits)
        self.assertFalse(sel.is_valid_version)
        self.assertFalse(sel.is_usable)

    def test_invalid_base64_in_p_tag(self):
        """Invalid base64 characters in p= must invalidate the record."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=!!!not_valid_base64!!!")
        self.assertFalse(sel.is_valid_version)
        self.assertFalse(sel.is_usable)
        self.assertIsNone(sel.key_bits)

    # --- FWS whitespace in p= tag (§2.8) ---

    def test_fws_tabs_in_p_value(self):
        """Tabs in p= must be stripped before base64 decode."""
        # Same key but with tabs injected
        sel = self._make_selector("v=DKIM1; k=rsa; p=MIGf\tMA0GCSqG\tSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_revoked)
        self.assertIsNotNone(sel.key_bits)

    def test_fws_newlines_in_p_value(self):
        """Newlines in p= must be stripped (FWS includes CR/LF)."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=MIGf\nMA0GCSqG\r\nSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_revoked)
        self.assertIsNotNone(sel.key_bits)

    # --- Base64 padding recovery ---

    def test_missing_base64_padding(self):
        """Missing trailing '=' padding should be recovered, not crash."""
        # Remove the trailing '==' from a valid base64 string
        sel = self._make_selector("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ")
        # Should not crash — padding is auto-fixed
        self.assertFalse(sel.is_revoked)
        self.assertIsNotNone(sel.key_bits)

    # --- Hash algorithms (§3.6.1 h= tag) ---

    def test_hash_algorithms_absent(self):
        """h= absent means all algorithms accepted (default)."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertIsNone(sel.hash_algorithms)
        self.assertFalse(sel.is_sha1_only)

    def test_hash_algorithms_sha256(self):
        """h=sha256 is parsed correctly."""
        sel = self._make_selector("v=DKIM1; h=sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertEqual(sel.hash_algorithms, ["sha256"])
        self.assertFalse(sel.is_sha1_only)

    def test_hash_algorithms_sha1_only(self):
        """h=sha1 with no sha256 is flagged as sha1-only."""
        sel = self._make_selector("v=DKIM1; h=sha1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertEqual(sel.hash_algorithms, ["sha1"])
        self.assertTrue(sel.is_sha1_only)

    def test_hash_algorithms_both(self):
        """h=sha1:sha256 supports both — not sha1-only."""
        sel = self._make_selector("v=DKIM1; h=sha1:sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertEqual(sel.hash_algorithms, ["sha1", "sha256"])
        self.assertFalse(sel.is_sha1_only)

    # --- Service type validation (§3.6.1 s= tag) ---

    def test_service_type_absent(self):
        """s= absent means default '*' — applicable for email."""
        sel = self._make_selector("v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_email_applicable)

    def test_service_type_email(self):
        """s=email is applicable for email."""
        sel = self._make_selector("v=DKIM1; s=email; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_email_applicable)

    def test_service_type_wildcard(self):
        """s=* is applicable for email."""
        sel = self._make_selector("v=DKIM1; s=*; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_email_applicable)

    def test_service_type_not_email(self):
        """s=voip is NOT applicable for email per RFC 6376 §3.6.1."""
        sel = self._make_selector("v=DKIM1; s=voip; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_email_applicable)
        self.assertFalse(sel.is_usable)

    def test_service_type_mixed_with_email(self):
        """s=voip:email includes email — applicable."""
        sel = self._make_selector("v=DKIM1; s=voip:email; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_email_applicable)

    # --- Testing flag (§3.6.1 t= tag) ---

    def test_testing_flag_absent(self):
        """No t= tag means not in testing mode."""
        sel = self._make_selector("v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_testing)

    def test_testing_flag_y(self):
        """t=y means testing mode."""
        sel = self._make_selector("v=DKIM1; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_testing)
        # Testing keys are still usable (valid version, not revoked, email-applicable)
        self.assertTrue(sel.is_usable)

    def test_testing_flag_s_not_testing(self):
        """t=s is the strict AUID flag, NOT testing mode."""
        sel = self._make_selector("v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_testing)

    def test_testing_flag_y_and_s(self):
        """t=y:s has both testing and strict — both should be detected."""
        sel = self._make_selector("v=DKIM1; t=y:s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_testing)
        self.assertTrue(sel.is_strict)

    # --- Strict subdomain flag (§3.6.1 t=s) ---

    def test_strict_flag_absent(self):
        """No t= tag means not in strict mode."""
        sel = self._make_selector("v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_strict)

    def test_strict_flag_s(self):
        """t=s means strict subdomain mode."""
        sel = self._make_selector("v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_strict)
        self.assertFalse(sel.is_testing)

    def test_strict_flag_in_dict(self):
        """is_strict should appear in to_dict output."""
        sel = self._make_selector("v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        d = sel.to_dict()
        self.assertIn("is_strict", d)
        self.assertTrue(d["is_strict"])

    def test_strict_flag_in_str(self):
        """__str__() shows [STRICT] for strict-mode keys."""
        sel = self._make_selector("v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertIn("STRICT", str(sel))

    # --- Ed25519 key type (RFC 8463) ---

    def test_ed25519_key_type(self):
        """k=ed25519 should be stored correctly."""
        sel = self._make_selector("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
        self.assertEqual(sel.key_type, "ed25519")

    def test_ed25519_key_bits(self):
        """Ed25519 keys are always 256-bit."""
        sel = self._make_selector("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
        self.assertEqual(sel.key_bits, 256)

    def test_ed25519_key_not_weak(self):
        """Ed25519 256-bit keys are NOT weak despite being < 2048 bits."""
        sel = self._make_selector("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
        self.assertFalse(sel.is_weak)

    def test_ed25519_key_is_usable(self):
        """Ed25519 keys should be usable."""
        sel = self._make_selector("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
        self.assertTrue(sel.is_usable)

    def test_ed25519_garbage_key_rejected(self):
        """Ed25519 with invalid base64 garbage should be rejected."""
        sel = self._make_selector("v=DKIM1; k=ed25519; p=invalid_garbage!!!")
        self.assertFalse(sel.is_valid_version)
        self.assertFalse(sel.is_usable)

    def test_ed25519_wrong_length_rejected(self):
        """Ed25519 key that decodes to != 32 bytes should be rejected."""
        # This decodes to ~86 bytes (an RSA-sized key), not 32 bytes
        sel = self._make_selector("v=DKIM1; k=ed25519; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_valid_version)
        self.assertFalse(sel.is_usable)
        self.assertIsNone(sel.key_bits)

    # --- Case-sensitive tag names (§3.2) ---

    def test_case_sensitive_tags(self):
        """Tag names are case-sensitive: K=rsa is NOT recognized as k=rsa."""
        sel = self._make_selector("v=DKIM1; K=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        # K= is not k=, so key_type should default to "rsa" (from the default, not the tag)
        self.assertEqual(sel.key_type, "rsa")

    def test_case_sensitive_v_tag(self):
        """V=DKIM1 (uppercase V) is NOT recognized as v=DKIM1."""
        sel = self._make_selector("V=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        # V= is an unrecognized tag. v= is absent, so is_valid_version stays True (v is optional)
        self.assertTrue(sel.is_valid_version)
        # But the uppercase V was ignored, so no version validation triggered
        self.assertEqual(sel.key_type, "rsa")

    # --- Duplicate tag detection (§3.2) ---

    def test_duplicate_tag_invalidates(self):
        """Duplicate tag names MUST invalidate the entire record."""
        sel = self._make_selector("v=DKIM1; p=key1; p=key2")
        self.assertFalse(sel.is_valid_version)
        self.assertFalse(sel.is_usable)

    def test_duplicate_tag_case_sensitive(self):
        """Duplicate detection is case-sensitive: p= and P= are different tags."""
        sel = self._make_selector("v=DKIM1; P=key1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        # P= and p= are different tags (case-sensitive), so this is valid
        self.assertTrue(sel.is_valid_version)

    # --- Key type defaults (§3.6.1 k= tag) ---

    def test_key_type_default_rsa(self):
        """k= absent defaults to 'rsa'."""
        sel = self._make_selector("v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertEqual(sel.key_type, "rsa")

    def test_key_type_explicit_rsa(self):
        """k=rsa is parsed."""
        sel = self._make_selector("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertEqual(sel.key_type, "rsa")

    def test_key_type_ed25519(self):
        """k=ed25519 is stored as-is (lowercased)."""
        sel = self._make_selector("v=DKIM1; k=ed25519; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertEqual(sel.key_type, "ed25519")

    # --- to_dict() and __str__() ---

    def test_to_dict_includes_all_fields(self):
        """to_dict() must include all RFC 6376 + 8463 compliance fields."""
        sel = self._make_selector("v=DKIM1; t=y:s; h=sha1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        d = sel.to_dict()
        self.assertIn("is_revoked", d)
        self.assertIn("is_testing", d)
        self.assertIn("is_strict", d)
        self.assertIn("is_valid_version", d)
        self.assertIn("is_email_applicable", d)
        self.assertIn("is_sha1_only", d)
        self.assertIn("is_usable", d)
        self.assertIn("hash_algorithms", d)
        self.assertTrue(d["is_testing"])
        self.assertTrue(d["is_strict"])
        self.assertTrue(d["is_sha1_only"])

    def test_str_revoked(self):
        """__str__() shows REVOKED for revoked keys."""
        sel = self._make_selector("v=DKIM1; p=")
        self.assertIn("REVOKED", str(sel))

    def test_str_testing(self):
        """__str__() shows TESTING MODE for testing keys."""
        sel = self._make_selector("v=DKIM1; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertIn("TESTING MODE", str(sel))


class TestDKIMIsUsable(unittest.TestCase):
    """Test the is_usable composite property."""

    def _make_selector(self, raw_value):
        return DKIMSelector("test", "example.com", raw_value, source="test")

    def test_normal_key_is_usable(self):
        sel = self._make_selector("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_usable)

    def test_revoked_key_not_usable(self):
        sel = self._make_selector("v=DKIM1; p=")
        self.assertFalse(sel.is_usable)

    def test_invalid_version_not_usable(self):
        sel = self._make_selector("v=DKIM2; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_usable)

    def test_non_email_not_usable(self):
        sel = self._make_selector("v=DKIM1; s=voip; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_usable)

    def test_testing_key_still_usable(self):
        """Testing-mode keys are usable — the testing penalty is in scoring, not usability."""
        sel = self._make_selector("v=DKIM1; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertTrue(sel.is_usable)

    def test_v_not_first_tag_not_usable(self):
        """v= at non-first position invalidates the record."""
        sel = self._make_selector("k=rsa; v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==")
        self.assertFalse(sel.is_usable)


class TestDKIMSelectorDictionary(unittest.TestCase):
    """Test the curated STATIC_SELECTORS and dynamic generator."""

    def test_hallucinated_selectors_removed(self):
        """Selectors for tenant-specific platforms must not be in the static list."""
        from modules.dkim import STATIC_SELECTORS
        hallucinated = {"amazonses", "hubspot", "hs1", "hs2",
                        "proofpoint", "ppk1", "ppk2",
                        "mimecast", "mimecast20190104", "smtpapi"}
        present = hallucinated & set(STATIC_SELECTORS)
        self.assertEqual(present, set(),
                         f"Hallucinated selectors still present: {present}")

    def test_documented_vendor_selectors_present(self):
        """Key documented vendor defaults must be in the static list."""
        from modules.dkim import STATIC_SELECTORS
        required = {
            # Core
            "default", "selector1", "selector2", "google",
            # Marketing/ESP
            "kl", "kl2", "dk", "acmail", "mkto", "cm", "ctct1", "ctct2",
            "10dkim1", "sib2k", "scph0421",
            # Consumer
            "sig1", "apple", "yahoo", "zoho", "protonmail",
            # Enterprise
            "spop1024", "aweber_key_a",
        }
        missing = required - set(STATIC_SELECTORS)
        self.assertEqual(missing, set(),
                         f"Documented selectors missing: {missing}")

    def test_dynamic_generator_produces_temporal_patterns(self):
        """Dynamic generator must produce year-prefixed selectors."""
        from modules.dkim import DKIM
        generated = DKIM._generate_dynamic_selectors()
        # Must contain current year bare and with common prefixes
        from datetime import datetime
        year = str(datetime.now().year)
        self.assertIn(year, generated)
        self.assertIn(f"s{year}", generated)
        self.assertIn(f"dkim{year}", generated)

    def test_dynamic_generator_produces_numeric_patterns(self):
        """Dynamic generator must produce numbered selector patterns."""
        from modules.dkim import DKIM
        generated = DKIM._generate_dynamic_selectors()
        # Must contain prefix+number combinations
        self.assertIn("s3", generated)
        self.assertIn("key4", generated)
        self.assertIn("selector5", generated)

    def test_dynamic_generator_no_bare_numbers(self):
        """Bare single-digit numbers (1, 2, 3..) should not be generated
        as they overlap with year generation and are not useful selectors."""
        from modules.dkim import DKIM
        generated = DKIM._generate_dynamic_selectors()
        bare_digits = [s for s in generated if s.isdigit() and len(s) == 1]
        self.assertEqual(bare_digits, [],
                         f"Bare single-digit numbers found: {bare_digits}")

    def test_combined_payload_has_no_duplicates(self):
        """The combined static + dynamic payload should have no duplicates
        after dict.fromkeys deduplication."""
        from modules.dkim import STATIC_SELECTORS, DKIM
        combined = list(dict.fromkeys(
            STATIC_SELECTORS + DKIM._generate_dynamic_selectors()
        ))
        self.assertEqual(len(combined), len(set(combined)),
                         "Duplicate selectors found in combined payload")


if __name__ == "__main__":
    unittest.main()
