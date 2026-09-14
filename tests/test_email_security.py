import unittest
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from tools.email_security_tool import (
    _discover_dynamic_selectors,
    _is_dmarc_record,
    _is_spf_record,
    _parse_dkim_record,
    _query_txt,
    _spf_policy,
    email_security_check,
)


class TestEmailSecurityScanner(unittest.TestCase):
    @patch("tools.email_security_tool.is_valid_domain")
    def test_invalid_domain_format(self, mock_is_valid):
        """Ensure invalid domains return a clean failure dictionary immediately."""
        mock_is_valid.return_value = False
        result = email_security_check("invalid_domain")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Invalid domain format")

    def test_spf_policy_mapping(self):
        """Verify the 'all' mechanism is resolved via tokenization, not substring matching."""
        self.assertEqual(_spf_policy("v=spf1 include:_spf.google.com -all"), "fail")
        self.assertEqual(
            _spf_policy("v=spf1 include:spf.protection.outlook.com ~all"), "softfail"
        )
        self.assertEqual(_spf_policy("v=spf1 ?all"), "neutral")
        self.assertEqual(_spf_policy("v=spf1 +all"), "pass")
        # Bare 'all' is equivalent to '+all' per RFC 7208
        self.assertEqual(_spf_policy("v=spf1 all"), "pass")
        # Mechanisms are evaluated left-to-right: the first 'all' wins
        self.assertEqual(_spf_policy("v=spf1 ~all -all"), "softfail")
        # A redirect= modifier means the policy is delegated to the target
        self.assertEqual(_spf_policy("v=spf1 redirect=example.com"), "redirect")
        # ...but an explicit 'all' still takes precedence over redirect=
        self.assertEqual(_spf_policy("v=spf1 redirect=example.com -all"), "fail")
        # No 'all' and no redirect -> distinct 'missing' status
        self.assertEqual(_spf_policy("v=spf1 include:_spf.google.com"), "missing")
        # Substrings inside unrelated tokens must not false-match '-all'
        self.assertEqual(_spf_policy("v=spf1 include:send-all.example.com"), "missing")
        self.assertEqual(_spf_policy("v=spf1 -allow"), "missing")
        # Not a valid SPF record at all
        self.assertEqual(_spf_policy("V=SPF1 -all"), "unknown")
        self.assertEqual(_spf_policy("v=spf1foo -all"), "unknown")
        self.assertEqual(_spf_policy("not an spf record"), "unknown")

    def test_is_spf_record(self):
        """RFC 7208 §4.5: only an exact 'v=spf1' version token qualifies."""
        self.assertTrue(_is_spf_record("v=spf1 -all"))
        self.assertTrue(_is_spf_record("v=spf1"))
        self.assertFalse(_is_spf_record("V=SPF1 -all"))
        self.assertFalse(_is_spf_record("v=spf1foo -all"))
        self.assertFalse(_is_spf_record("v=spf1;-all"))
        self.assertFalse(_is_spf_record("some other txt record"))
        self.assertFalse(_is_spf_record(""))

    def test_parse_dkim_record(self):
        """RFC 6376: distinguish active, revoked, malformed and unrelated records."""
        # Active key
        status, _ = _parse_dkim_record(
            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
        )
        self.assertEqual(status, "active")
        # The v= tag is optional — a valid p= alone is still an active record
        self.assertEqual(
            _parse_dkim_record("p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A")[0], "active"
        )
        # Unknown extension tags (containing '_') are ignored
        self.assertEqual(_parse_dkim_record("v=DKIM1; x_foo=bar; p=MIIB")[0], "active")
        # Empty p= is a revoked key, not an active one
        self.assertEqual(_parse_dkim_record("v=DKIM1; p=")[0], "revoked")
        self.assertEqual(_parse_dkim_record("v=DKIM1; p=   ")[0], "revoked")
        # v=DKIM1 without p= is malformed (p= is required)
        self.assertEqual(_parse_dkim_record("v=DKIM1; k=rsa")[0], "malformed")
        # Version tag is case-sensitive — must be exactly 'DKIM1'
        self.assertEqual(_parse_dkim_record("v=dkim1; p=MIIB")[0], "malformed")
        # v= must be the first tag when present
        self.assertEqual(_parse_dkim_record("p=MIIB; v=DKIM1")[0], "malformed")
        # Whitespace inside a tag name invalidates the record
        self.assertEqual(_parse_dkim_record("v =DKIM1; p=MIIB")[0], "malformed")
        # Tag names are case-sensitive — 'P=' is not the p= tag
        self.assertEqual(_parse_dkim_record("v=DKIM1; P=MIIB")[0], "malformed")
        # Duplicate tag names invalidate the record
        self.assertEqual(_parse_dkim_record("v=DKIM1; p=MIIB; p=MIIC")[0], "malformed")
        # A p= value that is not base64 public-key data is malformed
        self.assertEqual(
            _parse_dkim_record("v=DKIM1; p=not-a-public-key!")[0], "malformed"
        )
        # Unrelated TXT records are not DKIM records
        self.assertEqual(
            _parse_dkim_record("google-site-verification=abc123")[0], "not_dkim"
        )
        self.assertEqual(_parse_dkim_record("v=spf1 -all")[0], "not_dkim")
        self.assertEqual(_parse_dkim_record("")[0], "not_dkim")

    def test_is_dmarc_record(self):
        """A DMARC record must begin with a v=DMARC1 tag."""
        self.assertTrue(_is_dmarc_record("v=DMARC1; p=reject"))
        self.assertTrue(_is_dmarc_record("v=DMARC1"))
        self.assertFalse(_is_dmarc_record("v=DMARC2; p=reject"))
        self.assertFalse(_is_dmarc_record("p=reject; v=DMARC1"))
        self.assertFalse(_is_dmarc_record("v=spf1 -all"))
        self.assertFalse(_is_dmarc_record(""))

    @patch("dns.resolver.Resolver.resolve")
    def test_query_txt_fallback_mechanism(self, mock_resolve):
        """Ensure standard resolver timeouts trigger the public 1.1.1.1/8.8.8.8 fallback."""
        # First call raises a Timeout; second call (fallback) succeeds
        mock_resolve.side_effect = [
            dns.resolver.Timeout(),
            [MagicMock(strings=[b"fallback-record"])],
        ]

        records, failed = _query_txt("example.com")
        self.assertFalse(failed)
        self.assertIn("fallback-record", records)
        self.assertEqual(mock_resolve.call_count, 2)

    @patch("dns.resolver.Resolver.resolve")
    def test_discover_dynamic_selectors_google_mx(self, mock_resolve):
        """Verify that discovering a Google MX server appends relevant target selectors."""
        mock_mx = MagicMock()
        mock_mx.exchange = "aspmx.l.google.com."
        mock_resolve.return_value = [mock_mx]

        selectors = _discover_dynamic_selectors("example.com")

        # Check that specific corporate signature keys are added dynamically
        self.assertIn("20161025", selectors)
        self.assertIn("20230601", selectors)

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_perfect_score_scenario_openai(self, mock_valid, mock_discover, mock_query):
        """Verify an optimal setup scores 100% ('Excellent') with no recommendations."""
        mock_discover.return_value = []

        # Mocking endpoints sequentially:
        # 1. Apex Domain TXT (SPF lookup)
        # 2. _dmarc sub-domain TXT
        # 3. DKIM checks (simulating one match on 'default')
        def side_effect_query(name):
            if name == "openai.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.openai.com":
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@openai.com"], False
            elif "default._domainkey.openai.com" in name:
                return ["v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQFAAOE"], False
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("openai.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["security_score"], "100%")
        self.assertEqual(result["rating"], "Excellent")
        self.assertEqual(len(result["recommendations"]), 0)
        self.assertEqual(result["dkim"]["found_selectors"], ["default"])

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_partial_score_scenario_github(self, mock_valid, mock_discover, mock_query):
        """Verify that softfail and quarantine settings pull down scores accurately."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "github.com":
                return ["v=spf1 ~all"], False
            elif name == "_dmarc.github.com":
                return ["v=DMARC1; p=quarantine; rua=mailto:dmarc@github.com"], False
            elif "default._domainkey.github.com" in name:
                return ["v=DKIM1; p=MIIB"], False
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("github.com")

        # Math: SPF(20) + DMARC(25) + DKIM(35) = 80%
        self.assertEqual(result["security_score"], "80%")
        self.assertEqual(result["rating"], "Good")
        self.assertIn(
            "SPF uses softfail (~all) — consider a hard fail (-all) for stronger protection",
            result["recommendations"],
        )
        self.assertIn(
            "DMARC policy is 'quarantine' — failing mail goes to spam.",
            result["recommendations"],
        )

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_missing_rua_tag_deduction(self, mock_valid, mock_discover, mock_query):
        """Ensure omitting the 'rua' visibility reporting tag deducts 5 points from DMARC."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject"], False  # Missing rua=
            return [], False  # DKIM absent

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        # Math: SPF(30) + DMARC(35 - 5 deduction = 30) + DKIM(0) = 60%
        self.assertEqual(result["security_score"], "60%")
        self.assertEqual(result["rating"], "Fair")
        self.assertIn("DMARC has no rua= reporting address.", result["recommendations"])

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_empty_rua_tag_deduction(self, mock_valid, mock_discover, mock_query):
        """An empty rua= tag is not a configured reporting destination."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject; rua="], False  # Empty rua=
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        # Same -5 deduction as a missing rua tag
        self.assertEqual(result["security_score"], "60%")
        self.assertIn(
            "DMARC has an empty rua= tag with no reporting address.",
            result["recommendations"],
        )

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_multiple_spf_records_invalid(self, mock_valid, mock_discover, mock_query):
        """Multiple SPF records are flagged invalid and all records are preserved."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all", "v=spf1 ~all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@test.com"], False
            elif "default._domainkey.test.com" in name:
                return ["v=DKIM1; p=MIIB"], False
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        spf = result["spf"]
        self.assertTrue(spf["found"])
        self.assertFalse(spf["valid"])
        self.assertIsNone(spf["record"])
        self.assertIsNone(spf["policy"])
        self.assertEqual(spf["records"], ["v=spf1 -all", "v=spf1 ~all"])
        self.assertTrue(
            any("Multiple SPF records" in r for r in result["recommendations"])
        )
        # Math: SPF(0) + DMARC(35) + DKIM(35) = 70%
        self.assertEqual(result["security_score"], "70%")

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_multiple_dmarc_records_invalid(
        self, mock_valid, mock_discover, mock_query
    ):
        """Multiple DMARC records are flagged ambiguous and all records are preserved."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject", "v=DMARC1; p=none"], False
            elif "default._domainkey.test.com" in name:
                return ["v=DKIM1; p=MIIB"], False
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        dmarc = result["dmarc"]
        self.assertTrue(dmarc["found"])
        self.assertFalse(dmarc["valid"])
        self.assertIsNone(dmarc["record"])
        self.assertIsNone(dmarc["policy"])
        self.assertEqual(dmarc["records"], ["v=DMARC1; p=reject", "v=DMARC1; p=none"])
        self.assertTrue(
            any("Multiple DMARC records" in r for r in result["recommendations"])
        )
        # Math: SPF(30) + DMARC(0) + DKIM(35) = 65%
        self.assertEqual(result["security_score"], "65%")

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_invalid_dmarc_policy_value(self, mock_valid, mock_discover, mock_query):
        """A p= value outside none/quarantine/reject is reported invalid."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=banana; rua=mailto:dmarc@test.com"], False
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        self.assertTrue(result["dmarc"]["found"])
        self.assertFalse(result["dmarc"]["valid"])
        self.assertEqual(result["dmarc"]["policy"], "invalid")
        self.assertTrue(any("p=banana" in r for r in result["recommendations"]))

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_missing_dmarc_policy_tag(self, mock_valid, mock_discover, mock_query):
        """A DMARC record without p= defaults to 'none' but gets a recommendation."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; rua=mailto:dmarc@test.com"], False  # Missing p=
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        self.assertTrue(result["dmarc"]["valid"])
        self.assertEqual(result["dmarc"]["policy"], "none")
        self.assertTrue(any("no 'p=' tag" in r for r in result["recommendations"]))

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_dkim_revoked_selector(self, mock_valid, mock_discover, mock_query):
        """A selector with an empty p= key is reported as revoked, not active."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@test.com"], False
            elif "selector1._domainkey.test.com" in name:
                return ["v=DKIM1; p="], False  # Revoked key
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        dkim = result["dkim"]
        self.assertFalse(dkim["found"])
        self.assertEqual(dkim["found_selectors"], [])
        self.assertEqual(dkim["revoked_selectors"], ["selector1"])
        self.assertEqual(dkim["malformed_selectors"], [])
        self.assertTrue(any("revoked" in r for r in result["recommendations"]))
        # Math: SPF(30) + DMARC(35) + DKIM(0) = 65%
        self.assertEqual(result["security_score"], "65%")

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_dkim_malformed_selector(self, mock_valid, mock_discover, mock_query):
        """A DKIM-intended record that fails parsing is reported as malformed."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@test.com"], False
            elif "google._domainkey.test.com" in name:
                return ["v=DKIM1; k=rsa"], False  # Missing required p= tag
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        dkim = result["dkim"]
        self.assertFalse(dkim["found"])
        self.assertEqual(dkim["found_selectors"], [])
        self.assertEqual(dkim["revoked_selectors"], [])
        self.assertEqual(dkim["malformed_selectors"], ["google"])
        self.assertTrue(any("malformed" in r for r in result["recommendations"]))

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_dkim_unrelated_txt_ignored(self, mock_valid, mock_discover, mock_query):
        """TXT records without DKIM tags do not produce DKIM findings."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@test.com"], False
            elif "default._domainkey.test.com" in name:
                return ["some unrelated verification=token"], False
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        dkim = result["dkim"]
        self.assertFalse(dkim["found"])
        self.assertEqual(dkim["found_selectors"], [])
        self.assertEqual(dkim["revoked_selectors"], [])
        self.assertEqual(dkim["malformed_selectors"], [])
        # Best-effort wording must not claim DKIM is definitively absent
        self.assertTrue(
            any("may still be configured" in r for r in result["recommendations"])
        )

    @patch("tools.email_security_tool._query_txt")
    @patch("tools.email_security_tool._discover_dynamic_selectors")
    @patch("tools.email_security_tool.is_valid_domain", return_value=True)
    def test_spf_missing_all_mechanism(self, mock_valid, mock_discover, mock_query):
        """An SPF record without 'all' or redirect= reports policy 'missing'."""
        mock_discover.return_value = []

        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 include:_spf.google.com"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@test.com"], False
            return [], False

        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")

        self.assertTrue(result["spf"]["found"])
        self.assertTrue(result["spf"]["valid"])
        self.assertEqual(result["spf"]["policy"], "missing")
        self.assertTrue(
            any("no 'all' mechanism" in r for r in result["recommendations"])
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
