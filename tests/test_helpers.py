from utils.helpers import is_valid_domain , get_cvss_details , get_english_description
import unittest

class TestHelpers(unittest.TestCase):

    # ── is_valid_domain ──────────────────────────────────────
    def test_valid_domains(self):
        for d in ["example.com", "sub.example.com", "a.b.c.org", "xn--nxasmq6b.com"]:
            with self.subTest(domain=d):
                self.assertTrue(is_valid_domain(d))

    def test_invalid_domains(self):
        for d in ["", "localhost", "192.168.1.1", "no-tld", "bad domain.com", "-start.com"]:
            with self.subTest(domain=d):
                self.assertFalse(is_valid_domain(d))

    # ── get_cvss_details ─────────────────────────────────────
    def test_cvss_v31_extraction(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}
                ]
            }
        }
        result = get_cvss_details(cve)
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["score"], 7.5)

    def test_cvss_falls_back_to_v2(self):
        cve = {
            "metrics": {
                "cvssMetricV2": [
                    {"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}
                ]
            }
        }
        result = get_cvss_details(cve)
        self.assertEqual(result["severity"], "MEDIUM")

    def test_cvss_no_metrics_returns_unknown(self):
        result = get_cvss_details({})
        self.assertEqual(result["severity"], "Unknown")
        self.assertIsNone(result["score"])

    # ── get_english_description ──────────────────────────────
    def test_english_description_extracted(self):
        cve = {"descriptions": [{"lang": "fr", "value": "Bonjour"}, {"lang": "en", "value": "Hello"}]}
        self.assertEqual(get_english_description(cve), "Hello")

    def test_no_english_description_returns_empty(self):
        cve = {"descriptions": [{"lang": "fr", "value": "Bonjour"}]}
        self.assertEqual(get_english_description(cve), "")

    def test_empty_descriptions_returns_empty(self):
        self.assertEqual(get_english_description({}), "")

if __name__ == "__main__":
    unittest.main(verbosity=2)