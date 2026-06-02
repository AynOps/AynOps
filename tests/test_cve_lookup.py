from unittest.mock import Mock, MagicMock, patch, call
import unittest
from tools.cve_tool import cve_lookup

class TestCveLookup(unittest.TestCase):

    @patch("tools.cve_tool.requests.get")
    def test_cve_lookup_returns_nvd_results(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "published": "2021-10-05T12:15:07.000",
                        "lastModified": "2024-11-21T05:31:44.123",
                        "descriptions": [{"lang": "en", "value": "Path traversal vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"baseSeverity": "CRITICAL", "cvssData": {"baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ],
        }
        mock_get.return_value = response

        result = cve_lookup("apache", "2.4.49")

        self.assertTrue(result["success"])
        self.assertEqual(result["software"], "apache")
        self.assertEqual(result["version"], "2.4.49")
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-41773")
        self.assertEqual(result["cves"][0]["severity"], "CRITICAL")
        self.assertEqual(result["cves"][0]["score"], 9.8)
        mock_get.assert_called_once()

    @patch("tools.cve_tool.requests.get")
    def test_cve_lookup_empty_results(self, mock_get):
        response = Mock()
        response.json.return_value = {"totalResults": 0, "vulnerabilities": []}
        mock_get.return_value = response

        result = cve_lookup("unknownsoftware", "9.9.9")
        self.assertTrue(result["success"])
        self.assertEqual(result["total_results"], 0)
        self.assertEqual(result["cves"], [])

    def test_cve_lookup_empty_software_rejected(self):
        result = cve_lookup("", "1.0")
        self.assertFalse(result["success"])
        self.assertIn("required", result["error"])

    def test_cve_lookup_empty_version_rejected(self):
        result = cve_lookup("apache", "")
        self.assertFalse(result["success"])

    def test_cve_lookup_whitespace_only_rejected(self):
        result = cve_lookup("   ", "   ")
        self.assertFalse(result["success"])

    @patch("tools.cve_tool.requests.get")
    def test_cve_lookup_multiple_cves(self, mock_get):
        def make_vuln(cve_id, score):
            return {
                "cve": {
                    "id": cve_id,
                    "published": "2021-01-01T00:00:00.000",
                    "lastModified": "2021-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"baseSeverity": "HIGH", "cvssData": {"baseScore": score}}
                        ]
                    },
                }
            }

        response = Mock()
        response.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [make_vuln("CVE-2021-00001", 8.0), make_vuln("CVE-2021-00002", 7.5)],
        }
        mock_get.return_value = response

        result = cve_lookup("nginx", "1.18")
        self.assertEqual(len(result["cves"]), 2)
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-00001")

    @patch("tools.cve_tool.requests.get", side_effect=Exception("NVD unreachable"))
    def test_cve_lookup_exception_caught(self, _):
        result = cve_lookup("apache", "2.4")
        self.assertFalse(result["success"])
        self.assertIn("NVD unreachable", result["error"])

if __name__ == "__main__":
    unittest.main(verbosity=2)