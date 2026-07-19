import os
import unittest
from unittest.mock import Mock, patch

from tools.iprep_tool import _classify_reputation, ip_reputation


class TestIpReputation(unittest.TestCase):
    def test_ip_reputation_requires_valid_ip_and_api_key(self):
        self.assertFalse(ip_reputation("not-an-ip")["success"])

        with patch.dict(os.environ, {}, clear=True):
            result = ip_reputation("1.2.3.4")

        self.assertFalse(result["success"])
        self.assertIn("ABUSEIPDB_API_KEY", result["error"])

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_ip_reputation_maps_abuseipdb_response(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 95,
                "totalReports": 342,
                "numDistinctUsers": 40,
                "isWhitelisted": False,
                "isPublic": True,
                "isTor": False,
                "ipVersion": 4,
                "hostnames": ["bad.example"],
                "countryCode": "CN",
                "isp": "Example ISP",
                "domain": "example.net",
                "usageType": "Data Center/Web Hosting/Transit",
                "lastReportedAt": "2026-05-01T00:00:00+00:00",
            }
        }
        mock_get.return_value = response

        result = ip_reputation("1.2.3.4")

        self.assertTrue(result["success"])
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["reputation"], "high-risk")
        self.assertEqual(result["abuse_confidence_score"], 95)
        self.assertEqual(result["total_reports"], 342)
        self.assertEqual(result["num_distinct_users"], 40)
        self.assertFalse(result["is_whitelisted"])
        self.assertTrue(result["is_public"])
        self.assertFalse(result["is_tor"])
        self.assertEqual(result["ip_version"], 4)
        self.assertEqual(result["hostnames"], ["bad.example"])
        self.assertEqual(result["country"], "CN")
        self.assertEqual(result["isp"], "Example ISP")
        self.assertEqual(result["usage_type"], "Data Center/Web Hosting/Transit")
        self.assertEqual(result["last_reported_at"], "2026-05-01T00:00:00+00:00")
        mock_get.assert_called_once()

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_low_score_not_malicious(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 5,
                "totalReports": 1,
                "isWhitelisted": False,
                "countryCode": "US",
                "isp": "Good ISP",
                "domain": "good.net",
                "usageType": "ISP",
                "lastReportedAt": None,
            }
        }
        mock_get.return_value = response

        result = ip_reputation("8.8.8.8")
        self.assertTrue(result["success"])
        self.assertFalse(result["is_malicious"])  # score < 25
        self.assertEqual(result["reputation"], "low-risk")

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_score_exactly_25_is_malicious(self, mock_get):
        """Boundary: score == 25 should be flagged malicious."""
        response = Mock()
        response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 25,
                "totalReports": 5,
                "isWhitelisted": False,
                "countryCode": "RU",
                "isp": "Some ISP",
                "domain": "bad.net",
                "usageType": "Hosting",
                "lastReportedAt": None,
            }
        }
        mock_get.return_value = response

        result = ip_reputation("1.1.1.1")
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["reputation"], "suspicious")

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_whitelisted_ip_is_trusted_even_with_reports(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 0,
                "totalReports": 120,
                "numDistinctUsers": 65,
                "isWhitelisted": True,
                "isPublic": True,
                "isTor": False,
                "ipVersion": 4,
                "hostnames": ["dns.google"],
                "countryCode": "US",
                "isp": "Google LLC",
                "domain": "google.com",
                "usageType": "Content Delivery Network",
                "lastReportedAt": "2026-04-01T00:00:00+00:00",
            }
        }
        mock_get.return_value = response

        result = ip_reputation("8.8.8.8")
        self.assertTrue(result["success"])
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["reputation"], "trusted")
        self.assertTrue(result["is_whitelisted"])
        self.assertEqual(result["total_reports"], 120)
        self.assertEqual(result["usage_type"], "Content Delivery Network")

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_clean_ip_with_no_reports(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "isWhitelisted": False,
                "countryCode": "DE",
                "isp": "Clean ISP",
                "domain": "clean.net",
                "usageType": "ISP",
                "lastReportedAt": None,
            }
        }
        mock_get.return_value = response

        result = ip_reputation("9.9.9.9")
        self.assertTrue(result["success"])
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["reputation"], "clean")

    def test_classify_reputation_priority(self):
        self.assertEqual(
            _classify_reputation(is_whitelisted=True, abuse_score=99, total_reports=1000),
            "trusted",
        )
        self.assertEqual(
            _classify_reputation(is_whitelisted=False, abuse_score=80, total_reports=1),
            "high-risk",
        )
        self.assertEqual(
            _classify_reputation(is_whitelisted=False, abuse_score=30, total_reports=2),
            "suspicious",
        )
        self.assertEqual(
            _classify_reputation(is_whitelisted=False, abuse_score=0, total_reports=10),
            "low-risk",
        )
        self.assertEqual(
            _classify_reputation(is_whitelisted=False, abuse_score=0, total_reports=0),
            "clean",
        )

    def test_ipv6_address_accepted(self):
        with patch.dict(os.environ, {}, clear=True):
            # Should fail on missing API key, not on IP validation
            result = ip_reputation("2001:db8::1")
        self.assertIn("ABUSEIPDB_API_KEY", result["error"])

    def test_invalid_ip_formats(self):
        for bad_ip in ["999.999.999.999", "abc", "1.2.3", "", "192.168.1.1/24"]:
            with self.subTest(ip=bad_ip):
                result = ip_reputation(bad_ip)
                self.assertFalse(result["success"])
                self.assertIn("Invalid IP", result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
