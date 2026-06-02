from unittest.mock import Mock, MagicMock, patch, call
import unittest
from tools.iprep_tool import ip_reputation
import os

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
        self.assertEqual(result["abuse_confidence_score"], 95)
        self.assertEqual(result["total_reports"], 342)
        self.assertEqual(result["country"], "CN")
        self.assertEqual(result["isp"], "Example ISP")
        mock_get.assert_called_once()

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_low_score_not_malicious(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "data": {"abuseConfidenceScore": 5, "totalReports": 1,
                     "countryCode": "US", "isp": "Good ISP",
                     "domain": "good.net", "usageType": "ISP",
                     "lastReportedAt": None}
        }
        mock_get.return_value = response

        result = ip_reputation("8.8.8.8")
        self.assertTrue(result["success"])
        self.assertFalse(result["is_malicious"])  # score < 25

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_score_exactly_25_is_malicious(self, mock_get):
        """Boundary: score == 25 should be flagged malicious."""
        response = Mock()
        response.json.return_value = {
            "data": {"abuseConfidenceScore": 25, "totalReports": 5,
                     "countryCode": "RU", "isp": "Some ISP",
                     "domain": "bad.net", "usageType": "Hosting",
                     "lastReportedAt": None}
        }
        mock_get.return_value = response

        result = ip_reputation("1.1.1.1")
        self.assertTrue(result["is_malicious"])

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