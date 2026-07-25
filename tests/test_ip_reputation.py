import os
import unittest
from unittest.mock import Mock, patch
from requests.exceptions import HTTPError, RequestException, Timeout
from tools.iprep_tool import classify_reputation, ip_reputation

class TestClassifyReputation(unittest.TestCase):
    """Direct unit tests for the classification rules logic."""

    def test_trusted_when_whitelisted(self):
        # Whitelisted takes priority even if abuse score is high
        self.assertEqual(classify_reputation(True, 90, True), "trusted")
        self.assertEqual(classify_reputation(True, 0, False), "trusted")

    def test_high_risk_threshold(self):
        self.assertEqual(classify_reputation(False, 75, False), "high-risk")
        self.assertEqual(classify_reputation(False, 100, False), "high-risk")

    def test_suspicious_threshold_and_tor(self):
        # Suspicious if score >= 25 OR if it's a Tor node
        self.assertEqual(classify_reputation(False, 25, False), "suspicious")
        self.assertEqual(classify_reputation(False, 74, False), "suspicious")
        self.assertEqual(classify_reputation(False, 0, True), "suspicious")

    def test_low_risk(self):
        self.assertEqual(classify_reputation(False, 1, False), "low-risk")
        self.assertEqual(classify_reputation(False, 24, False), "low-risk")

    def test_clean(self):
        self.assertEqual(classify_reputation(False, 0, False), "clean")


class TestIpReputation(unittest.TestCase):
    """Integration tests for the main ip_reputation function."""

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
                "isWhitelisted": False,
                "isTor": False,
            }
        }
        mock_get.return_value = response

        result = ip_reputation("1.2.3.4")

        self.assertTrue(result["success"])
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["reputation"], "high-risk")
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
            "data": {
                "abuseConfidenceScore": 5,
                "totalReports": 1,
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
    def test_handles_null_fields_gracefully(self, mock_get):
        """Ensures missing or None values from API don't cause TypeError."""
        response = Mock()
        # API returns None for keys instead of omitting them
        response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 0,
                "isWhitelisted": None,
                "isTor": None,
            }
        }
        mock_get.return_value = response

        result = ip_reputation("8.8.8.8")
        self.assertTrue(result["success"])
        self.assertEqual(result["reputation"], "clean")
        self.assertFalse(result["is_malicious"])

    # -------------------------------------------------------------------------
    # Exception Handling Tests
    # -------------------------------------------------------------------------

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_http_error_handling(self, mock_get):
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = HTTPError("401 Client Error: Unauthorized")
        mock_get.return_value = mock_response

        result = ip_reputation("1.1.1.1")
        self.assertFalse(result["success"])
        self.assertIn("API request failed", result["error"])

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_timeout_handling(self, mock_get):
        mock_get.side_effect = Timeout("Connection timed out")

        result = ip_reputation("1.1.1.1")
        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"])

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("tools.iprep_tool.requests.get")
    def test_generic_request_exception_handling(self, mock_get):
        mock_get.side_effect = RequestException("Connection refused")

        result = ip_reputation("1.1.1.1")
        self.assertFalse(result["success"])
        self.assertIn("Could not connect", result["error"])

    # -------------------------------------------------------------------------
    # Validation Tests
    # -------------------------------------------------------------------------

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