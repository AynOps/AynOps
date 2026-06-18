from unittest.mock import Mock, MagicMock, patch, call
import unittest
import socket
from tools.asn_tool import asn_lookup
import os


class TestAsnLookup(unittest.TestCase):

    def test_missing_api_key_returns_error(self):
        with patch.dict(os.environ, {}, clear=True):
            result = asn_lookup("example.com")
        self.assertFalse(result["success"])
        self.assertIn("IP_API_KEY", result["error"])

    @patch.dict(os.environ, {"IP_API_KEY": "test-key"})
    @patch("tools.asn_tool.requests.get")
    def test_valid_ip_returns_asn_data(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "ip": "8.8.8.8",
            "country_name": "United States",
            "region_name": "California",
            "city": "Mountain View",
            "connection": {
                "asn": 15169,
                "org": "Google LLC",
                "isp": "Google LLC",
            },
        }
        mock_get.return_value = response

        result = asn_lookup("8.8.8.8")

        self.assertTrue(result["success"])
        self.assertEqual(result["asn"], "AS15169")
        self.assertEqual(result["org"], "Google LLC")
        self.assertEqual(result["country"], "United States")
        mock_get.assert_called_once()

    @patch.dict(os.environ, {"IP_API_KEY": "test-key"})
    @patch("tools.asn_tool.socket.getaddrinfo")
    def test_unresolvable_domain_returns_error(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")

        result = asn_lookup("thisdomaindoesnotexist.invalid")

        self.assertFalse(result["success"])
        self.assertIn("resolve", result["error"])

    @patch.dict(os.environ, {"IP_API_KEY": "test-key"})
    @patch("tools.asn_tool.requests.get")
    def test_api_timeout_returns_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()

        result = asn_lookup("8.8.8.8")

        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)