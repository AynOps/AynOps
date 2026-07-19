from unittest.mock import Mock, patch
import unittest
from tools.hibp_tool import hibp_check
import os


class TestHibpCheck(unittest.TestCase):

    def test_hibp_check_requires_valid_input_and_api_key(self):
        # Invalid email format
        result = hibp_check("not-an-email")
        self.assertFalse(result["success"])
        self.assertIn("Input must be a valid email address or domain name", result["error"])

        # Invalid domain format
        result = hibp_check("not a domain")
        self.assertFalse(result["success"])
        self.assertIn("Input must be a valid email address or domain name", result["error"])

        # Missing API key
        with patch.dict(os.environ, {}, clear=True):
            result = hibp_check("test@example.com")
        self.assertFalse(result["success"])
        self.assertIn("HIBP_API_KEY", result["error"])

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_hibp_check_email_breached(self, mock_get):
        # First call: breachedaccount endpoint
        response1 = Mock()
        response1.json.return_value = [
            {
                "Name": "Adobe",
                "BreachDate": "2013-10-04",
                "PwnCount": 152445165,
                "DataClasses": ["Email addresses", "Passwords", "Usernames"],
                "Description": "In October 2013, 153 million Adobe accounts were breached",
            }
        ]
        response1.raise_for_status = Mock()

        # Second call: pasteaccount endpoint (returns empty for no pastes)
        response2 = Mock()
        response2.json.return_value = []
        response2.raise_for_status = Mock()

        mock_get.side_effect = [response1, response2]

        result = hibp_check("test@example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["query"], "test@example.com")
        self.assertEqual(result["type"], "email")
        self.assertTrue(result["breached"])
        self.assertEqual(result["total_breaches"], 1)
        self.assertEqual(len(result["breaches"]), 1)
        self.assertEqual(result["breaches"][0]["name"], "Adobe")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["pastes_found"], 0)
        # Should be called twice for email (breaches + pastes)
        self.assertEqual(mock_get.call_count, 2)

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_hibp_check_domain_breached(self, mock_get):
        response = Mock()
        response.json.return_value = [
            {
                "Name": "LinkedIn",
                "BreachDate": "2016-05-05",
                "PwnCount": 164611595,
                "DataClasses": ["Email addresses", "Passwords"],
                "Description": "In May 2016, LinkedIn had 164 million email addresses and passwords exposed",
            },
            {
                "Name": "MySpace",
                "BreachDate": "2013-07-01",
                "PwnCount": 359420698,
                "DataClasses": ["Email addresses", "Passwords", "Usernames"],
                "Description": "In 2013, MySpace had 359 million accounts breached",
            },
        ]
        response.raise_for_status = Mock()
        mock_get.return_value = response

        result = hibp_check("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["query"], "example.com")
        self.assertEqual(result["type"], "domain")
        self.assertTrue(result["breached"])
        self.assertEqual(result["total_breaches"], 2)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertIn("recommendation", result)

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_hibp_check_not_found_404(self, mock_get):
        response = Mock()
        response.raise_for_status = Mock()
        response.status_code = 404
        mock_get.return_value = response

        # The HIBP API returns 404 with empty body when no breaches found
        # We need to mock the JSON response properly
        import requests
        http_error = requests.exceptions.HTTPError("404 Not Found", response=response)
        response.raise_for_status.side_effect = http_error

        result = hibp_check("clean@example.com")

        self.assertTrue(result["success"])
        self.assertFalse(result["breached"])
        self.assertEqual(result["total_breaches"], 0)
        self.assertEqual(result["risk_level"], "NONE")

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_hibp_check_rate_limit(self, mock_get):
        import requests
        response = Mock()
        response.status_code = 429
        http_error = requests.exceptions.HTTPError("429 Too Many Requests", response=response)
        response.raise_for_status.side_effect = http_error
        mock_get.return_value = response

        result = hibp_check("test@example.com")

        self.assertFalse(result["success"])
        self.assertIn("rate limit", result["error"].lower())

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_hibp_check_invalid_key(self, mock_get):
        import requests
        response = Mock()
        response.status_code = 401
        http_error = requests.exceptions.HTTPError("401 Unauthorized", response=response)
        response.raise_for_status.side_effect = http_error
        mock_get.return_value = response

        result = hibp_check("test@example.com")

        self.assertFalse(result["success"])
        self.assertIn("invalid", result["error"].lower())

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_hibp_check_timeout(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()

        result = hibp_check("test@example.com")

        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"].lower())

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_hibp_check_connection_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError()

        result = hibp_check("test@example.com")

        self.assertFalse(result["success"])
        self.assertIn("connect", result["error"].lower())

    def test_hibp_check_email_detection(self):
        with patch.dict(os.environ, {}, clear=True):
            result = hibp_check("user@domain.com")
        # Should fail on API key, not on format
        self.assertIn("HIBP_API_KEY", result["error"])

    def test_hibp_check_domain_detection(self):
        with patch.dict(os.environ, {}, clear=True):
            result = hibp_check("example.com")
        # Should fail on API key, not on format
        self.assertIn("HIBP_API_KEY", result["error"])

    def test_hibp_check_invalid_formats(self):
        for bad_input in ["", " ", "not@valid", "@nodomain", "no@domain.", "not a domain"]:
            with patch.dict(os.environ, {}, clear=True):
                result = hibp_check(bad_input)
            self.assertFalse(result["success"])
            self.assertIn("Input must be a valid email address or domain name", result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)