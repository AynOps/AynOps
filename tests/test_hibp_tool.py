import os
import unittest
from unittest.mock import Mock, patch

from tools.hibp_tool import _risk_level, hibp_check


class TestHibpCheck(unittest.TestCase):
    def test_invalid_input(self):
        result = hibp_check("not-an-email-or-domain")
        self.assertFalse(result["success"])
        self.assertIn("Invalid input", result["error"])

    def test_missing_api_key(self):
        with patch.dict(os.environ, {}, clear=True):
            result = hibp_check("test@example.com")
        self.assertFalse(result["success"])
        self.assertIn("HIBP_API_KEY", result["error"])

    def test_risk_level_buckets(self):
        self.assertEqual(_risk_level(0), "NONE")
        self.assertEqual(_risk_level(1), "LOW")
        self.assertEqual(_risk_level(3), "MEDIUM")
        self.assertEqual(_risk_level(6), "HIGH")
        self.assertEqual(_risk_level(11), "CRITICAL")

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_email_no_breaches_404(self, mock_get):
        breach_resp = Mock()
        breach_resp.status_code = 404
        paste_resp = Mock()
        paste_resp.status_code = 404
        mock_get.side_effect = [breach_resp, paste_resp]

        result = hibp_check("clean@example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "email")
        self.assertFalse(result["breached"])
        self.assertEqual(result["total_breaches"], 0)
        self.assertEqual(result["risk_level"], "NONE")

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_email_with_breaches_and_pastes(self, mock_get):
        breach_resp = Mock()
        breach_resp.status_code = 200
        breach_resp.json.return_value = [
            {
                "Name": "Adobe",
                "BreachDate": "2013-10-04",
                "PwnCount": 152445165,
                "DataClasses": ["Email addresses", "Passwords"],
                "Description": "Adobe breach",
            },
            {
                "Name": "LinkedIn",
                "BreachDate": "2012-05-05",
                "PwnCount": 164611595,
                "DataClasses": ["Email addresses", "Passwords"],
                "Description": "LinkedIn breach",
            },
            {
                "Name": "Dropbox",
                "BreachDate": "2012-07-01",
                "PwnCount": 68648009,
                "DataClasses": ["Email addresses", "Passwords"],
                "Description": "Dropbox breach",
            },
        ]
        paste_resp = Mock()
        paste_resp.status_code = 200
        paste_resp.json.return_value = [{"Id": "a"}, {"Id": "b"}]
        mock_get.side_effect = [breach_resp, paste_resp]

        result = hibp_check("test@example.com")
        self.assertTrue(result["success"])
        self.assertTrue(result["breached"])
        self.assertEqual(result["total_breaches"], 3)
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(result["pastes_found"], 2)
        self.assertEqual(result["breaches"][0]["name"], "Adobe")

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_domain_breaches_include_recommendation(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = [
            {
                "Name": "ExampleCorp",
                "BreachDate": "2020-01-01",
                "PwnCount": 1000,
                "DataClasses": ["Email addresses"],
                "Description": "Example breach",
            }
        ]
        mock_get.return_value = response

        result = hibp_check("example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "domain")
        self.assertTrue(result["breached"])
        self.assertEqual(result["total_breaches"], 1)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertIn("password resets", result["recommendation"])

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_domain_no_breaches(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = []
        mock_get.return_value = response

        result = hibp_check("clean-example.com")
        self.assertTrue(result["success"])
        self.assertFalse(result["breached"])
        self.assertEqual(result["risk_level"], "NONE")
        self.assertNotIn("recommendation", result)

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_domain_is_normalized(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = []
        mock_get.return_value = response

        result = hibp_check(" Example.COM. ")

        self.assertTrue(result["success"])
        self.assertEqual(result["query"], "example.com")
        self.assertEqual(mock_get.call_args.kwargs["params"], {"domain": "example.com"})

    @patch.dict(os.environ, {"HIBP_API_KEY": "test-key"})
    @patch("tools.hibp_tool.requests.get")
    def test_unauthorized_api_key(self, mock_get):
        response = Mock()
        response.status_code = 401
        err = __import__("requests").exceptions.HTTPError(response=response)
        response.raise_for_status.side_effect = err
        mock_get.return_value = response

        # Force raise_for_status path by status 401 without special handling before raise
        # Our code only special-cases 404 before raise_for_status; 401 goes through HTTPError.
        def _raise():
            raise __import__("requests").exceptions.HTTPError(response=response)

        response.raise_for_status.side_effect = _raise
        result = hibp_check("test@example.com")
        self.assertFalse(result["success"])
        self.assertIn("unauthorized", result["error"].lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
