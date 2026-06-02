import unittest
from unittest.mock import Mock, MagicMock, patch, call
from tools.techstack_tool import tech_stack_detect

class TestTechStackDetect(unittest.TestCase):

    def _make_response(self, html="", headers=None, url="https://example.com", status=200):
        headers = headers or {"server": "nginx/1.18", "x-powered-by": "PHP/8.1"}
        resp = Mock()
        resp.text = html
        resp.headers = headers
        resp.url = url
        resp.status_code = status
        return resp

    def test_invalid_domain(self):
        result = tech_stack_detect("bad_domain")
        self.assertFalse(result["success"])

    @patch("tools.techstack_tool.requests.get")
    def test_detects_web_server(self, mock_get):
        mock_get.return_value = self._make_response()
        result = tech_stack_detect("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["technologies"]["web_server"], "nginx/1.18")
        self.assertEqual(result["technologies"]["powered_by"], "PHP/8.1")

    @patch("tools.techstack_tool.requests.get")
    def test_detects_cloudflare_cdn(self, mock_get):
        headers = {"cf-ray": "abc123", "cf-cache-status": "HIT"}
        mock_get.return_value = self._make_response(headers=headers)
        result = tech_stack_detect("example.com")

        self.assertIn("Cloudflare", result["technologies"]["cdn"])

    @patch("tools.techstack_tool.requests.get")
    def test_detects_wordpress_cms(self, mock_get):
        html = '<link rel="stylesheet" href="/wp-content/themes/theme.css">'
        mock_get.return_value = self._make_response(html=html)
        result = tech_stack_detect("example.com")

        self.assertIn("WordPress", result["technologies"]["cms"])

    @patch("tools.techstack_tool.requests.get")
    def test_detects_react_framework(self, mock_get):
        html = '<script src="/_next/static/chunks/main.js"></script>'
        mock_get.return_value = self._make_response(html=html)
        result = tech_stack_detect("example.com")

        self.assertIn("Next.js", result["technologies"]["javascript_frameworks"])

    @patch("tools.techstack_tool.requests.get")
    def test_security_header_scoring(self, mock_get):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'self'",
            "referrer-policy": "strict-origin",
            "permissions-policy": "geolocation=()",
            "x-xss-protection": "1; mode=block",
        }
        mock_get.return_value = self._make_response(headers=headers)
        result = tech_stack_detect("example.com")

        self.assertEqual(result["security_headers"]["score"], "100%")
        self.assertEqual(result["security_headers"]["rating"], "Excellent")
        self.assertEqual(result["security_headers"]["missing"], [])

    @patch("tools.techstack_tool.requests.get")
    def test_poor_security_header_rating(self, mock_get):
        mock_get.return_value = self._make_response(headers={})
        result = tech_stack_detect("example.com")

        self.assertEqual(result["security_headers"]["score"], "0%")
        self.assertEqual(result["security_headers"]["rating"], "Poor")

    @patch("tools.techstack_tool.requests.get", side_effect=Exception("Connection refused"))
    def test_connection_error_caught(self, _):
        result = tech_stack_detect("example.com")
        self.assertFalse(result["success"])

if __name__ == "__main__":
    unittest.main(verbosity=2)