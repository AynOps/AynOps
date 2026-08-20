import unittest
from unittest.mock import Mock, MagicMock, patch, call

import requests

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
    def test_no_security_analysis_in_output(self, mock_get):
        headers = {
            "server": "nginx/1.18",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
        }
        html = '<link rel="stylesheet" href="/wp-content/themes/theme.css">'
        mock_get.return_value = self._make_response(html=html, headers=headers)
        result = tech_stack_detect("example.com")

        self.assertNotIn("security_headers", result)
        self.assertEqual(
            set(result.keys()),
            {"success", "domain", "url", "status_code", "technologies"},
        )
        self.assertEqual(result["technologies"]["web_server"], "nginx/1.18")
        self.assertIn("WordPress", result["technologies"]["cms"])

    @patch("tools.techstack_tool.requests.get", side_effect=Exception("Connection refused"))
    def test_connection_error_caught(self, _):
        result = tech_stack_detect("example.com")
        self.assertFalse(result["success"])


# ---------------------------------------------------------------------------
# Characterization tests.
#
# These pin the *current* observable behaviour of tech_stack_detect(), warts
# included, so that moving the signature tables and match loops out of the tool
# body can be proven byte-for-byte behaviour preserving. They are written
# against the unmodified implementation and must stay green, unchanged, across
# the extraction. A failure here means behaviour moved, not that the
# expectation is wrong.
#
# The signature tables below are an independent restatement of the tables the
# tool matches against; if the moved copy ever drifts, these tests fail.
# ---------------------------------------------------------------------------

CDN_HEADER_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status"],
    "Fastly": ["x-fastly-request-id"],
    "Akamai": ["x-akamai-transformed"],
    "AWS CloudFront": ["x-amz-cf-id"],
    "Vercel": ["x-vercel-id"],
    "Netlify": ["x-nf-request-id"],
}

CMS_HTML_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Drupal": ["drupal.js", "drupal.min.js", "/sites/default/files"],
    "Joomla": ["/media/jui/", "joomla"],
    "Shopify": ["cdn.shopify.com", "shopify.com/s/files"],
    "Wix": ["wix.com", "wixstatic.com"],
    "Squarespace": ["squarespace.com", "static.squarespace.com"],
    "Ghost": ["ghost.io", "content/themes/ghost"],
}

JS_HTML_SIGNATURES = {
    "React": ["react.js", "react.min.js", "_react", "__react"],
    "Vue.js": ["vue.js", "vue.min.js", "__vue__"],
    "Angular": ["angular.js", "ng-version", "angular/core"],
    "Next.js": ["_next/static", "__next"],
    "Nuxt.js": ["_nuxt/", "__nuxt"],
    "jQuery": ["jquery.js", "jquery.min.js"],
    "Bootstrap": ["bootstrap.css", "bootstrap.min.css", "bootstrap.js"],
    "Tailwind": ["tailwindcss", "tailwind.css"],
}

ANALYTICS_HTML_SIGNATURES = {
    "Google Analytics": ["google-analytics.com", "gtag(", "ga("],
    "Google Tag Manager": ["googletagmanager.com"],
    "Hotjar": ["hotjar.com"],
    "Mixpanel": ["mixpanel.com"],
    "Segment": ["segment.com", "analytics.js"],
    "Facebook Pixel": ["connect.facebook.net/en_us/fbevents"],
}

TECHNOLOGY_KEY_ORDER = [
    "web_server",
    "powered_by",
    "cdn",
    "cms",
    "javascript_frameworks",
    "analytics",
]


def make_response(html="", headers=None, url="https://example.com", status=200):
    """Build a mock requests response.

    Unlike TestTechStackDetect._make_response this honours an *empty* header
    mapping instead of substituting defaults, which the signature sweeps need.
    """
    resp = Mock()
    resp.text = html
    resp.headers = {} if headers is None else headers
    resp.url = url
    resp.status_code = status
    return resp


class TestTechStackDetectCharacterization(unittest.TestCase):

    def _detect(self, **kwargs):
        with patch("tools.techstack_tool.requests.get") as mock_get:
            mock_get.return_value = make_response(**kwargs)
            return tech_stack_detect("example.com")

    # ── the empty case: categories are omitted, not emptied ──

    def test_empty_page_yields_empty_technologies(self):
        result = self._detect(html="", headers={})

        self.assertTrue(result["success"])
        self.assertEqual(result["technologies"], {})
        self.assertEqual(
            set(result.keys()),
            {"success", "domain", "url", "status_code", "technologies"},
        )

    # ── every entry of every signature table ──

    def test_all_cdn_signature_headers_detected(self):
        for name, header_names in CDN_HEADER_SIGNATURES.items():
            for header_name in header_names:
                with self.subTest(cdn=name, header=header_name):
                    result = self._detect(html="", headers={header_name: "value"})
                    self.assertEqual(result["technologies"], {"cdn": [name]})

    def test_all_cms_signature_strings_detected(self):
        for name, signatures in CMS_HTML_SIGNATURES.items():
            for signature in signatures:
                with self.subTest(cms=name, signature=signature):
                    result = self._detect(html=signature, headers={})
                    self.assertEqual(result["technologies"], {"cms": [name]})

    def test_all_javascript_signature_strings_detected(self):
        for name, signatures in JS_HTML_SIGNATURES.items():
            for signature in signatures:
                with self.subTest(framework=name, signature=signature):
                    result = self._detect(html=signature, headers={})
                    self.assertEqual(
                        result["technologies"], {"javascript_frameworks": [name]}
                    )

    def test_all_analytics_signature_strings_detected(self):
        for name, signatures in ANALYTICS_HTML_SIGNATURES.items():
            for signature in signatures:
                with self.subTest(analytics=name, signature=signature):
                    result = self._detect(html=signature, headers={})
                    self.assertEqual(result["technologies"], {"analytics": [name]})

    # ── shape of a fully populated result ──

    def test_technology_key_order_is_stable(self):
        result = self._detect(
            html='<link href="/wp-content/x.css"><script src="/_next/static/a.js">'
                 '</script><script src="https://google-analytics.com/ga.js"></script>',
            headers={
                "server": "nginx/1.18",
                "x-powered-by": "PHP/8.1",
                "cf-ray": "abc123",
            },
        )

        self.assertEqual(list(result["technologies"].keys()), TECHNOLOGY_KEY_ORDER)
        self.assertEqual(
            result["technologies"],
            {
                "web_server": "nginx/1.18",
                "powered_by": "PHP/8.1",
                "cdn": ["Cloudflare"],
                "cms": ["WordPress"],
                "javascript_frameworks": ["Next.js"],
                "analytics": ["Google Analytics"],
            },
        )

    def test_multiple_matches_within_a_category_keep_table_order(self):
        result = self._detect(
            html="wp-content joomla wixstatic.com",
            headers={"cf-ray": "a", "x-vercel-id": "b", "x-nf-request-id": "c"},
        )

        self.assertEqual(result["technologies"]["cdn"], ["Cloudflare", "Vercel", "Netlify"])
        self.assertEqual(result["technologies"]["cms"], ["WordPress", "Joomla", "Wix"])

    # ── normalisation ──

    def test_matching_is_case_insensitive(self):
        upper = self._detect(
            html='<LINK HREF="/WP-CONTENT/X.CSS"><SCRIPT SRC="/_NEXT/STATIC/A.JS">'
                 '</SCRIPT><SCRIPT SRC="HTTPS://GOOGLE-ANALYTICS.COM/GA.JS"></SCRIPT>',
            headers={"Server": "nginx/1.18", "X-Powered-By": "PHP/8.1", "CF-RAY": "abc123"},
        )

        self.assertEqual(
            upper["technologies"],
            {
                "web_server": "nginx/1.18",
                "powered_by": "PHP/8.1",
                "cdn": ["Cloudflare"],
                "cms": ["WordPress"],
                "javascript_frameworks": ["Next.js"],
                "analytics": ["Google Analytics"],
            },
        )

    def test_header_values_are_not_lowercased(self):
        result = self._detect(html="", headers={"Server": "Apache/2.4 (Ubuntu)"})

        self.assertEqual(result["technologies"]["web_server"], "Apache/2.4 (Ubuntu)")

    # ── known false positives: pinned deliberately, NOT fixed here ──

    def test_bare_substring_false_positives_are_preserved(self):
        # Issue #130 "Current Problems" §3 calls these out as real false
        # positives. They are pinned here so that fixing them is a visible,
        # separately reviewed behaviour change rather than a silent side
        # effect of moving the tables into the fingerprinting engine.
        saga = self._detect(html="the saga(s) of vega(1)", headers={})
        self.assertEqual(saga["technologies"], {"analytics": ["Google Analytics"]})

        # "wix.com" matches inside an unrelated word, and Segment's
        # "analytics.js" matches any script with that filename.
        prose = self._detect(html="phoenix.community and /js/analytics.js", headers={})
        self.assertEqual(prose["technologies"], {"analytics": ["Segment"]})

    # ── passthrough and error paths ──

    def test_url_and_status_code_passthrough(self):
        result = self._detect(
            html="", headers={}, url="https://www.example.com/landing", status=418
        )

        self.assertEqual(result["url"], "https://www.example.com/landing")
        self.assertEqual(result["status_code"], 418)
        self.assertEqual(result["domain"], "example.com")

    @patch(
        "tools.techstack_tool.requests.get",
        side_effect=requests.exceptions.SSLError("certificate verify failed"),
    )
    def test_ssl_error_message(self, _):
        result = tech_stack_detect("example.com")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "SSL error: certificate verify failed")

    @patch(
        "tools.techstack_tool.requests.get",
        side_effect=requests.exceptions.ConnectionError("boom"),
    )
    def test_connection_error_message(self, _):
        result = tech_stack_detect("example.com")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Could not connect to the domain")

    # ── the seam ──

    @patch("tools.techstack_tool.fingerprint")
    @patch("tools.techstack_tool.requests.get")
    def test_detection_is_delegated_to_the_fingerprint_engine(
        self, mock_get, mock_fingerprint
    ):
        headers = {"Server": "nginx/1.18"}
        html = "<html>/wp-content/</html>"
        mock_get.return_value = make_response(html=html, headers=headers)
        mock_fingerprint.return_value = {"sentinel": True}

        result = tech_stack_detect("example.com")

        # raw headers and raw text: normalisation belongs to the engine
        mock_fingerprint.assert_called_once_with(headers, html)
        self.assertEqual(result["technologies"], {"sentinel": True})


if __name__ == "__main__":
    unittest.main(verbosity=2)