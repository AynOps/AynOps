import unittest

from tools.fingerprint import fingerprint
from tools.fingerprint.engine import headers_layer, html_layer
from tools.fingerprint.signatures import (
    ANALYTICS_SIGNATURES,
    CDN_SIGNATURES,
    CMS_SIGNATURES,
    JS_SIGNATURES,
)


class TestFingerprintEngine(unittest.TestCase):
    """Contract of the I/O-free fingerprinting seam.

    fingerprint() owns the normalisation (lowercased header names, lowercased
    body) that the tool used to do inline, so callers hand it raw response
    headers and raw response text.
    """

    def test_fingerprint_returns_the_full_technology_map(self):
        result = fingerprint(
            {"Server": "nginx/1.18", "X-Powered-By": "PHP/8.1", "CF-RAY": "abc123"},
            '<LINK HREF="/WP-CONTENT/X.CSS"><SCRIPT SRC="/_NEXT/STATIC/A.JS"></SCRIPT>'
            '<SCRIPT SRC="HTTPS://GOOGLE-ANALYTICS.COM/GA.JS"></SCRIPT>',
        )

        self.assertEqual(
            result,
            {
                "web_server": "nginx/1.18",
                "powered_by": "PHP/8.1",
                "cdn": ["Cloudflare"],
                "cms": ["WordPress"],
                "javascript_frameworks": ["Next.js"],
                "analytics": ["Google Analytics"],
            },
        )
        self.assertEqual(
            list(result.keys()),
            [
                "web_server",
                "powered_by",
                "cdn",
                "cms",
                "javascript_frameworks",
                "analytics",
            ],
        )

    def test_fingerprint_omits_categories_that_match_nothing(self):
        self.assertEqual(fingerprint({}, ""), {})
        self.assertEqual(fingerprint({"Server": "nginx"}, ""), {"web_server": "nginx"})

    def test_layers_are_independent(self):
        self.assertEqual(
            headers_layer({"Server": "nginx", "CF-Ray": "x"}),
            {"web_server": "nginx", "cdn": ["Cloudflare"]},
        )
        self.assertEqual(html_layer("WP-CONTENT"), {"cms": ["WordPress"]})
        self.assertEqual(headers_layer({}), {})
        self.assertEqual(html_layer(""), {})

    def test_signature_tables_have_expected_shape(self):
        self.assertEqual(len(CDN_SIGNATURES), 6)
        self.assertEqual(len(CMS_SIGNATURES), 7)
        self.assertEqual(len(JS_SIGNATURES), 8)
        self.assertEqual(len(ANALYTICS_SIGNATURES), 6)
        self.assertEqual(CDN_SIGNATURES["Cloudflare"], ["cf-ray", "cf-cache-status"])
        self.assertEqual(
            ANALYTICS_SIGNATURES["Google Analytics"],
            ["google-analytics.com", "gtag(", "ga("],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
