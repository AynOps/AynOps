"""Tests for the 4-layer fingerprinting engine (issue #130 — Option B).

Each layer is tested in isolation, then ``fingerprint()`` is tested for
cross-layer merging and deduplication.
"""

from __future__ import annotations

import unittest

from tools.fingerprint import (
    cookies_layer,
    fingerprint,
    headers_layer,
    html_layer,
    meta_layer,
)
from tools.fingerprint.signatures import (
    ANALYTICS_SIGNATURES,
    CDN_SIGNATURES,
    CMS_SIGNATURES,
    JS_FRAMEWORK_SIGNATURES,
    LANGUAGE_SIGNATURES,
    WEB_SERVER_SIGNATURES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _names(result: dict, category: str) -> list[str]:
    return [d["name"] for d in result.get(category, [])]


def _get(result: dict, category: str, name: str) -> dict:
    for det in result.get(category, []):
        if det["name"] == name:
            return det
    raise AssertionError(f"{name!r} not found in category {category!r}: {result}")


# ---------------------------------------------------------------------------
# Layer 1: headers_layer
# ---------------------------------------------------------------------------

class TestHeadersLayer(unittest.TestCase):

    def test_nginx_from_server_header_value(self):
        result = headers_layer({"Server": "nginx/1.18"})
        self.assertIn("nginx", _names(result, "web_servers"))
        det = _get(result, "web_servers", "nginx")
        self.assertGreaterEqual(det["confidence"], 90)
        self.assertTrue(det["evidence"])

    def test_apache_from_server_header_value(self):
        result = headers_layer({"Server": "Apache/2.4 (Debian)"})
        self.assertIn("Apache", _names(result, "web_servers"))

    def test_php_from_x_powered_by(self):
        result = headers_layer({"X-Powered-By": "PHP/8.1"})
        self.assertIn("PHP", _names(result, "programming_languages"))

    def test_cloudflare_from_cf_ray_header_name(self):
        result = headers_layer({"cf-ray": "abc123"})
        self.assertIn("Cloudflare", _names(result, "hosting_providers"))

    def test_vercel_from_x_vercel_id(self):
        result = headers_layer({"x-vercel-id": "iad1::x"})
        self.assertIn("Vercel", _names(result, "hosting_providers"))

    def test_netlify_from_x_nf_request_id(self):
        result = headers_layer({"x-nf-request-id": "abc"})
        self.assertIn("Netlify", _names(result, "hosting_providers"))

    def test_header_names_are_compared_case_insensitively(self):
        upper = headers_layer({"CF-RAY": "abc", "SERVER": "nginx"})
        self.assertIn("Cloudflare", _names(upper, "hosting_providers"))
        self.assertIn("nginx",      _names(upper, "web_servers"))

    def test_empty_headers_returns_empty_dict(self):
        self.assertEqual(headers_layer({}), {})

    def test_result_contains_confidence_and_evidence(self):
        result = headers_layer({"Server": "nginx/1.18"})
        det = _get(result, "web_servers", "nginx")
        self.assertIn("confidence", det)
        self.assertIn("evidence",   det)
        self.assertIsInstance(det["evidence"], list)
        self.assertGreater(len(det["evidence"]), 0)


# ---------------------------------------------------------------------------
# Layer 2: cookies_layer
# ---------------------------------------------------------------------------

class TestCookiesLayer(unittest.TestCase):

    def test_php_from_phpsessid(self):
        result = cookies_layer(["PHPSESSID=abc123"])
        self.assertIn("PHP", _names(result, "programming_languages"))

    def test_aspnet_from_aspxauth(self):
        result = cookies_layer([".ASPXAUTH=xyz"])
        self.assertIn("ASP.NET", _names(result, "programming_languages"))

    def test_wordpress_from_logged_in_cookie(self):
        result = cookies_layer(["wordpress_logged_in_abc=1"])
        self.assertIn("WordPress", _names(result, "cms"))

    def test_shopify_from_shopify_s_cookie(self):
        result = cookies_layer(["_shopify_s=abc"])
        self.assertIn("Shopify", _names(result, "cms"))

    def test_empty_cookies_returns_empty_dict(self):
        self.assertEqual(cookies_layer([]), {})

    def test_cookie_evidence_contains_cookie_name(self):
        result = cookies_layer(["PHPSESSID=xyz"])
        det = _get(result, "programming_languages", "PHP")
        self.assertTrue(any("PHPSESSID" in ev for ev in det["evidence"]))


# ---------------------------------------------------------------------------
# Layer 3: meta_layer
# ---------------------------------------------------------------------------

class TestMetaLayer(unittest.TestCase):

    def test_wordpress_from_meta_generator(self):
        html = '<meta name="generator" content="WordPress 6.4.2">'
        result = meta_layer(html)
        self.assertIn("WordPress", _names(result, "cms"))
        det = _get(result, "cms", "WordPress")
        self.assertGreaterEqual(det["confidence"], 90)
        self.assertTrue(any("WordPress" in ev for ev in det["evidence"]))

    def test_ghost_from_meta_generator(self):
        html = '<meta name="generator" content="Ghost 5.59.0">'
        result = meta_layer(html)
        self.assertIn("Ghost", _names(result, "cms"))

    def test_generator_tag_with_reversed_attribute_order(self):
        html = '<meta content="WordPress 6.0" name="generator">'
        result = meta_layer(html)
        self.assertIn("WordPress", _names(result, "cms"))

    def test_nextjs_from_meta_generator(self):
        html = '<meta name="generator" content="Next.js">'
        result = meta_layer(html)
        self.assertIn("Next.js", _names(result, "frameworks"))

    def test_no_generator_tag_returns_empty_dict(self):
        self.assertEqual(meta_layer("<html><body>hello</body></html>"), {})

    def test_meta_tags_artefact_captured_in_fingerprint(self):
        html = '<meta name="generator" content="WordPress 6.4">'
        _, artefacts = fingerprint({}, html)
        self.assertEqual(artefacts["meta_tags"].get("generator"), "WordPress 6.4")


# ---------------------------------------------------------------------------
# Layer 4: html_layer
# ---------------------------------------------------------------------------

class TestHtmlLayer(unittest.TestCase):

    def test_wordpress_from_wp_content(self):
        result = html_layer('<link href="/wp-content/themes/x.css">')
        self.assertIn("WordPress", _names(result, "cms"))

    def test_nextjs_from_asset_path(self):
        result = html_layer('<script src="/_next/static/chunks/main.js">')
        self.assertIn("Next.js", _names(result, "frameworks"))

    def test_google_analytics_from_script_url(self):
        result = html_layer(
            '<script src="https://www.google-analytics.com/analytics.js">'
        )
        self.assertIn("Google Analytics", _names(result, "analytics"))

    def test_html_matching_is_case_insensitive(self):
        result = html_layer('<LINK HREF="/WP-CONTENT/X.CSS">')
        self.assertIn("WordPress", _names(result, "cms"))

    def test_empty_body_returns_empty_dict(self):
        self.assertEqual(html_layer(""), {})

    def test_facebook_pixel_from_fbevents(self):
        result = html_layer(
            'fbq("init"); <script src="https://connect.facebook.net/en_US/fbevents.js">'
        )
        self.assertIn("Facebook Pixel", _names(result, "analytics"))


# ---------------------------------------------------------------------------
# fingerprint() — cross-layer merging
# ---------------------------------------------------------------------------

class TestFingerprintMerging(unittest.TestCase):

    def test_empty_inputs_return_empty_technologies(self):
        technologies, artefacts = fingerprint({}, "")
        self.assertEqual(technologies, {})

    def test_headers_and_html_results_are_merged(self):
        technologies, _ = fingerprint(
            {"Server": "nginx/1.18", "cf-ray": "x"},
            '<link href="/wp-content/x.css">'
            '<script src="/_next/static/a.js"></script>'
            '<script src="https://www.google-analytics.com/analytics.js"></script>',
        )
        self.assertIn("web_servers",       technologies)
        self.assertIn("hosting_providers", technologies)
        self.assertIn("cms",               technologies)
        self.assertIn("frameworks",        technologies)
        self.assertIn("analytics",         technologies)

    def test_same_tech_from_multiple_layers_is_not_duplicated(self):
        """WordPress detected from both html_substring and meta_generator
        must appear exactly once in the result."""
        technologies, _ = fingerprint(
            {},
            '<meta name="generator" content="WordPress 6.4">'
            '<link href="/wp-content/x.css">',
        )
        wordpress_entries = [
            d for d in technologies.get("cms", [])
            if d["name"] == "WordPress"
        ]
        self.assertEqual(len(wordpress_entries), 1)

    def test_evidence_merged_from_multiple_layers(self):
        """The same tech hit in html and meta_generator → both evidence strings
        appear in the merged detection."""
        technologies, _ = fingerprint(
            {},
            '<meta name="generator" content="WordPress 6.4">'
            '<link href="/wp-content/themes/x.css">',
        )
        det = _get(technologies, "cms", "WordPress")
        self.assertGreaterEqual(len(det["evidence"]), 2)

    def test_confidence_is_maximum_across_layers(self):
        """If a tech fires in two layers with different confidence scores,
        the reported confidence must be the higher of the two."""
        technologies, _ = fingerprint(
            {},
            # html_substring confidence is lower than meta_generator
            '<meta name="generator" content="WordPress 6.4">'
            '<link href="/wp-content/x.css">',
        )
        det = _get(technologies, "cms", "WordPress")
        self.assertGreaterEqual(det["confidence"], 90)

    def test_cookies_are_used_for_detection(self):
        technologies, _ = fingerprint(
            {},
            "",
            cookie_names=["PHPSESSID=xyz"],
        )
        self.assertIn("PHP", _names(technologies, "programming_languages"))

    def test_fingerprints_artefact_always_has_three_keys(self):
        _, artefacts = fingerprint({}, "")
        self.assertIn("headers",   artefacts)
        self.assertIn("cookies",   artefacts)
        self.assertIn("meta_tags", artefacts)

    def test_fingerprints_headers_are_normalised(self):
        _, artefacts = fingerprint({"Server": "nginx", "CF-Ray": "x"}, "")
        self.assertIn("server", artefacts["headers"])
        self.assertIn("cf-ray", artefacts["headers"])

    def test_categories_with_no_detections_are_omitted(self):
        technologies, _ = fingerprint({"Server": "nginx"}, "")
        self.assertIn("web_servers", technologies)
        # cms, frameworks, analytics etc. should be absent — not empty lists
        for empty_cat in ("cms", "frameworks", "analytics"):
            self.assertNotIn(empty_cat, technologies)

    def test_category_order_matches_signature_order(self):
        technologies, _ = fingerprint(
            {"Server": "nginx/1.18", "X-Powered-By": "PHP/8.1", "cf-ray": "x"},
            '<link href="/wp-content/x.css">'
            '<script src="/_next/static/a.js"></script>'
            '<script src="https://www.google-analytics.com/analytics.js"></script>',
        )
        expected_order = [
            "web_servers",
            "programming_languages",
            "cms",
            "frameworks",
            "hosting_providers",
            "analytics",
        ]
        actual = [k for k in expected_order if k in technologies]
        self.assertEqual(list(technologies.keys()), actual)


# ---------------------------------------------------------------------------
# Signature table shapes (contract pinning)
# ---------------------------------------------------------------------------

class TestSignatureTableShapes(unittest.TestCase):

    def test_web_server_signatures_count(self):
        self.assertGreaterEqual(len(WEB_SERVER_SIGNATURES), 5)

    def test_language_signatures_count(self):
        self.assertGreaterEqual(len(LANGUAGE_SIGNATURES), 4)

    def test_cms_signatures_count(self):
        self.assertGreaterEqual(len(CMS_SIGNATURES), 7)

    def test_js_framework_signatures_count(self):
        self.assertGreaterEqual(len(JS_FRAMEWORK_SIGNATURES), 8)

    def test_cdn_signatures_count(self):
        self.assertGreaterEqual(len(CDN_SIGNATURES), 6)

    def test_analytics_signatures_count(self):
        self.assertGreaterEqual(len(ANALYTICS_SIGNATURES), 6)

    def test_every_signature_is_a_list_of_triples(self):
        all_tables = [
            WEB_SERVER_SIGNATURES,
            LANGUAGE_SIGNATURES,
            CMS_SIGNATURES,
            JS_FRAMEWORK_SIGNATURES,
            CDN_SIGNATURES,
            ANALYTICS_SIGNATURES,
        ]
        for table in all_tables:
            for tech, markers in table.items():
                with self.subTest(tech=tech):
                    self.assertIsInstance(markers, list)
                    for triple in markers:
                        self.assertEqual(len(triple), 3, triple)
                        mtype, mval, conf = triple
                        self.assertIn(
                            mtype,
                            {"header_name", "header_value", "cookie_name",
                             "meta_generator", "html_substring"},
                        )
                        self.assertIsInstance(mval,  str)
                        self.assertIsInstance(conf,  int)
                        self.assertGreater(conf, 0)
                        self.assertLessEqual(conf, 100)

    def test_cloudflare_has_cf_ray_marker(self):
        cf_markers = [m for _, m, _ in CDN_SIGNATURES["Cloudflare"]]
        self.assertIn("cf-ray", cf_markers)

    def test_wordpress_has_wp_content_marker(self):
        wp_markers = [m for _, m, _ in CMS_SIGNATURES["WordPress"]]
        self.assertIn("wp-content", wp_markers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
