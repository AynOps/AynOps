"""Characterization tests for tech_stack_detect (issue #130 — Option B schema).

Contract under test
-------------------
* On success the result has the keys:
  ``success``, ``domain``, ``url``, ``status_code``,
  ``technologies``, ``fingerprints``.
* ``technologies`` is a dict keyed by category; each value is a list of
  detection dicts ``{"name": str, "confidence": int, "evidence": [str, ...]}``.
* ``fingerprints`` always contains sub-keys
  ``"headers"``, ``"cookies"``, ``"meta_tags"``.
* Categories with no detections are omitted.
* On failure the result is ``{"success": False, "error": "<reason>"}``.
* HTTPS is tried first; SSL / connection errors cause an HTTP retry.
* The response body is capped at ``MAX_BODY_BYTES`` before fingerprinting.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, call, patch

import requests

from tools.techstack_tool import MAX_BODY_BYTES, tech_stack_detect


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    html: str = "",
    headers: dict | None = None,
    url: str = "https://example.com",
    status: int = 200,
    cookies: list[str] | None = None,
) -> MagicMock:
    """Build a mock *streaming* requests.Response."""
    resp = MagicMock()
    resp.headers = {} if headers is None else headers
    resp.url = url
    resp.status_code = status

    # stream=True: iter_content yields bytes chunks, close() is called
    resp.iter_content.return_value = iter([html.encode("utf-8")])
    resp.close.return_value = None

    # Set-Cookie headers via resp.raw.headers.getlist()
    raw_cookies: list[str] = cookies or []
    resp.raw.headers.getlist.return_value = raw_cookies

    return resp


def _detect(
    html: str = "",
    headers: dict | None = None,
    url: str = "https://example.com",
    status: int = 200,
    cookies: list[str] | None = None,
    domain: str = "example.com",
) -> dict:
    """Run tech_stack_detect against a canned response."""
    with patch("tools.techstack_tool._fetch") as mock_fetch:
        mock_fetch.return_value = _make_response(
            html=html,
            headers=headers,
            url=url,
            status=status,
            cookies=cookies,
        )
        return tech_stack_detect(domain)


# ---------------------------------------------------------------------------
# Success-path: top-level shape
# ---------------------------------------------------------------------------

class TestResultShape(unittest.TestCase):

    def test_success_keys_are_present(self):
        result = _detect()
        self.assertTrue(result["success"])
        self.assertEqual(
            set(result.keys()),
            {"success", "domain", "url", "status_code", "technologies", "fingerprints"},
        )

    def test_fingerprints_subkeys_always_present(self):
        result = _detect()
        fp = result["fingerprints"]
        self.assertIn("headers",   fp)
        self.assertIn("cookies",   fp)
        self.assertIn("meta_tags", fp)

    def test_empty_page_yields_empty_technologies(self):
        result = _detect(html="", headers={})
        self.assertTrue(result["success"])
        self.assertEqual(result["technologies"], {})

    def test_url_and_status_code_passthrough(self):
        result = _detect(
            html="", headers={},
            url="https://www.example.com/landing",
            status=418,
        )
        self.assertEqual(result["url"],         "https://www.example.com/landing")
        self.assertEqual(result["status_code"], 418)
        self.assertEqual(result["domain"],      "example.com")


# ---------------------------------------------------------------------------
# Success-path: detection accuracy (new schema)
# ---------------------------------------------------------------------------

class TestDetections(unittest.TestCase):

    def _assert_detected(self, result: dict, category: str, name: str):
        """Assert that *name* appears in *category* with confidence > 0."""
        self.assertIn(category, result["technologies"], f"Category {category!r} missing")
        names = [d["name"] for d in result["technologies"][category]]
        self.assertIn(name, names, f"{name!r} not detected in {category!r}: {names}")

    def _get_detection(self, result: dict, category: str, name: str) -> dict:
        for det in result["technologies"].get(category, []):
            if det["name"] == name:
                return det
        self.fail(f"{name!r} not found in {category!r}")

    # ── web server ──

    def test_nginx_detected_from_server_header(self):
        result = _detect(headers={"Server": "nginx/1.18"})
        self._assert_detected(result, "web_servers", "nginx")
        det = self._get_detection(result, "web_servers", "nginx")
        self.assertGreaterEqual(det["confidence"], 90)
        self.assertTrue(det["evidence"])

    def test_apache_detected_from_server_header(self):
        result = _detect(headers={"Server": "Apache/2.4 (Ubuntu)"})
        self._assert_detected(result, "web_servers", "Apache")

    # ── programming language ──

    def test_php_detected_from_x_powered_by(self):
        result = _detect(headers={"X-Powered-By": "PHP/8.1"})
        self._assert_detected(result, "programming_languages", "PHP")
        det = self._get_detection(result, "programming_languages", "PHP")
        self.assertGreaterEqual(det["confidence"], 85)

    def test_php_detected_from_phpsessid_cookie(self):
        result = _detect(cookies=["PHPSESSID=abc123"])
        self._assert_detected(result, "programming_languages", "PHP")

    # ── CMS ──

    def test_wordpress_detected_from_html(self):
        result = _detect(html='<link href="/wp-content/themes/x/style.css">')
        self._assert_detected(result, "cms", "WordPress")

    def test_wordpress_detected_from_meta_generator(self):
        result = _detect(
            html='<meta name="generator" content="WordPress 6.4.2">'
        )
        self._assert_detected(result, "cms", "WordPress")
        det = self._get_detection(result, "cms", "WordPress")
        # meta generator should carry higher confidence
        self.assertGreaterEqual(det["confidence"], 90)

    def test_wordpress_evidence_merged_from_multiple_sources(self):
        """wp-content in HTML + meta generator → evidence list contains both."""
        result = _detect(
            html='<meta name="generator" content="WordPress 6.4">'
                 '<link href="/wp-content/x.css">'
        )
        det = self._get_detection(result, "cms", "WordPress")
        # at least two evidence strings
        self.assertGreaterEqual(len(det["evidence"]), 2)

    def test_shopify_detected_from_cdn_url(self):
        result = _detect(html='<script src="https://cdn.shopify.com/s/files/1.js">')
        self._assert_detected(result, "cms", "Shopify")

    # ── JS frameworks ──

    def test_nextjs_detected_from_asset_path(self):
        result = _detect(html='<script src="/_next/static/chunks/main.js">')
        self._assert_detected(result, "frameworks", "Next.js")

    def test_react_detected_from_html(self):
        result = _detect(html='<div id="__react_root"></div>')
        self._assert_detected(result, "frameworks", "React")

    # ── CDN / hosting ──

    def test_cloudflare_detected_from_cf_ray_header(self):
        result = _detect(headers={"cf-ray": "abc123-SIN"})
        self._assert_detected(result, "hosting_providers", "Cloudflare")

    def test_vercel_detected_from_header(self):
        result = _detect(headers={"x-vercel-id": "iad1::abc"})
        self._assert_detected(result, "hosting_providers", "Vercel")

    # ── analytics ──

    def test_google_analytics_detected_from_script_url(self):
        result = _detect(
            html='<script src="https://www.google-analytics.com/analytics.js">'
        )
        self._assert_detected(result, "analytics", "Google Analytics")

    def test_google_tag_manager_detected(self):
        result = _detect(
            html='<script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX">'
        )
        self._assert_detected(result, "analytics", "Google Tag Manager")

    # ── detection dict shape ──

    def test_every_detection_has_required_keys(self):
        result = _detect(
            html='<link href="/wp-content/x.css">',
            headers={"Server": "nginx/1.18", "cf-ray": "x"},
        )
        for category, detections in result["technologies"].items():
            for det in detections:
                with self.subTest(category=category, det=det):
                    self.assertIn("name",       det)
                    self.assertIn("confidence", det)
                    self.assertIn("evidence",   det)
                    self.assertIsInstance(det["evidence"], list)
                    self.assertGreater(det["confidence"], 0)


# ---------------------------------------------------------------------------
# fingerprints artefact
# ---------------------------------------------------------------------------

class TestFingerprints(unittest.TestCase):

    def test_headers_artefact_is_normalised_to_lowercase(self):
        result = _detect(headers={"Server": "nginx/1.18", "CF-Ray": "abc"})
        fp_headers = result["fingerprints"]["headers"]
        self.assertIn("server",  fp_headers)
        self.assertIn("cf-ray",  fp_headers)
        self.assertNotIn("Server",  fp_headers)

    def test_cookies_artefact_contains_cookie_names(self):
        result = _detect(cookies=["PHPSESSID=xyz", "wordpress_logged_in=1"])
        self.assertIn("PHPSESSID", result["fingerprints"]["cookies"])

    def test_meta_tags_artefact_captures_generator(self):
        result = _detect(
            html='<meta name="generator" content="Ghost 5.0">'
        )
        self.assertEqual(result["fingerprints"]["meta_tags"].get("generator"), "Ghost 5.0")

    def test_meta_tags_empty_when_no_generator_tag(self):
        result = _detect(html="<html><body>Hello</body></html>")
        self.assertEqual(result["fingerprints"]["meta_tags"], {})


# ---------------------------------------------------------------------------
# HTTPS → HTTP fallback
# ---------------------------------------------------------------------------

class TestHttpsFallback(unittest.TestCase):

    def test_ssl_error_on_https_retries_with_http(self):
        good_resp = _make_response(html="", headers={})

        with patch("tools.techstack_tool._fetch") as mock_fetch:
            mock_fetch.side_effect = [
                requests.exceptions.SSLError("cert failed"),
                good_resp,
            ]
            result = tech_stack_detect("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(mock_fetch.call_count, 2)
        calls = mock_fetch.call_args_list
        self.assertIn("https://", calls[0][0][0])
        self.assertIn("http://",  calls[1][0][0])

    def test_connection_error_on_https_retries_with_http(self):
        good_resp = _make_response(html="", headers={})

        with patch("tools.techstack_tool._fetch") as mock_fetch:
            mock_fetch.side_effect = [
                requests.exceptions.ConnectionError("refused"),
                good_resp,
            ]
            result = tech_stack_detect("example.com")

        self.assertTrue(result["success"])

    def test_both_schemes_fail_returns_error(self):
        with patch("tools.techstack_tool._fetch") as mock_fetch:
            mock_fetch.side_effect = requests.exceptions.ConnectionError("refused")
            result = tech_stack_detect("example.com")

        self.assertFalse(result["success"])
        self.assertIn("error", result)


# ---------------------------------------------------------------------------
# HTML size cap
# ---------------------------------------------------------------------------

class TestBodySizeCap(unittest.TestCase):

    def test_body_larger_than_cap_is_truncated(self):
        """The engine must only see MAX_BODY_BYTES of the body."""
        oversized_html = "A" * (MAX_BODY_BYTES * 2)

        resp = MagicMock()
        resp.headers = {}
        resp.url = "https://example.com"
        resp.status_code = 200
        resp.close.return_value = None
        resp.raw.headers.getlist.return_value = []

        # Yield the oversized body in one chunk
        resp.iter_content.return_value = iter([oversized_html.encode("utf-8")])

        captured: list[str] = []

        def fake_fingerprint(raw_headers, raw_text, *, cookie_names=None):
            captured.append(raw_text)
            return {}, {"headers": {}, "cookies": [], "meta_tags": {}}

        with patch("tools.techstack_tool._fetch", return_value=resp), \
             patch("tools.techstack_tool.fingerprint", side_effect=fake_fingerprint):
            tech_stack_detect("example.com")

        self.assertEqual(len(captured), 1)
        self.assertLessEqual(len(captured[0]), MAX_BODY_BYTES)


# ---------------------------------------------------------------------------
# Improved error handling
# ---------------------------------------------------------------------------

class TestErrorHandling(unittest.TestCase):

    def _error_result(self, exc) -> dict:
        with patch("tools.techstack_tool._fetch", side_effect=exc):
            return tech_stack_detect("example.com")

    def test_timeout_returns_descriptive_error(self):
        result = self._error_result(requests.exceptions.Timeout())
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Request timed out")

    def test_too_many_redirects_returns_descriptive_error(self):
        result = self._error_result(requests.exceptions.TooManyRedirects())
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Too many redirects")

    def test_ssl_error_on_both_schemes_surfaces_ssl_error(self):
        with patch("tools.techstack_tool._fetch",
                   side_effect=requests.exceptions.SSLError("bad cert")):
            result = tech_stack_detect("example.com")
        self.assertFalse(result["success"])
        self.assertIn("SSL error", result["error"])

    def test_connection_error_surfaces_connect_error(self):
        with patch("tools.techstack_tool._fetch",
                   side_effect=requests.exceptions.ConnectionError()):
            result = tech_stack_detect("example.com")
        self.assertFalse(result["success"])
        self.assertIn("connect", result["error"].lower())

    def test_invalid_domain_returns_error(self):
        result = tech_stack_detect("not_a_domain!!!")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Invalid domain format")

    def test_fingerprint_engine_exception_returns_error_dict(self):
        """If the fingerprint engine raises, tech_stack_detect must return
        {success: False, error: ...} instead of propagating the exception.

        Regression test for PR #195 review comment: fingerprint() was called
        outside the surrounding try/except, so any engine exception escaped
        the tool's structured error contract.
        """
        good_resp = _make_response(html="", headers={})

        with patch("tools.techstack_tool._fetch", return_value=good_resp), \
             patch("tools.techstack_tool.fingerprint",
                   side_effect=RuntimeError("unexpected engine failure")):
            result = tech_stack_detect("example.com")

        self.assertFalse(result["success"],
                         "Expected success=False when fingerprint() raises")
        self.assertIn("error", result,
                      "Expected 'error' key in failure response")
        self.assertIsInstance(result["error"], str)
        self.assertGreater(len(result["error"]), 0)

    def test_no_false_positive_apache_nginx_with_unknown_server_header(self):
        """Server: gws must not produce Apache or nginx detections.

        Regression test for PR #195 review: WEB_SERVER_SIGNATURES previously
        included header_name:server markers that fired on any response with a
        Server header, producing bogus Apache/nginx detections for servers
        like GWS, envoy, or any unknown banner.
        """
        result = _detect(headers={"Server": "gws"})
        self.assertTrue(result["success"])
        web_servers = [
            d["name"]
            for d in result["technologies"].get("web_servers", [])
        ]
        self.assertNotIn("Apache", web_servers,
                         "Apache falsely detected from 'Server: gws'")
        self.assertNotIn("nginx", web_servers,
                         "nginx falsely detected from 'Server: gws'")


# ---------------------------------------------------------------------------
# Seam test: fingerprint engine is called correctly
# ---------------------------------------------------------------------------

class TestFingerprintSeam(unittest.TestCase):

    def test_fingerprint_receives_raw_headers_and_body(self):
        raw_headers = {"Server": "nginx/1.18"}
        html = "<html>/wp-content/</html>"
        resp = _make_response(html=html, headers=raw_headers, cookies=["PHPSESSID=x"])

        with patch("tools.techstack_tool._fetch", return_value=resp), \
             patch("tools.techstack_tool.fingerprint") as mock_fp:
            mock_fp.return_value = ({"sentinel": [{"name": "X", "confidence": 99,
                                                    "evidence": []}]},
                                    {"headers": {}, "cookies": [], "meta_tags": {}})
            result = tech_stack_detect("example.com")

        mock_fp.assert_called_once()
        call_kwargs = mock_fp.call_args
        # first positional arg: raw headers dict
        self.assertEqual(call_kwargs[0][0], raw_headers)
        # second positional arg: body string (capped)
        self.assertIsInstance(call_kwargs[0][1], str)
        # keyword: cookie_names extracted
        self.assertIn("PHPSESSID", call_kwargs[1]["cookie_names"])
        # result carries both fields
        self.assertIn("technologies", result)
        self.assertIn("fingerprints",  result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
