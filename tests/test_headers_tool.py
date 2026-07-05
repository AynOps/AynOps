import unittest
from unittest.mock import patch, Mock
from curl_cffi.requests.errors import RequestsError
from curl_cffi.requests.headers import Headers
from tools.headers_tool import headers_analyzer


def _resp(status_code: int, headers: dict):
    """Build a mock curl_cffi response for a single hop.

    Wraps headers in curl_cffi's real Headers class (not a plain dict)
    -- Headers does case-insensitive lookups (e.g. .get("location")
    matches a "Location" key), matching real response behavior. A plain
    dict would silently fail that lookup and give false test failures
    that look like a production bug but are actually just an inaccurate
    mock.

    headers is a plain dict on input, note this means a genuinely
    duplicate header name can't be represented this way (a Python dict
    literal collapses a repeated key before Headers() ever sees it).
    See test_dict_headers_items_preserves_genuinely_duplicate_headers
    below for the test that specifically covers that case using a
    list of tuples instead.
    """
    m = Mock()
    m.status_code = status_code
    m.headers = Headers(headers)
    return m


class TestHeadersAnalyzer(unittest.TestCase):

    # ------------------------------------------------------------------
    # Domain validation
    # ------------------------------------------------------------------

    def test_invalid_domain_rejected(self):
        result = headers_analyzer("not-a-domain")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Invalid domain format")

    def test_ip_address_rejected(self):
        result = headers_analyzer("192.168.1.1")
        self.assertFalse(result["success"])

    # ------------------------------------------------------------------
    # Successful response (single hop, no redirect)
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get")
    def test_success_returns_correct_structure(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        })
        result = headers_analyzer("example.com")
        self.assertTrue(result["success"])
        self.assertIn("domain", result)
        self.assertIn("headers", result)
        self.assertIn("redirect_chain", result)

    @patch("tools.headers_tool.requests.get")
    def test_hsts_present_and_valid(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertEqual(hsts["issue"], "None")
        self.assertEqual(hsts["severity"], "low")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_missing_flagged_as_high(self, mock_get):
        mock_get.return_value = _resp(200, {})
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertFalse(hsts["present"])
        self.assertEqual(hsts["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_low_max_age_flagged_medium(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=3600",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertIn("max-age", hsts["issue"])
        self.assertEqual(hsts["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_max_age_zero_flagged_high(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=0",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertEqual(hsts["severity"], "high")
        self.assertIn("disables", hsts["issue"])

    @patch("tools.headers_tool.requests.get")
    def test_hsts_negative_max_age_flagged_high(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=-1",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertEqual(hsts["severity"], "high")
        self.assertIn("invalid", hsts["issue"])

    @patch("tools.headers_tool.requests.get")
    def test_hsts_malformed_max_age_value_caught(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=notanumber",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertIn("Could not parse", hsts["issue"])
        self.assertEqual(hsts["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_present_without_max_age_directive(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "includeSubDomains",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertIn("max-age directive is missing", hsts["issue"])
        self.assertEqual(hsts["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_missing_includesubdomains_upgrades_severity(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=31536000",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertIn("includeSubDomains", hsts["issue"])
        self.assertEqual(hsts["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_csp_missing_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {})
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertFalse(csp["present"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_csp_unsafe_inline_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertTrue(csp["present"])
        self.assertIn("unsafe-inline", csp["issue"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_csp_unsafe_eval_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertIn("unsafe-eval", csp["issue"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_csp_wildcard_source_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "default-src *",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertIn("Wildcard", csp["issue"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_csp_missing_default_src_flagged_once(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "script-src 'self'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        issue_count = csp["issue"].count("No restrictive default-src")
        self.assertEqual(issue_count, 1)
        self.assertEqual(csp["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_csp_report_only_mode_detected(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy-Report-Only": "default-src 'self'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertTrue(csp["present"])
        self.assertIn("report-only mode", csp["issue"])
        self.assertEqual(csp["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_combined_duplicate_csp_directives_are_analyzed_correctly(self, mock_get):
        """curl_cffi (like `requests` and like DevTools) already combines
        a header that appears more than once in a real response into one
        comma-joined value during parsing, verify the analysis logic
        correctly flags an unsafe directive even when it's not first in
        an already-combined value.

        Note: this test's mock is built from a Python dict, so it can
        only represent a value that is ALREADY combined into one string.
        It tests the downstream CSP-parsing logic, not curl_cffi's
        own merging mechanism. See
        test_dict_headers_items_preserves_genuinely_duplicate_headers
        for the test that covers the merging mechanism itself using
        genuinely separate header entries.
        """
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "default-src 'self', script-src 'unsafe-inline'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertIn("default-src 'self'", csp["value"])
        self.assertIn("script-src 'unsafe-inline'", csp["value"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_dict_headers_items_preserves_genuinely_duplicate_headers(self, mock_get):
        """Regression test requested in review: the test above
        (test_combined_duplicate_csp_directives_are_analyzed_correctly)
        builds Headers() from a Python dict literal, but a dict
        literal with a duplicate key collapses to a single entry in
        plain Python before Headers() ever receives it, so that test
        never actually exercised curl_cffi's own duplicate-merging
        behavior, only the downstream CSP-parsing logic on a value
        that was already a single combined string.

        This test instead builds a real curl_cffi Headers object from
        a list of tuples, which CAN represent two genuinely separate
        entries for the same header name, unlike a dict, to directly
        verify that dict(resp.headers.items()) in _walk_redirect_chain
        does not silently collapse to just one of them, the way the
        original urllib-based implementation did.
        """
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = Headers([
            ("Content-Security-Policy", "script-src 'unsafe-inline'"),
            ("Content-Security-Policy", "default-src 'self'"),
        ])
        mock_get.return_value = mock_resp

        result = headers_analyzer("example.com")

        csp = result["headers"]["content-security-policy"]
        self.assertIn("script-src 'unsafe-inline'", csp["value"])
        self.assertIn("default-src 'self'", csp["value"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_x_frame_options_deny_accepted(self, mock_get):
        mock_get.return_value = _resp(200, {"X-Frame-Options": "DENY"})
        result = headers_analyzer("example.com")
        xfo = result["headers"]["x-frame-options"]
        self.assertTrue(xfo["present"])
        self.assertEqual(xfo["issue"], "None")

    @patch("tools.headers_tool.requests.get")
    def test_x_frame_options_unrecognized_value_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {"X-Frame-Options": "ALLOW-FROM https://example.com"})
        result = headers_analyzer("example.com")
        xfo = result["headers"]["x-frame-options"]
        self.assertTrue(xfo["present"])
        self.assertIn("Unexpected value", xfo["issue"])
        self.assertEqual(xfo["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_x_content_type_options_nosniff_accepted(self, mock_get):
        mock_get.return_value = _resp(200, {"X-Content-Type-Options": "nosniff"})
        result = headers_analyzer("example.com")
        xcto = result["headers"]["x-content-type-options"]
        self.assertTrue(xcto["present"])
        self.assertEqual(xcto["issue"], "None")

    @patch("tools.headers_tool.requests.get")
    def test_server_header_flagged_as_disclosure(self, mock_get):
        mock_get.return_value = _resp(200, {"Server": "Apache/2.4.41"})
        result = headers_analyzer("example.com")
        self.assertIn("server", result["headers"])
        self.assertIn("exposes technology", result["headers"]["server"]["issue"])

    @patch("tools.headers_tool.requests.get")
    def test_referrer_policy_good_value_accepted(self, mock_get):
        mock_get.return_value = _resp(200, {"Referrer-Policy": "strict-origin-when-cross-origin"})
        result = headers_analyzer("example.com")
        rp = result["headers"]["referrer-policy"]
        self.assertTrue(rp["present"])
        self.assertEqual(rp["issue"], "None")
        self.assertEqual(rp["severity"], "low")

    @patch("tools.headers_tool.requests.get")
    def test_referrer_policy_weak_value_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {"Referrer-Policy": "unsafe-url"})
        result = headers_analyzer("example.com")
        rp = result["headers"]["referrer-policy"]
        self.assertTrue(rp["present"])
        self.assertIn("may leak", rp["issue"])
        self.assertEqual(rp["severity"], "medium")

    # ------------------------------------------------------------------
    # Permissions-Policy content analysis
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get")
    def test_permissions_policy_restrictive_clean(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Permissions-Policy": "camera=(), microphone=()",
        })
        result = headers_analyzer("example.com")
        pp = result["headers"]["permissions-policy"]
        self.assertTrue(pp["present"])
        self.assertEqual(pp["issue"], "None")
        self.assertEqual(pp["severity"], "low")

    @patch("tools.headers_tool.requests.get")
    def test_permissions_policy_wildcard_sensitive_feature_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Permissions-Policy": "camera=*, geolocation=()",
        })
        result = headers_analyzer("example.com")
        pp = result["headers"]["permissions-policy"]
        self.assertTrue(pp["present"])
        self.assertIn("camera", pp["issue"])
        self.assertEqual(pp["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_permissions_policy_missing_flagged_low(self, mock_get):
        mock_get.return_value = _resp(200, {})
        result = headers_analyzer("example.com")
        pp = result["headers"]["permissions-policy"]
        self.assertFalse(pp["present"])
        self.assertEqual(pp["severity"], "low")

    # ------------------------------------------------------------------
    # WAF / bot-challenge detection
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get")
    def test_cloudflare_challenge_page_is_rejected_not_analyzed(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Server": "cloudflare",
            "cf-mitigated": "challenge",
            "X-Frame-Options": "SAMEORIGIN",
        })
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("challenge", result["error"].lower())

    @patch("tools.headers_tool.requests.get")
    def test_normal_cloudflare_site_without_challenge_is_analyzed_normally(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Server": "cloudflare",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })
        result = headers_analyzer("example.com")
        self.assertTrue(result["success"])
        self.assertTrue(result["headers"]["x-frame-options"]["present"])

    # ------------------------------------------------------------------
    # Full redirect-chain recovery
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get")
    def test_no_redirect_single_hop_chain(self, mock_get):
        mock_get.return_value = _resp(200, {"X-Frame-Options": "DENY"})
        result = headers_analyzer("example.com")
        self.assertFalse(result["redirected"])
        self.assertEqual(len(result["redirect_chain"]), 1)
        self.assertEqual(result["final_url"], "https://example.com")
        self.assertEqual(result["requested_url"], "https://example.com")

    @patch("tools.headers_tool.requests.get")
    def test_redirect_captures_each_hops_distinct_headers(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {
                "Location": "https://www.example.com/home",
                "X-Frame-Options": "SAMEORIGIN",
            }),
            _resp(200, {
                "X-Frame-Options": "DENY",
            }),
        ]
        result = headers_analyzer("example.com")

        self.assertTrue(result["redirected"])
        self.assertEqual(len(result["redirect_chain"]), 2)
        self.assertEqual(result["redirect_chain"][0]["status_code"], 301)
        self.assertEqual(
            result["redirect_chain"][0]["headers"]["x-frame-options"], "SAMEORIGIN"
        )
        self.assertEqual(result["redirect_chain"][1]["status_code"], 200)
        self.assertEqual(
            result["redirect_chain"][1]["headers"]["x-frame-options"], "DENY"
        )
        self.assertEqual(result["headers"]["x-frame-options"]["value"], "DENY")
        self.assertEqual(result["final_url"], "https://www.example.com/home")

    @patch("tools.headers_tool.requests.get")
    def test_relative_location_header_is_resolved(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "/new-path"}),
            _resp(200, {"X-Frame-Options": "DENY"}),
        ]
        result = headers_analyzer("example.com")
        self.assertEqual(result["final_url"], "https://example.com/new-path")

    @patch("tools.headers_tool.requests.get")
    def test_self_redirecting_url_fails_explicitly(self, mock_get):
        mock_get.return_value = _resp(301, {
            "Location": "https://example.com",
            "X-Frame-Options": "SAMEORIGIN",
        })
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)
        self.assertNotIn("headers", result)

    @patch("tools.headers_tool.requests.get")
    def test_redirect_loop_does_not_hang(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "https://example.com/b"}),
            _resp(301, {"Location": "https://example.com"}),
        ]
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("loop", result["error"].lower())

    @patch("tools.headers_tool.requests.get")
    def test_redirect_chain_caps_at_max_hops(self, mock_get):
        def make_redirect(i):
            return _resp(301, {"Location": f"https://example.com/{i}"})
        mock_get.side_effect = [make_redirect(i) for i in range(20)]
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertLessEqual(mock_get.call_count, 8)
        self.assertIn("hop", result["error"].lower())

    @patch("tools.headers_tool.requests.get")
    def test_redirect_missing_location_header_stops_cleanly(self, mock_get):
        mock_get.return_value = _resp(301, {})
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("tools.headers_tool.requests.get")
    def test_domain_in_result_reflects_final_destination(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "https://www.example.com/"}),
            _resp(200, {}),
        ]
        result = headers_analyzer("example.com")
        self.assertEqual(result["domain"], "www.example.com")

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get",
           side_effect=RequestsError("Failed to connect"))
    def test_connection_error_returns_failure(self, _):
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("Connection failed", result["error"])

    @patch("tools.headers_tool._walk_redirect_chain", return_value=[])
    def test_empty_hop_list_returns_failure(self, _):
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("tools.headers_tool.requests.get",
           side_effect=Exception("Unexpected error"))
    def test_unexpected_exception_returns_failure(self, _):
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)