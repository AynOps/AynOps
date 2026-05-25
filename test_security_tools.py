import os
import ssl
import socket
import unittest
from unittest.mock import Mock, MagicMock, patch, call

from main import (
    cve_lookup,
    ip_reputation,
    whois_lookup,
    dns_enumeration,
    port_scan,
    ssl_inspect,
    tech_stack_detect,
    full_recon,
    is_valid_domain,
    get_cvss_details,
    get_english_description,
)


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

class TestHelpers(unittest.TestCase):

    # ── is_valid_domain ──────────────────────────────────────
    def test_valid_domains(self):
        for d in ["example.com", "sub.example.com", "a.b.c.org", "xn--nxasmq6b.com"]:
            with self.subTest(domain=d):
                self.assertTrue(is_valid_domain(d))

    def test_invalid_domains(self):
        for d in ["", "localhost", "192.168.1.1", "no-tld", "bad domain.com", "-start.com"]:
            with self.subTest(domain=d):
                self.assertFalse(is_valid_domain(d))

    # ── get_cvss_details ─────────────────────────────────────
    def test_cvss_v31_extraction(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}
                ]
            }
        }
        result = get_cvss_details(cve)
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["score"], 7.5)

    def test_cvss_falls_back_to_v2(self):
        cve = {
            "metrics": {
                "cvssMetricV2": [
                    {"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}
                ]
            }
        }
        result = get_cvss_details(cve)
        self.assertEqual(result["severity"], "MEDIUM")

    def test_cvss_no_metrics_returns_unknown(self):
        result = get_cvss_details({})
        self.assertEqual(result["severity"], "Unknown")
        self.assertIsNone(result["score"])

    # ── get_english_description ──────────────────────────────
    def test_english_description_extracted(self):
        cve = {"descriptions": [{"lang": "fr", "value": "Bonjour"}, {"lang": "en", "value": "Hello"}]}
        self.assertEqual(get_english_description(cve), "Hello")

    def test_no_english_description_returns_empty(self):
        cve = {"descriptions": [{"lang": "fr", "value": "Bonjour"}]}
        self.assertEqual(get_english_description(cve), "")

    def test_empty_descriptions_returns_empty(self):
        self.assertEqual(get_english_description({}), "")


# ─────────────────────────────────────────────────────────────
# TOOL 1 — WHOIS LOOKUP
# ─────────────────────────────────────────────────────────────

class TestWhoisLookup(unittest.TestCase):

    def _mock_whois_result(self):
        m = MagicMock()
        m.registrar = "Example Registrar LLC"
        m.whois_server = "whois.example.com"
        m.creation_date = "2010-01-01"
        m.expiration_date = "2030-01-01"
        m.updated_date = "2023-06-15"
        m.name_servers = ["ns1.example.com", "ns2.example.com"]
        m.status = "clientTransferProhibited"
        m.emails = "admin@example.com"
        m.dnssec = "unsigned"
        m.country = "US"
        m.org = "Example Org"
        return m

    @patch("main.whois.whois")
    def test_whois_success(self, mock_whois):
        mock_whois.return_value = self._mock_whois_result()
        result = whois_lookup("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["registrar"], "Example Registrar LLC")
        self.assertEqual(result["country"], "US")
        self.assertEqual(result["org"], "Example Org")

    @patch("main.whois.whois")
    def test_whois_list_dates_normalized(self, mock_whois):
        m = self._mock_whois_result()
        m.creation_date = ["2010-01-01", "2010-01-02"]  # some registrars return lists
        mock_whois.return_value = m
        result = whois_lookup("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["creation_date"], "2010-01-01")  # first item taken

    def test_whois_invalid_domain(self):
        result = whois_lookup("not-a-domain")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("main.whois.whois", side_effect=Exception("WHOIS server timeout"))
    def test_whois_exception_caught(self, _):
        result = whois_lookup("example.com")
        self.assertFalse(result["success"])
        self.assertIn("WHOIS server timeout", result["error"])


# ─────────────────────────────────────────────────────────────
# TOOL 2 — DNS ENUMERATION
# ─────────────────────────────────────────────────────────────

class TestDnsEnumeration(unittest.TestCase):

    def _make_resolver_answer(self, values):
        """Return a mock dns.resolver answer iterable."""
        records = []
        for v in values:
            r = MagicMock()
            r.__str__ = lambda self, _v=v: _v
            records.append(r)
        return records

    def test_invalid_domain(self):
        result = dns_enumeration("bad_domain")
        self.assertFalse(result["success"])

    @patch("main.dns.resolver.resolve")
    def test_dns_success_returns_records(self, mock_resolve):
        def side_effect(domain, rtype, lifetime=5):
            if rtype == "A":
                return self._make_resolver_answer(["93.184.216.34"])
            raise Exception("no record")

        mock_resolve.side_effect = side_effect
        result = dns_enumeration("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["domain"], "example.com")
        self.assertIn("records", result)
        self.assertIn("subdomains_found", result)

    @patch("main.dns.resolver.resolve")
    def test_dns_nxdomain_returns_failure(self, mock_resolve):
        import dns.resolver as real_dns
        mock_resolve.side_effect = real_dns.NXDOMAIN
        result = dns_enumeration("thisdoesnotexistatall12345.com")
        self.assertFalse(result["success"])
        self.assertIn("does not exist", result["error"])

    @patch("main.dns.resolver.resolve")
    def test_dns_no_answer_returns_empty_list(self, mock_resolve):
        import dns.resolver as real_dns
        mock_resolve.side_effect = real_dns.NoAnswer
        result = dns_enumeration("example.com")
        # NoAnswer means success but empty records
        self.assertTrue(result["success"])
        for rtype_records in result["records"].values():
            self.assertEqual(rtype_records, [])


# ─────────────────────────────────────────────────────────────
# TOOL 3 — PORT SCAN
# ─────────────────────────────────────────────────────────────

class TestPortScan(unittest.TestCase):

    def _make_scanner_mock(self, host="93.184.216.34", open_ports=None):
        open_ports = open_ports or {80: {"state": "open", "name": "http", "product": "nginx", "version": "1.18"}}
        scanner = MagicMock()
        scanner.all_hosts.return_value = [host]
        scanner[host].hostname.return_value = "example.com"
        scanner[host].state.return_value = "up"
        scanner[host].all_protocols.return_value = ["tcp"]
        scanner[host]["tcp"].items.return_value = open_ports.items()
        return scanner

    @patch("main.nmap.PortScanner")
    def test_basic_scan_success(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock()
        result = port_scan("example.com", "basic")

        self.assertTrue(result["success"])
        self.assertEqual(result["target"], "example.com")
        self.assertEqual(result["scan_type"], "basic")
        self.assertEqual(result["hosts_found"], 1)
        self.assertIn("results", result)

    @patch("main.nmap.PortScanner")
    def test_scan_includes_port_details(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock()
        result = port_scan("example.com")

        port_entry = result["results"][0]["protocols"]["tcp"][0]
        self.assertEqual(port_entry["port"], 80)
        self.assertEqual(port_entry["service"], "http")
        self.assertEqual(port_entry["product"], "nginx")

    @patch("main.nmap.PortScanner")
    def test_scan_no_hosts_found(self, mock_cls):
        scanner = MagicMock()
        scanner.all_hosts.return_value = []
        mock_cls.return_value = scanner

        result = port_scan("192.0.2.1")
        self.assertTrue(result["success"])
        self.assertEqual(result["hosts_found"], 0)
        self.assertEqual(result["results"], [])

    @patch("main.nmap.PortScanner")
    def test_nmap_not_installed_error(self, mock_cls):
        import nmap
        mock_cls.return_value.scan.side_effect = nmap.PortScannerError("nmap not found")
        result = port_scan("example.com")

        self.assertFalse(result["success"])
        self.assertIn("Nmap not found", result["error"])

    @patch("main.nmap.PortScanner")
    def test_unknown_scan_type_defaults_to_basic(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock()
        result = port_scan("example.com", scan_type="invalid_type")
        # Should still succeed — falls back to "-F"
        self.assertTrue(result["success"])


# ─────────────────────────────────────────────────────────────
# TOOL 4 — SSL INSPECTION
# ─────────────────────────────────────────────────────────────

class TestSslInspect(unittest.TestCase):

    def _make_cert(self, days_valid=365):
        from datetime import datetime, timedelta
        now = datetime.utcnow()
        not_before = (now - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
        not_after = (now + timedelta(days=days_valid)).strftime("%b %d %H:%M:%S %Y GMT")
        return {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "serialNumber": "DEADBEEF",
            "notBefore": not_before,
            "notAfter": not_after,
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "version": 3,
        }

    def test_invalid_domain(self):
        result = ssl_inspect("not-valid")
        self.assertFalse(result["success"])

    @patch("main.socket.create_connection")
    @patch("main.ssl.create_default_context")
    def test_ssl_success(self, mock_ctx_cls, mock_conn):
        cert = self._make_cert(days_valid=90)
        mock_conn_obj = MagicMock()
        mock_conn.return_value = mock_conn_obj

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = cert
        mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_sock.version.return_value = "TLSv1.3"

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_ctx_cls.return_value = mock_ctx

        result = ssl_inspect("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["tls_version"], "TLSv1.3")
        self.assertEqual(result["cipher"]["bits"], 256)
        self.assertFalse(result["certificate"]["expired"])
        self.assertIn("example.com", result["certificate"]["subject_alt_names"])

    @patch("main.socket.create_connection")
    @patch("main.ssl.create_default_context")
    def test_ssl_expiry_flags(self, mock_ctx_cls, mock_conn):
        cert = self._make_cert(days_valid=10)  # expiring soon
        mock_conn_obj = MagicMock()
        mock_conn.return_value = mock_conn_obj

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = cert
        mock_ssl_sock.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
        mock_ssl_sock.version.return_value = "TLSv1.3"

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_ctx_cls.return_value = mock_ctx

        result = ssl_inspect("example.com")
        self.assertTrue(result["certificate"]["expiring_soon"])
        self.assertFalse(result["certificate"]["expired"])

    @patch("main.socket.create_connection", side_effect=socket.timeout)
    @patch("main.ssl.create_default_context")
    def test_ssl_timeout(self, mock_ctx_cls, _):
        result = ssl_inspect("example.com")
        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"])

    @patch("main.socket.create_connection")
    @patch("main.ssl.create_default_context")
    def test_ssl_cert_verification_error(self, mock_ctx_cls, mock_conn):
        mock_conn_obj = MagicMock()
        mock_conn.return_value = mock_conn_obj

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("cert verify failed")
        mock_ctx_cls.return_value = mock_ctx

        result = ssl_inspect("example.com")
        self.assertFalse(result["success"])
        self.assertIn("SSL verification failed", result["error"])


# ─────────────────────────────────────────────────────────────
# TOOL 5 — TECH STACK DETECTION
# ─────────────────────────────────────────────────────────────

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

    @patch("main.requests.get")
    def test_detects_web_server(self, mock_get):
        mock_get.return_value = self._make_response()
        result = tech_stack_detect("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["technologies"]["web_server"], "nginx/1.18")
        self.assertEqual(result["technologies"]["powered_by"], "PHP/8.1")

    @patch("main.requests.get")
    def test_detects_cloudflare_cdn(self, mock_get):
        headers = {"cf-ray": "abc123", "cf-cache-status": "HIT"}
        mock_get.return_value = self._make_response(headers=headers)
        result = tech_stack_detect("example.com")

        self.assertIn("Cloudflare", result["technologies"]["cdn"])

    @patch("main.requests.get")
    def test_detects_wordpress_cms(self, mock_get):
        html = '<link rel="stylesheet" href="/wp-content/themes/theme.css">'
        mock_get.return_value = self._make_response(html=html)
        result = tech_stack_detect("example.com")

        self.assertIn("WordPress", result["technologies"]["cms"])

    @patch("main.requests.get")
    def test_detects_react_framework(self, mock_get):
        html = '<script src="/_next/static/chunks/main.js"></script>'
        mock_get.return_value = self._make_response(html=html)
        result = tech_stack_detect("example.com")

        self.assertIn("Next.js", result["technologies"]["javascript_frameworks"])

    @patch("main.requests.get")
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

    @patch("main.requests.get")
    def test_poor_security_header_rating(self, mock_get):
        mock_get.return_value = self._make_response(headers={})
        result = tech_stack_detect("example.com")

        self.assertEqual(result["security_headers"]["score"], "0%")
        self.assertEqual(result["security_headers"]["rating"], "Poor")

    @patch("main.requests.get", side_effect=Exception("Connection refused"))
    def test_connection_error_caught(self, _):
        result = tech_stack_detect("example.com")
        self.assertFalse(result["success"])


# ─────────────────────────────────────────────────────────────
# TOOL 6 — CVE LOOKUP  (original tests kept + new ones)
# ─────────────────────────────────────────────────────────────

class TestCveLookup(unittest.TestCase):

    @patch("main.requests.get")
    def test_cve_lookup_returns_nvd_results(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "published": "2021-10-05T12:15:07.000",
                        "lastModified": "2024-11-21T05:31:44.123",
                        "descriptions": [{"lang": "en", "value": "Path traversal vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"baseSeverity": "CRITICAL", "cvssData": {"baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ],
        }
        mock_get.return_value = response

        result = cve_lookup("apache", "2.4.49")

        self.assertTrue(result["success"])
        self.assertEqual(result["software"], "apache")
        self.assertEqual(result["version"], "2.4.49")
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-41773")
        self.assertEqual(result["cves"][0]["severity"], "CRITICAL")
        self.assertEqual(result["cves"][0]["score"], 9.8)
        mock_get.assert_called_once()

    @patch("main.requests.get")
    def test_cve_lookup_empty_results(self, mock_get):
        response = Mock()
        response.json.return_value = {"totalResults": 0, "vulnerabilities": []}
        mock_get.return_value = response

        result = cve_lookup("unknownsoftware", "9.9.9")
        self.assertTrue(result["success"])
        self.assertEqual(result["total_results"], 0)
        self.assertEqual(result["cves"], [])

    def test_cve_lookup_empty_software_rejected(self):
        result = cve_lookup("", "1.0")
        self.assertFalse(result["success"])
        self.assertIn("required", result["error"])

    def test_cve_lookup_empty_version_rejected(self):
        result = cve_lookup("apache", "")
        self.assertFalse(result["success"])

    def test_cve_lookup_whitespace_only_rejected(self):
        result = cve_lookup("   ", "   ")
        self.assertFalse(result["success"])

    @patch("main.requests.get")
    def test_cve_lookup_multiple_cves(self, mock_get):
        def make_vuln(cve_id, score):
            return {
                "cve": {
                    "id": cve_id,
                    "published": "2021-01-01T00:00:00.000",
                    "lastModified": "2021-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"baseSeverity": "HIGH", "cvssData": {"baseScore": score}}
                        ]
                    },
                }
            }

        response = Mock()
        response.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [make_vuln("CVE-2021-00001", 8.0), make_vuln("CVE-2021-00002", 7.5)],
        }
        mock_get.return_value = response

        result = cve_lookup("nginx", "1.18")
        self.assertEqual(len(result["cves"]), 2)
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-00001")

    @patch("main.requests.get", side_effect=Exception("NVD unreachable"))
    def test_cve_lookup_exception_caught(self, _):
        result = cve_lookup("apache", "2.4")
        self.assertFalse(result["success"])
        self.assertIn("NVD unreachable", result["error"])


# ─────────────────────────────────────────────────────────────
# TOOL 7 — IP REPUTATION  (original tests kept + new ones)
# ─────────────────────────────────────────────────────────────

class TestIpReputation(unittest.TestCase):

    def test_ip_reputation_requires_valid_ip_and_api_key(self):
        self.assertFalse(ip_reputation("not-an-ip")["success"])

        with patch.dict(os.environ, {}, clear=True):
            result = ip_reputation("1.2.3.4")

        self.assertFalse(result["success"])
        self.assertIn("ABUSEIPDB_API_KEY", result["error"])

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("main.requests.get")
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
            }
        }
        mock_get.return_value = response

        result = ip_reputation("1.2.3.4")

        self.assertTrue(result["success"])
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["abuse_confidence_score"], 95)
        self.assertEqual(result["total_reports"], 342)
        self.assertEqual(result["country"], "CN")
        self.assertEqual(result["isp"], "Example ISP")
        mock_get.assert_called_once()

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("main.requests.get")
    def test_low_score_not_malicious(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "data": {"abuseConfidenceScore": 5, "totalReports": 1,
                     "countryCode": "US", "isp": "Good ISP",
                     "domain": "good.net", "usageType": "ISP",
                     "lastReportedAt": None}
        }
        mock_get.return_value = response

        result = ip_reputation("8.8.8.8")
        self.assertTrue(result["success"])
        self.assertFalse(result["is_malicious"])  # score < 25

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("main.requests.get")
    def test_score_exactly_25_is_malicious(self, mock_get):
        """Boundary: score == 25 should be flagged malicious."""
        response = Mock()
        response.json.return_value = {
            "data": {"abuseConfidenceScore": 25, "totalReports": 5,
                     "countryCode": "RU", "isp": "Some ISP",
                     "domain": "bad.net", "usageType": "Hosting",
                     "lastReportedAt": None}
        }
        mock_get.return_value = response

        result = ip_reputation("1.1.1.1")
        self.assertTrue(result["is_malicious"])

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


# ─────────────────────────────────────────────────────────────
# TOOL 8 — FULL RECON
# ─────────────────────────────────────────────────────────────

class TestFullRecon(unittest.TestCase):

    def test_invalid_domain_rejected(self):
        result = full_recon("not-a-domain")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("main.whois_lookup", return_value={"success": True, "domain": "example.com"})
    @patch("main.dns_enumeration", return_value={"success": True, "records": {}})
    @patch("main.port_scan", return_value={"success": True, "results": []})
    @patch("main.ssl_inspect", return_value={"success": True, "certificate": {}})
    @patch("main.tech_stack_detect", return_value={"success": True, "technologies": {}})
    def test_full_recon_calls_all_tools(self, mock_tech, mock_ssl, mock_ports, mock_dns, mock_whois):
        result = full_recon("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["domain"], "example.com")
        self.assertIn("scanned_at", result)
        self.assertIn("results", result)

        # All 5 subtool results present
        self.assertIn("whois", result["results"])
        self.assertIn("dns", result["results"])
        self.assertIn("ports", result["results"])
        self.assertIn("ssl", result["results"])
        self.assertIn("techstack", result["results"])

        mock_whois.assert_called_once_with("example.com")
        mock_dns.assert_called_once_with("example.com")
        mock_ssl.assert_called_once_with("example.com")
        mock_tech.assert_called_once_with("example.com")

    @patch("main.whois_lookup", side_effect=Exception("WHOIS exploded"))
    @patch("main.dns_enumeration", return_value={"success": True})
    @patch("main.port_scan", return_value={"success": True})
    @patch("main.ssl_inspect", return_value={"success": True})
    @patch("main.tech_stack_detect", return_value={"success": True})
    def test_full_recon_tool_failure_isolated(self, mock_tech, mock_ssl, mock_ports, mock_dns, mock_whois):
        """One tool crashing must not crash the whole recon."""
        result = full_recon("example.com")

        self.assertTrue(result["success"])
        # The failing tool should have an error, others should be fine
        self.assertFalse(result["results"]["whois"]["success"])
        self.assertTrue(result["results"]["dns"]["success"])

    @patch("main.whois_lookup", return_value={"success": True})
    @patch("main.dns_enumeration", return_value={"success": True})
    @patch("main.port_scan", return_value={"success": True})
    @patch("main.ssl_inspect", return_value={"success": True})
    @patch("main.tech_stack_detect", return_value={"success": True})
    def test_full_recon_scanned_at_is_iso_format(self, *_):
        from datetime import datetime
        result = full_recon("example.com")
        # Should be parseable ISO timestamp ending in Z
        ts = result["scanned_at"]
        self.assertTrue(ts.endswith("Z"))
        datetime.fromisoformat(ts.rstrip("Z"))  # raises if invalid


if __name__ == "__main__":
    unittest.main(verbosity=2)