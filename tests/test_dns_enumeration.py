from unittest.mock import MagicMock, Mock, patch
import unittest
from tools.dns_tool import dns_enumeration

class TestDnsEnumeration(unittest.TestCase):

    def _make_resolver_answer(self, values):
        """Return a mock dns.resolver answer iterable."""
        records = []
        for v in values:
            r = MagicMock()
            r.__str__ = lambda self, _v=v: _v
            records.append(r)
        return records

    def _make_txt_answer(self, chunks):
        record = Mock()
        record.strings = chunks
        return [record]

    def _make_soa_answer(self):
        record = Mock()
        record.mname = "ns1.example.com."
        record.rname = "hostmaster.example.com."
        record.serial = 1
        record.refresh = 2
        record.retry = 3
        record.expire = 4
        record.minimum = 5
        return [record]

    def _make_caa_answer(self, flags, tag, value):
        record = Mock()
        record.flags = flags
        record.tag = tag
        record.value = value
        return [record]

    def _make_ttl_answer(self, values, ttl):
        records = self._make_resolver_answer(values)
        answer = MagicMock()
        answer.__iter__.return_value = iter(records)
        answer.rrset.ttl = ttl
        return answer

    def test_invalid_domain(self):
        result = dns_enumeration("bad_domain")
        self.assertFalse(result["success"])

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_dns_success_returns_records(self, mock_resolver_class):
        resolver = Mock()
        mock_resolver_class.return_value = resolver

        def side_effect(domain, rtype, lifetime=5, tcp=False):
            import dns.resolver as real_dns

            if domain != "example.com":
                raise real_dns.NoAnswer
            if rtype == "A":
                return self._make_resolver_answer(["93.184.216.34"])
            if rtype == "MX":
                record = Mock()
                record.preference = 10
                record.exchange = "mail.example.com."
                return [record]
            if rtype == "NS":
                return self._make_resolver_answer(["ns1.example.com."])
            if rtype == "TXT":
                return self._make_txt_answer((b"v=spf1 ", b"include:example.com"))
            if rtype == "CNAME":
                return self._make_resolver_answer(["alias.example.com."])
            if rtype == "SOA":
                return self._make_soa_answer()
            raise Exception("no record")

        resolver.resolve.side_effect = side_effect
        result = dns_enumeration("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["records"]["MX"][0]["exchange"], "mail.example.com")
        self.assertEqual(result["records"]["NS"], ["ns1.example.com"])
        self.assertEqual(result["records"]["TXT"], ["v=spf1 include:example.com"])
        self.assertEqual(result["records"]["CNAME"], ["alias.example.com"])
        self.assertEqual(result["records"]["SOA"]["mname"], "ns1.example.com")
        self.assertEqual(result["records"]["SOA"]["rname"], "hostmaster.example.com")
        self.assertIn("subdomains_found", result)
        self.assertEqual(resolver.nameservers, ["1.1.1.1", "8.8.8.8"])
        resolver.resolve.assert_any_call("example.com", "TXT", lifetime=5, tcp=True)
        resolver.resolve.assert_any_call("www.example.com", "A", lifetime=3, tcp=True)

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_dns_nxdomain_returns_failure(self, mock_resolver_class):
        import dns.resolver as real_dns

        resolver = Mock()
        resolver.resolve.side_effect = real_dns.NXDOMAIN
        mock_resolver_class.return_value = resolver
        result = dns_enumeration("thisdoesnotexistatall12345.com")
        self.assertFalse(result["success"])
        self.assertIn("does not exist", result["error"])

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_dns_no_answer_returns_empty_list(self, mock_resolver_class):
        import dns.resolver as real_dns

        resolver = Mock()
        resolver.resolve.side_effect = real_dns.NoAnswer
        mock_resolver_class.return_value = resolver
        result = dns_enumeration("example.com")
        # NoAnswer means success but empty records
        self.assertTrue(result["success"])
        for rtype_records in result["records"].values():
            self.assertEqual(rtype_records, [])

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_caa_records_parsed(self, mock_resolver_class):
        resolver = Mock()
        mock_resolver_class.return_value = resolver

        def side_effect(domain, rtype, lifetime=5, tcp=False):
            import dns.resolver as real_dns

            if domain != "example.com":
                raise real_dns.NoAnswer
            if rtype == "CAA":
                return self._make_caa_answer(0, b"issue", b"letsencrypt.org")
            raise real_dns.NoAnswer

        resolver.resolve.side_effect = side_effect
        result = dns_enumeration("example.com")

        self.assertTrue(result["success"])
        caa = result["records"]["CAA"]
        self.assertEqual(len(caa), 1)
        self.assertEqual(caa[0]["flags"], 0)
        self.assertEqual(caa[0]["tag"], "issue")
        self.assertEqual(caa[0]["value"], "letsencrypt.org")

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_ttl_included_when_available(self, mock_resolver_class):
        resolver = Mock()
        mock_resolver_class.return_value = resolver

        def side_effect(domain, rtype, lifetime=5, tcp=False):
            import dns.resolver as real_dns

            if domain != "example.com":
                raise real_dns.NoAnswer
            if rtype == "A":
                return self._make_ttl_answer(["93.184.216.34"], 300)
            raise real_dns.NoAnswer

        resolver.resolve.side_effect = side_effect
        result = dns_enumeration("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["records"]["A"], ["93.184.216.34"])
        self.assertEqual(result["ttl"]["A"], 300)
        self.assertNotIn("MX", result["ttl"])

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_subdomain_detected_via_aaaa_and_cname(self, mock_resolver_class):
        resolver = Mock()
        mock_resolver_class.return_value = resolver

        def side_effect(domain, rtype, lifetime=5, tcp=False):
            import dns.resolver as real_dns

            if domain == "example.com":
                raise real_dns.NoAnswer
            if domain == "www.example.com" and rtype == "AAAA":
                return self._make_resolver_answer(["2606:2800:220:1:248:1893:25c8:1946"])
            if domain == "mail.example.com" and rtype == "CNAME":
                return self._make_resolver_answer(["example.com."])
            raise real_dns.NoAnswer

        resolver.resolve.side_effect = side_effect
        result = dns_enumeration("example.com")

        self.assertTrue(result["success"])
        self.assertIn("www.example.com", result["subdomains_found"])
        self.assertIn("mail.example.com", result["subdomains_found"])
        self.assertNotIn("ftp.example.com", result["subdomains_found"])
        self.assertEqual(result["subdomains_found"].count("www.example.com"), 1)
        resolver.resolve.assert_any_call("www.example.com", "A", lifetime=3, tcp=True)
        resolver.resolve.assert_any_call("www.example.com", "AAAA", lifetime=3, tcp=True)
        resolver.resolve.assert_any_call("mail.example.com", "CNAME", lifetime=3, tcp=True)

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_resolver_metadata_in_output(self, mock_resolver_class):
        import dns.resolver as real_dns

        resolver = Mock()
        resolver.resolve.side_effect = real_dns.NoAnswer
        mock_resolver_class.return_value = resolver
        result = dns_enumeration("example.com")

        self.assertTrue(result["success"])
        self.assertIn("resolver", result)
        self.assertEqual(result["resolver"]["nameservers"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(result["resolver"]["lifetime"], 5)

if __name__ == "__main__":
    unittest.main(verbosity=2)
