from unittest.mock import Mock, MagicMock, patch, call
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

    def test_invalid_domain(self):
        result = dns_enumeration("bad_domain")
        self.assertFalse(result["success"])

    @patch("tools.dns_tool.dns.resolver.resolve")
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

    @patch("tools.dns_tool.dns.resolver.resolve")
    def test_dns_nxdomain_returns_failure(self, mock_resolve):
        import dns.resolver as real_dns
        mock_resolve.side_effect = real_dns.NXDOMAIN
        result = dns_enumeration("thisdoesnotexistatall12345.com")
        self.assertFalse(result["success"])
        self.assertIn("does not exist", result["error"])

    @patch("tools.dns_tool.dns.resolver.resolve")
    def test_dns_no_answer_returns_empty_list(self, mock_resolve):
        import dns.resolver as real_dns
        mock_resolve.side_effect = real_dns.NoAnswer
        result = dns_enumeration("example.com")
        # NoAnswer means success but empty records
        self.assertTrue(result["success"])
        for rtype_records in result["records"].values():
            self.assertEqual(rtype_records, [])

if __name__ == "__main__":
    unittest.main(verbosity=2)