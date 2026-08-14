from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlparse

import dns.rdata
import dns.rdataclass
import dns.rdatatype

from tools.subdomain_takeover_tool import subdomain_takeover


class _ResolverAnswer(list):
    def __init__(self, records, ttl):
        super().__init__(records)
        self.rrset = SimpleNamespace(ttl=ttl)


def _enumeration_result(subdomains):
    return {
        "success": True,
        "domain": "example.com",
        "records": {},
        "subdomains_found": subdomains,
    }


def _cname_record(target):
    record = Mock()
    record.__str__ = lambda self: target
    return record


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_vulnerable_subdomain_is_flagged(mock_enum, mock_resolver_class, mock_get):
    """Dangling CNAME to a fingerprinted service + takeover indicator => vulnerable."""
    mock_enum.return_value = _enumeration_result(["blog.example.com", "www.example.com"])

    import dns.resolver as real_dns

    resolver = Mock()
    resolver.resolve.side_effect = lambda name, rtype, **kwargs: (
        [_cname_record("example.ghost.io.")]
        if name == "blog.example.com"
        else (_ for _ in ()).throw(real_dns.NoAnswer)
    )
    mock_resolver_class.return_value = resolver

    mock_response = Mock()
    mock_response.status_code = 404
    mock_response.text = "404 Domain Not Found"
    mock_get.return_value = mock_response

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["subdomains_checked"] == 2
    assert result["total_vulnerable"] == 1
    assert result["vulnerable"][0]["subdomain"] == "blog.example.com"
    assert result["vulnerable"][0]["cname"] == "example.ghost.io"
    assert result["vulnerable"][0]["service"] == "Ghost"
    assert result["vulnerable"][0]["severity"] == "HIGH"
    assert "reason" in result["vulnerable"][0]
    assert result["safe"] == ["www.example.com"]
    mock_get.assert_called_once()


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_fingerprint_match_without_indicator_is_safe(mock_enum, mock_resolver_class, mock_get):
    """CNAME matches a fingerprint but the service is still live => safe."""
    mock_enum.return_value = _enumeration_result(["blog.example.com"])

    resolver = Mock()
    resolver.resolve.return_value = [_cname_record("example.ghost.io.")]
    mock_resolver_class.return_value = resolver

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "Welcome to my blog"
    mock_get.return_value = mock_response

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["vulnerable"] == []
    assert result["total_vulnerable"] == 0
    assert result["safe"] == ["blog.example.com"]


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_no_dangling_cname_is_safe(mock_enum, mock_resolver_class, mock_get):
    """Subdomain with no CNAME record at all => safe, and no HTTP probe is made."""
    mock_enum.return_value = _enumeration_result(["www.example.com", "mail.example.com"])

    import dns.resolver as real_dns

    resolver = Mock()
    resolver.resolve.side_effect = real_dns.NoAnswer
    mock_resolver_class.return_value = resolver

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["subdomains_checked"] == 2
    assert result["vulnerable"] == []
    assert result["total_vulnerable"] == 0
    assert result["safe"] == ["www.example.com", "mail.example.com"]
    mock_get.assert_not_called()


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_aggregate_counts(mock_enum, mock_resolver_class, mock_get):
    """Mixed results: one vulnerable (GitHub Pages, body-based), one safe (live), one safe (no CNAME)."""
    mock_enum.return_value = _enumeration_result(
        ["dev.example.com", "blog.example.com", "www.example.com"]
    )

    import dns.resolver as real_dns

    cnames = {
        "dev.example.com": [_cname_record("user.github.io.")],
        "blog.example.com": [_cname_record("example.myshopify.com.")],
    }

    def resolve_side_effect(name, rtype, **kwargs):
        if name in cnames:
            return cnames[name]
        raise real_dns.NoAnswer

    resolver = Mock()
    resolver.resolve.side_effect = resolve_side_effect
    mock_resolver_class.return_value = resolver

    def http_side_effect(url, **kwargs):
        response = Mock()
        host = (urlparse(url).hostname or "").lower()
        if host == "dev.example.com":
            # GitHub Pages: takeover indicator is the unclaimed-site body string.
            # status_code is intentionally 200 (not 404) to prove the match keys
            # on the response body, not on a bare status code.
            response.status_code = 200
            response.text = "There isn't a GitHub Pages site here."
        else:
            # Shopify CNAME but shop is live
            response.status_code = 200
            response.text = "My awesome shop"
        return response

    mock_get.side_effect = http_side_effect

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["subdomains_checked"] == 3
    assert result["total_vulnerable"] == 1
    assert result["vulnerable"][0]["subdomain"] == "dev.example.com"
    assert result["vulnerable"][0]["service"] == "GitHub Pages"
    assert result["safe"] == ["blog.example.com", "www.example.com"]


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_azure_vulnerable_matches_body(mock_enum, mock_resolver_class, mock_get):
    """Azure CNAME + Azure-specific body string => vulnerable, probed over HTTPS first."""
    mock_enum.return_value = _enumeration_result(["app.example.com"])

    resolver = Mock()
    resolver.resolve.return_value = [_cname_record("app.azurewebsites.net.")]
    mock_resolver_class.return_value = resolver

    mock_response = Mock()
    # A non-404 status proves the match keys on the body, not on the status code.
    mock_response.status_code = 200
    mock_response.text = "404 Web Site not found"
    mock_get.return_value = mock_response

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["total_vulnerable"] == 1
    assert result["vulnerable"][0]["subdomain"] == "app.example.com"
    assert result["vulnerable"][0]["service"] == "Azure"
    # HTTPS is attempted first and succeeded, so exactly one request is made to https://.
    assert mock_get.call_count == 1
    first_url = urlparse(mock_get.call_args_list[0].args[0])
    assert first_url.scheme == "https"
    assert first_url.hostname == "app.example.com"


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_https_failure_falls_back_to_http(mock_enum, mock_resolver_class, mock_get):
    """HTTPS connection fails => probe falls back to HTTP and still confirms takeover."""
    import requests as real_requests

    mock_enum.return_value = _enumeration_result(["app.example.com"])

    resolver = Mock()
    resolver.resolve.return_value = [_cname_record("app.azurewebsites.net.")]
    mock_resolver_class.return_value = resolver

    def http_side_effect(url, **kwargs):
        if url.startswith("https://"):
            raise real_requests.exceptions.ConnectionError("HTTPS unavailable")
        response = Mock()
        response.status_code = 404
        response.text = "404 Web Site not found"
        return response

    mock_get.side_effect = http_side_effect

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["total_vulnerable"] == 1
    assert result["vulnerable"][0]["service"] == "Azure"
    # HTTPS tried first (and failed), then HTTP fallback succeeded.
    assert mock_get.call_count == 2
    first_url = urlparse(mock_get.call_args_list[0].args[0])
    second_url = urlparse(mock_get.call_args_list[1].args[0])
    assert first_url.scheme == "https"
    assert first_url.hostname == "app.example.com"
    assert second_url.scheme == "http"
    assert second_url.hostname == "app.example.com"


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_both_schemes_fail_is_safe(mock_enum, mock_resolver_class, mock_get):
    """Neither HTTPS nor HTTP connects => not confirmed => safe."""
    import requests as real_requests

    mock_enum.return_value = _enumeration_result(["app.example.com"])

    resolver = Mock()
    resolver.resolve.return_value = [_cname_record("app.azurewebsites.net.")]
    mock_resolver_class.return_value = resolver

    mock_get.side_effect = real_requests.exceptions.ConnectionError("unreachable")

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["total_vulnerable"] == 0
    assert result["safe"] == ["app.example.com"]
    assert mock_get.call_count == 2


@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_invalid_domain(mock_enum):
    result = subdomain_takeover("bad_domain")
    assert result["success"] is False
    assert "error" in result
    mock_enum.assert_not_called()


@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_enumeration_failure_propagates(mock_enum):
    mock_enum.return_value = {"success": False, "error": "Domain example.com does not exist"}
    result = subdomain_takeover("example.com")
    assert result["success"] is False
    assert "does not exist" in result["error"]


@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
def test_invalid_utf8_dns_record_does_not_escape_enumeration(mock_resolver_class):
    """A malformed TXT payload must not abort takeover checking."""
    import dns.resolver as real_dns

    txt_record = dns.rdata.from_wire(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        bytes([4, 0xff, 0xfe, 0x41, 0x42]),
        0,
        5,
    )
    resolver = Mock()

    def side_effect(domain, rtype, lifetime=5, tcp=False):
        if domain == "example.com" and rtype == "TXT":
            return _ResolverAnswer([txt_record], 300)
        raise real_dns.NoAnswer

    resolver.resolve.side_effect = side_effect
    mock_resolver_class.return_value = resolver

    try:
        result = subdomain_takeover("example.com")
    except Exception as exc:
        assert False, f"subdomain_takeover raised {type(exc).__name__}: {exc}"

    assert result["success"] is True
    assert result["domain"] == "example.com"
    assert result["subdomains_checked"] == 0


if __name__ == "__main__":
    unittest.main(verbosity=2)
