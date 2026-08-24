from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlparse

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.name
import dns.resolver
import pytest

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
    assert result.get("unknown") == []
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
    assert result.get("unknown") == []


@pytest.mark.parametrize(
    "no_cname_error",
    [
        pytest.param(dns.resolver.NoAnswer, id="no-answer"),
        pytest.param(dns.resolver.NXDOMAIN, id="nxdomain"),
    ],
)
@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_no_dangling_cname_is_safe(
    mock_enum, mock_resolver_class, mock_get, no_cname_error
):
    """Subdomain with no CNAME record at all => safe, and no HTTP probe is made."""
    mock_enum.return_value = _enumeration_result(["www.example.com", "mail.example.com"])

    resolver = Mock()
    resolver.resolve.side_effect = no_cname_error
    mock_resolver_class.return_value = resolver

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["subdomains_checked"] == 2
    assert result["vulnerable"] == []
    assert result["total_vulnerable"] == 0
    assert result["safe"] == ["www.example.com", "mail.example.com"]
    assert result["unknown"] == []
    mock_get.assert_not_called()


@pytest.mark.parametrize(
    "dns_error",
    [
        pytest.param(dns.resolver.NoNameservers, id="no-nameservers"),
        pytest.param(dns.resolver.LifetimeTimeout, id="lifetime-timeout"),
        pytest.param(dns.resolver.YXDOMAIN, id="yxdomain"),
        pytest.param(dns.name.NameTooLong, id="name-too-long"),
    ],
)
@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_dns_resolution_errors_are_unknown_not_safe(
    mock_enum, mock_resolver_class, mock_get, dns_error
):
    """Operational CNAME lookup failures must not be reported as safe."""
    mock_enum.return_value = _enumeration_result(["app.example.com"])
    resolver = Mock()
    resolver.resolve.side_effect = dns_error
    mock_resolver_class.return_value = resolver

    result = subdomain_takeover("example.com")

    assert result["vulnerable"] == []
    assert result["safe"] == []
    assert result["unknown"] == [
        {
            "subdomain": "app.example.com",
            "reason": "Unable to resolve CNAME record",
            "dns_error": f"{dns_error.__name__}: {dns_error()}",
        }
    ]
    mock_get.assert_not_called()


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_unexpected_dns_failure_propagates_without_http_probe(
    mock_enum, mock_resolver_class, mock_get
):
    """Unexpected non-dnspython resolver failures remain visible to callers."""
    mock_enum.return_value = _enumeration_result(["app.example.com"])
    resolver = Mock()
    resolver.resolve.side_effect = RuntimeError("resolver invariant broken")
    mock_resolver_class.return_value = resolver

    with pytest.raises(RuntimeError, match="resolver invariant broken"):
        subdomain_takeover("example.com")

    mock_get.assert_not_called()


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_unsupported_cname_service_is_unknown_not_safe(
    mock_enum, mock_resolver_class, mock_get
):
    """A CNAME outside the known fingerprints must remain an unknown result."""
    mock_enum.return_value = _enumeration_result(["app.example.com"])
    resolver = Mock()
    resolver.resolve.return_value = [_cname_record("app.unsupported.example.")]
    mock_resolver_class.return_value = resolver

    result = subdomain_takeover("example.com")

    assert result["vulnerable"] == []
    assert result["safe"] == []
    assert result["unknown"] == [
        {
            "subdomain": "app.example.com",
            "reason": "CNAME points to an unsupported service",
        }
    ]
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
    assert result.get("unknown") == []


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
    assert result.get("unknown") == []
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
def test_both_schemes_fail_is_unknown(mock_enum, mock_resolver_class, mock_get):
    """Neither HTTPS nor HTTP connects => the probe outcome is unknown."""
    import requests as real_requests

    mock_enum.return_value = _enumeration_result(["app.example.com"])

    resolver = Mock()
    resolver.resolve.return_value = [_cname_record("app.azurewebsites.net.")]
    mock_resolver_class.return_value = resolver

    mock_get.side_effect = real_requests.exceptions.ConnectionError("unreachable")

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["total_vulnerable"] == 0
    assert result["safe"] == []
    assert result["unknown"][0]["subdomain"] == "app.example.com"
    assert result["unknown"][0]["reason"] == "Unable to complete HTTP probe over HTTPS or HTTP"
    assert [error["scheme"] for error in result["unknown"][0]["probe_errors"]] == [
        "https",
        "http",
    ]
    assert all("ConnectionError: unreachable" in error["error"] for error in result["unknown"][0]["probe_errors"])
    assert mock_get.call_count == 2


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_mixed_probe_outcomes_are_disjoint_and_total(mock_enum, mock_resolver_class, mock_get):
    """Every subdomain lands in exactly one of vulnerable, safe, or unknown."""
    import requests as real_requests
    import dns.resolver as real_dns

    subdomains = [
        "vulnerable.example.com",
        "safe.example.com",
        "unknown.example.com",
        "dns-error.example.com",
        "unsupported.example.com",
    ]
    mock_enum.return_value = _enumeration_result(subdomains)

    resolver = Mock()

    def resolve_side_effect(name, rtype, **kwargs):
        if name == "dns-error.example.com":
            raise real_dns.NoNameservers
        if name == "unsupported.example.com":
            return [_cname_record("app.unsupported.example.")]
        return [
            _cname_record(
                "vulnerable.ghost.io."
                if name.startswith("vulnerable")
                else "safe.ghost.io."
            )
        ]

    resolver.resolve.side_effect = resolve_side_effect
    mock_resolver_class.return_value = resolver

    def http_side_effect(url, **kwargs):
        host = (urlparse(url).hostname or "").lower()
        if host.startswith("unknown"):
            raise real_requests.exceptions.Timeout("probe timed out")
        response = Mock()
        response.status_code = 200
        response.text = (
            "404 Domain Not Found"
            if host.startswith("vulnerable")
            else "Welcome to a live site"
        )
        return response

    mock_get.side_effect = http_side_effect

    result = subdomain_takeover("example.com")

    assert result.get("unknown") is not None
    bucket_subdomains = {
        "vulnerable": [item["subdomain"] for item in result["vulnerable"]],
        "safe": list(result["safe"]),
        "unknown": [item["subdomain"] for item in result.get("unknown", [])],
    }
    classified_subdomains = [
        subdomain
        for bucket in bucket_subdomains.values()
        for subdomain in bucket
    ]
    assert len(classified_subdomains) == len(subdomains)
    assert len(set(classified_subdomains)) == len(classified_subdomains)
    assert set(classified_subdomains) == set(subdomains)
    bucket_sets = {
        name: set(bucket) for name, bucket in bucket_subdomains.items()
    }
    for left_name, left_bucket in bucket_sets.items():
        for right_name, right_bucket in bucket_sets.items():
            if left_name != right_name:
                assert left_bucket.isdisjoint(right_bucket)
    assert bucket_subdomains["vulnerable"] == ["vulnerable.example.com"]
    assert bucket_subdomains["safe"] == ["safe.example.com"]
    assert bucket_subdomains["unknown"] == [
        "unknown.example.com",
        "dns-error.example.com",
        "unsupported.example.com",
    ]


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_s3_fingerprint_matches_only_s3_endpoints(mock_enum, mock_resolver_class, mock_get):
    """Only actual S3 bucket endpoint CNAMEs select the AWS S3 fingerprint; other AWS endpoints are unknown and unprobed."""
    mock_enum.return_value = _enumeration_result(["static.example.com"])
    resolver = Mock()
    mock_resolver_class.return_value = resolver

    s3_cnames = [
        "static-example-com.s3.amazonaws.com.",  # legacy global
        "static-example-com.s3.us-east-1.amazonaws.com.",  # virtual-hosted regional
        "static-example-com.s3-us-west-2.amazonaws.com.",  # legacy dash region
        "static-example-com.s3.dualstack.us-east-1.amazonaws.com.",  # dual-stack
        "static-example-com.s3-fips.us-east-1.amazonaws.com.",  # FIPS
        "static-example-com.s3-fips.dualstack.us-east-1.amazonaws.com.",  # FIPS dual-stack
        "static-example-com.s3-accelerate.amazonaws.com.",  # Transfer Acceleration
        "static-example-com.s3-accelerate.dualstack.amazonaws.com.",  # Acceleration dual-stack
        "static-example-com.s3-website-us-east-1.amazonaws.com.",  # website, dash form
        "static-example-com.s3-website.eu-west-1.amazonaws.com.",  # website, dot form
        "static-example-com.s3.us-gov-west-1.amazonaws.com.",  # GovCloud
        "static-example-com.s3.cn-north-1.amazonaws.com.cn.",  # China regional
        "static-example-com.s3-cn-northwest-1.amazonaws.com.cn.",  # China legacy dash
        "static-example-com.s3.amazonaws.com.cn.",  # China legacy global
        "static-example-com.s3.dualstack.cn-north-1.amazonaws.com.cn.",  # China dual-stack
        "static-example-com.s3.dualstack.cn-northwest-1.amazonaws.com.cn.",  # China dual-stack
        "static-example-com.s3-website.cn-north-1.amazonaws.com.cn.",  # China website
        "Static-Example-Com.S3.Us-East-1.Amazonaws.Com.",
    ]
    non_s3_cnames = [
        "abc123def4.execute-api.us-east-1.amazonaws.com.",  # API Gateway
        "my-alb-1234567890.us-east-1.elb.amazonaws.com.",  # Elastic Load Balancing
        "dualstack.my-alb-1234567890.us-west-2.elb.amazonaws.com.",  # ELB dualstack
        "ABC123DEF4.EXECUTE-API.US-EAST-1.AMAZONAWS.COM.",  # uppercase API Gateway
        "123456789012.s3-control.us-east-1.amazonaws.com.",  # S3 Control
        "my-ap-123456789012.s3-accesspoint.us-east-1.amazonaws.com.",  # access point
        "my-olap-123456789012.s3-object-lambda.us-east-1.amazonaws.com.",  # Object Lambda
        "my-ap-123456789012.s3-outposts.us-east-1.amazonaws.com.",  # S3 on Outposts
        "bucket-base--use1-az5--x-s3.s3express-use1-az5.us-east-1.amazonaws.com.",  # S3 Express zonal
        "s3express-control.us-east-1.amazonaws.com.",  # S3 Express control
        "static-example-com.s3.not-a-real-region.amazonaws.com.",  # fabricated region token
        "static-example-com.s3-website.dualstack.us-east-1.amazonaws.com.",  # website has no dual-stack form
        "static-example-com.s3-fips.cn-north-1.amazonaws.com.cn.",  # China has no FIPS form
        "static-example-com.s3-accelerate.amazonaws.com.cn.",  # China has no accelerate form
        "static-example-com.s3-website-cn-north-1.amazonaws.com.cn.",  # China website is dot-separated only
        "static-example-com.s3.us-east-1.amazonaws.com.evil.com.",  # lookalike suffix, not an AWS host
        "static-example-com.s3.amazonaws.com.cn.evil.com.",  # lookalike suffix, not an AWS host
        "nots3.amazonaws.com.",  # s3 substring inside a label, not an s3 label
    ]

    failures = []
    for cname, is_s3 in [(c, True) for c in s3_cnames] + [(c, False) for c in non_s3_cnames]:
        mock_get.reset_mock()
        resolver.resolve.return_value = [_cname_record(cname)]
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "NoSuchBucket"
        mock_get.return_value = mock_response

        result = subdomain_takeover("example.com")

        assert result["success"] is True
        if is_s3:
            matched = (
                result["total_vulnerable"] == 1
                and result["vulnerable"][0]["service"] == "AWS S3"
                and result["vulnerable"][0]["cname"] == cname.rstrip(".")
                and mock_get.call_count == 1
            )
            if not matched:
                failures.append(f"actual S3 bucket endpoint must match and be probed: {cname}")
        else:
            ignored = (
                result["vulnerable"] == []
                and result["safe"] == []
                and [
                    entry["subdomain"] for entry in result["unknown"]
                ] == ["static.example.com"]
                and mock_get.call_count == 0
            )
            if not ignored:
                failures.append(f"non-bucket endpoint must not match or be probed: {cname}")

    assert failures == [], "wrong AWS S3 fingerprint selection:\n" + "\n".join(failures)


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
