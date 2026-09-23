import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import urlparse

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from tools import subdomain_takeover


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


def _cname_chain(*targets):
    records = iter(targets)

    def resolve(_name, _rtype, **_kwargs):
        try:
            return [_cname_record(next(records))]
        except StopIteration:
            raise dns.resolver.NoAnswer

    return resolve


def test_cname_chain_reaches_fingerprinted_service_and_preserves_evidence():
    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain(
        "Alias.Example.NET.",
        "User.GitHub.IO.",
    )

    from tools.subdomain_takeover_tool import _resolve_cname

    result = _resolve_cname("Blog.Example.Com.", resolver)

    assert result.error is None
    assert result.cname == "User.GitHub.IO"
    assert result.chain == ("Alias.Example.NET", "User.GitHub.IO")
    assert [call.args[0] for call in resolver.resolve.call_args_list] == [
        "blog.example.com",
        "alias.example.net",
        "user.github.io",
    ]


def test_cname_chain_detects_loops():
    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain(
        "alias.example.net.",
        "blog.example.com.",
    )

    from tools.subdomain_takeover_tool import _resolve_cname

    result = _resolve_cname("blog.example.com", resolver)

    assert result.error == "CNAME loop detected"
    assert result.chain == ("alias.example.net", "blog.example.com")


def test_cname_chain_stops_after_bounded_depth():
    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain(
        *(f"hop-{index}.example.net." for index in range(1, 7))
    )

    from tools.subdomain_takeover_tool import _resolve_cname

    result = _resolve_cname("blog.example.com", resolver)

    assert result.error == "CNAME chain exceeds maximum depth of 5"
    assert len(result.chain) == 6


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_multihop_cname_reaches_takeover_fingerprint(
    mock_enum, mock_resolver_class, mock_get
):
    mock_enum.return_value = _enumeration_result(["blog.example.com"])
    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain(
        "alias.example.net.",
        "user.github.io.",
    )
    mock_resolver_class.return_value = resolver
    response = Mock(status_code=404)
    response.text = "There isn't a GitHub Pages site here."
    response.headers = {"Server": "GitHub.com"}
    mock_get.return_value = response

    result = subdomain_takeover("example.com")

    assert result["total_vulnerable"] == 1
    assert result["vulnerable"][0]["service"] == "GitHub Pages"
    assert result["vulnerable"][0]["cname"] == "user.github.io"
    assert result["cname_chains"] == {
        "blog.example.com": ["alias.example.net", "user.github.io"]
    }
    mock_get.assert_called_once()


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_vulnerable_subdomain_is_flagged(mock_enum, mock_resolver_class, mock_get):
    """Dangling CNAME to a fingerprinted service + takeover indicator => vulnerable."""
    mock_enum.return_value = _enumeration_result(
        ["blog.example.com", "www.example.com"]
    )

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
    mock_response.headers = {"X-Ghost-Cache-Status": "MISS"}
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
    assert result["not_vulnerable"] == ["www.example.com"]
    assert result.get("unknown") == []
    mock_get.assert_called_once()


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_fingerprint_match_without_indicator_is_not_vulnerable(
    mock_enum, mock_resolver_class, mock_get
):
    """CNAME matches a fingerprint but the service is still live => not vulnerable."""
    mock_enum.return_value = _enumeration_result(["blog.example.com"])

    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain("example.ghost.io.")
    mock_resolver_class.return_value = resolver

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "Welcome to my blog"
    mock_response.headers = {}  # No takeover identity headers; status/body don't match either
    mock_get.return_value = mock_response

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["vulnerable"] == []
    assert result["total_vulnerable"] == 0
    assert result.get("not_vulnerable") == ["blog.example.com"]
    assert "safe" not in result
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
def test_no_dangling_cname_is_not_vulnerable(
    mock_enum, mock_resolver_class, mock_get, no_cname_error
):
    """Subdomain with no CNAME record at all => not vulnerable, without an HTTP probe."""
    mock_enum.return_value = _enumeration_result(
        ["www.example.com", "mail.example.com"]
    )

    resolver = Mock()
    resolver.resolve.side_effect = no_cname_error
    mock_resolver_class.return_value = resolver

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["subdomains_checked"] == 2
    assert result["vulnerable"] == []
    assert result["total_vulnerable"] == 0
    assert result["not_vulnerable"] == ["www.example.com", "mail.example.com"]
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
def test_dns_resolution_errors_are_unknown_without_negative_bucket(
    mock_enum, mock_resolver_class, mock_get, dns_error
):
    """Operational CNAME lookup failures must not be reported as not vulnerable."""
    mock_enum.return_value = _enumeration_result(["app.example.com"])
    resolver = Mock()
    resolver.resolve.side_effect = dns_error
    mock_resolver_class.return_value = resolver

    result = subdomain_takeover("example.com")

    assert result["vulnerable"] == []
    assert result["not_vulnerable"] == []
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
def test_unsupported_cname_service_is_unknown_without_negative_bucket(
    mock_enum, mock_resolver_class, mock_get
):
    """A CNAME outside the known fingerprints must remain unknown, not negative."""
    mock_enum.return_value = _enumeration_result(["app.example.com"])
    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain("app.unsupported.example.")
    mock_resolver_class.return_value = resolver

    result = subdomain_takeover("example.com")

    assert result["vulnerable"] == []
    assert result["not_vulnerable"] == []
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
    """Mixed results: vulnerable, not-vulnerable, and unknown outcomes remain distinct."""
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
            # GitHub Pages: all three signals must fire for confirmed takeover.
            response.status_code = 404
            response.text = "There isn't a GitHub Pages site here."
            response.headers = {"Server": "GitHub.com"}
        else:
            # Shopify CNAME but shop is live
            response.status_code = 200
            response.text = "My awesome shop"
            response.headers = {}
        return response

    mock_get.side_effect = http_side_effect

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["subdomains_checked"] == 3
    assert result["total_vulnerable"] == 1
    assert result["vulnerable"][0]["subdomain"] == "dev.example.com"
    assert result["vulnerable"][0]["service"] == "GitHub Pages"
    assert result["not_vulnerable"] == ["blog.example.com", "www.example.com"]
    assert result.get("unknown") == []


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_azure_vulnerable_matches_body(mock_enum, mock_resolver_class, mock_get):
    """Azure CNAME + Azure-specific body string => vulnerable, probed over HTTPS first."""
    mock_enum.return_value = _enumeration_result(["app.example.com"])

    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain("app.azurewebsites.net.")
    mock_resolver_class.return_value = resolver

    mock_response = Mock()
    # All three Azure signals are required: status 404, body substring, x-ms-request-id header.
    mock_response.status_code = 404
    mock_response.text = "404 Web Site not found"
    mock_response.headers = {"X-Ms-Request-Id": "abc-123"}
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
    resolver.resolve.side_effect = _cname_chain("app.azurewebsites.net.")
    mock_resolver_class.return_value = resolver

    def http_side_effect(url, **kwargs):
        if url.startswith("https://"):
            raise real_requests.exceptions.ConnectionError("HTTPS unavailable")
        response = Mock()
        response.status_code = 404
        response.text = "404 Web Site not found"
        response.headers = {"X-Ms-Request-Id": "abc-123"}
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
    resolver.resolve.side_effect = _cname_chain("app.azurewebsites.net.")
    mock_resolver_class.return_value = resolver

    mock_get.side_effect = real_requests.exceptions.ConnectionError("unreachable")

    result = subdomain_takeover("example.com")

    assert result["success"] is True
    assert result["total_vulnerable"] == 0
    assert result["not_vulnerable"] == []
    assert result["unknown"][0]["subdomain"] == "app.example.com"
    assert (
        result["unknown"][0]["reason"]
        == "Unable to complete HTTP probe over HTTPS or HTTP"
    )
    assert [error["scheme"] for error in result["unknown"][0]["probe_errors"]] == [
        "https",
        "http",
    ]
    assert all(
        "ConnectionError: unreachable" in error["error"]
        for error in result["unknown"][0]["probe_errors"]
    )
    assert mock_get.call_count == 2


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_mixed_probe_outcomes_are_disjoint_and_total(
    mock_enum, mock_resolver_class, mock_get
):
    """Every subdomain lands in exactly one of vulnerable, not-vulnerable, or unknown."""
    import dns.resolver as real_dns
    import requests as real_requests

    subdomains = [
        "vulnerable.example.com",
        "not-vulnerable.example.com",
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
        if name not in subdomains:
            raise real_dns.NoAnswer
        return [
            _cname_record(
                "vulnerable.ghost.io."
                if name.startswith("vulnerable")
                else "not-vulnerable.ghost.io."
            )
        ]

    resolver.resolve.side_effect = resolve_side_effect
    mock_resolver_class.return_value = resolver

    def http_side_effect(url, **kwargs):
        host = (urlparse(url).hostname or "").lower()
        if host.startswith("unknown"):
            raise real_requests.exceptions.Timeout("probe timed out")
        response = Mock()
        if host.startswith("vulnerable"):
            # Ghost multi-signal: status 404, body, x-ghost-cache-status header
            response.status_code = 404
            response.text = "404 Domain Not Found"
            response.headers = {"X-Ghost-Cache-Status": "MISS"}
        else:
            response.status_code = 200
            response.text = "Welcome to a live site"
            response.headers = {}
        return response

    mock_get.side_effect = http_side_effect

    result = subdomain_takeover("example.com")

    assert result.get("unknown") is not None
    bucket_subdomains = {
        "vulnerable": [item["subdomain"] for item in result["vulnerable"]],
        "not_vulnerable": list(result["not_vulnerable"]),
        "unknown": [item["subdomain"] for item in result.get("unknown", [])],
    }
    classified_subdomains = [
        subdomain for bucket in bucket_subdomains.values() for subdomain in bucket
    ]
    assert len(classified_subdomains) == len(subdomains)
    assert len(set(classified_subdomains)) == len(classified_subdomains)
    assert set(classified_subdomains) == set(subdomains)
    bucket_sets = {name: set(bucket) for name, bucket in bucket_subdomains.items()}
    for left_name, left_bucket in bucket_sets.items():
        for right_name, right_bucket in bucket_sets.items():
            if left_name != right_name:
                assert left_bucket.isdisjoint(right_bucket)
    assert bucket_subdomains["vulnerable"] == ["vulnerable.example.com"]
    assert bucket_subdomains["not_vulnerable"] == ["not-vulnerable.example.com"]
    assert bucket_subdomains["unknown"] == [
        "unknown.example.com",
        "dns-error.example.com",
        "unsupported.example.com",
    ]


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_s3_fingerprint_matches_only_s3_endpoints(
    mock_enum, mock_resolver_class, mock_get
):
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
    for cname, is_s3 in [(c, True) for c in s3_cnames] + [
        (c, False) for c in non_s3_cnames
    ]:
        mock_get.reset_mock()
        resolver.resolve.side_effect = _cname_chain(cname)
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "NoSuchBucket"
        mock_response.headers = {"Server": "AmazonS3"}
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
                failures.append(
                    f"actual S3 bucket endpoint must match and be probed: {cname}"
                )
        else:
            ignored = (
                result["vulnerable"] == []
                and result["not_vulnerable"] == []
                and [entry["subdomain"] for entry in result["unknown"]]
                == ["static.example.com"]
                and mock_get.call_count == 0
            )
            if not ignored:
                failures.append(
                    f"non-bucket endpoint must not match or be probed: {cname}"
                )

    assert failures == [], "wrong AWS S3 fingerprint selection:\n" + "\n".join(failures)


@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_invalid_domain(mock_enum):
    result = subdomain_takeover("bad_domain")
    assert result["success"] is False
    assert "error" in result
    mock_enum.assert_not_called()


@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_enumeration_failure_propagates(mock_enum):
    mock_enum.return_value = {
        "success": False,
        "error": "Domain example.com does not exist",
    }
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
        bytes([4, 0xFF, 0xFE, 0x41, 0x42]),
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


def test_resolve_cname_udp_first_without_forced_tcp():
    """Item 12: Verify CNAME resolution does not force tcp=True on resolver calls."""
    from tools.subdomain_takeover_tool import _resolve_cname

    resolver = Mock()
    record = Mock()
    record.__str__ = lambda self: "target.example.net."
    # First hop returns CNAME target.example.net, second hop returns NoAnswer (clean termination without looping)
    resolver.resolve.side_effect = [[record], dns.resolver.NoAnswer()]

    result = _resolve_cname("sub.example.com", resolver)

    assert result.error is None
    assert result.cname == "target.example.net"
    assert resolver.resolve.call_count == 2
    for call in resolver.resolve.call_args_list:
        assert "tcp" not in call.kwargs or call.kwargs["tcp"] is False


def test_fingerprint_regex_patterns_anchored_and_normalized():
    """Item 6: Verify regex patterns match valid service targets and reject spoofed/unanchored domains."""
    from tools.subdomain_takeover_tool import _match_fingerprint

    # Valid service hostnames with various casings and trailing dots
    assert _match_fingerprint("myblog.github.io.")["service"] == "GitHub Pages"
    assert _match_fingerprint("APP.HEROKUAPP.COM")["service"] == "Heroku"
    assert _match_fingerprint("secure.herokussl.com.")["service"] == "Heroku"
    assert _match_fingerprint("dns.herokudns.com")["service"] == "Heroku"
    assert _match_fingerprint("site.azurewebsites.net.")["service"] == "Azure"
    assert _match_fingerprint("cloud.cloudapp.net")["service"] == "Azure"
    assert _match_fingerprint("routing.trafficmanager.net.")["service"] == "Azure"
    assert _match_fingerprint("publication.ghost.io")["service"] == "Ghost"
    assert _match_fingerprint("store.myshopify.com.")["service"] == "Shopify"
    assert _match_fingerprint("cdn.fastly.net")["service"] == "Fastly"
    assert _match_fingerprint("lb.fastlylb.net.")["service"] == "Fastly"

    # Spoofed/unanchored lookalike domains must NOT match
    assert _match_fingerprint("github.io.attacker.com") is None
    assert _match_fingerprint("fake-github.io.com") is None
    assert _match_fingerprint("herokuapp.com.phishing.org") is None
    assert _match_fingerprint("azurewebsites.net.badsite.io") is None
    assert _match_fingerprint("ghost.io.evil.com") is None
    assert _match_fingerprint("myshopify.com.scam.net") is None
    assert _match_fingerprint("fastly.net.malicious.com") is None


def test_fastly_fingerprint_refined_indicator():
    """Item 5: Fastly takeover requires multi-signal match (CNAME, status 500, body indicator, headers)."""
    from tools.subdomain_takeover_tool import _confirms_takeover, _match_fingerprint

    fingerprint = _match_fingerprint("mycdn.fastly.net")
    assert fingerprint is not None
    assert fingerprint["service"] == "Fastly"

    # Multi-signal matching (status=500, body, x-served-by header) confirms takeover
    mock_probe = Mock()
    mock_probe.errors = ()
    mock_probe.response = Mock(
        status_code=500,
        text="Fastly error: unknown domain: sub.example.com",
        headers={"X-Served-By": "cache-iad-kiad7000000-IAD"},
    )
    with patch("tools.subdomain_takeover_tool._probe", return_value=mock_probe):
        res = _confirms_takeover("sub.example.com", fingerprint)
        assert res.status.value == "confirmed"

    # Generic error without 'unknown domain' does NOT confirm takeover
    mock_probe_generic = Mock()
    mock_probe_generic.errors = ()
    mock_probe_generic.response = Mock(
        status_code=500,
        text="Fastly error: configuration fetch failed",
        headers={"X-Served-By": "cache-iad-kiad7000000-IAD"},
    )
    with patch("tools.subdomain_takeover_tool._probe", return_value=mock_probe_generic):
        res = _confirms_takeover("sub.example.com", fingerprint)
        assert res.status.value == "no_indicator"

    # Correct body and headers but wrong HTTP status code (e.g. 200) does NOT confirm takeover
    mock_probe_wrong_status = Mock()
    mock_probe_wrong_status.errors = ()
    mock_probe_wrong_status.response = Mock(
        status_code=200,
        text="Fastly error: unknown domain: sub.example.com",
        headers={"X-Served-By": "cache-iad-kiad7000000-IAD"},
    )
    with patch(
        "tools.subdomain_takeover_tool._probe", return_value=mock_probe_wrong_status
    ):
        res = _confirms_takeover("sub.example.com", fingerprint)
        assert res.status.value == "no_indicator"


@patch("tools.subdomain_takeover_tool.requests.get")
def test_explicit_redirect_handling_cross_domain_halt(mock_get):
    """Item 8: Redirect handling halts when target leaves subdomain scope to avoid third-party false positives."""
    from tools.subdomain_takeover_tool import _probe

    # First request returns redirect to an external parking domain
    redirect_resp = Mock(
        status_code=302, headers={"Location": "https://external-parking.com/landing"}
    )
    redirect_resp.is_redirect = True
    mock_get.return_value = redirect_resp

    # No resolver provided: _check_host_ssrf validates subdomain as public string literal without mocking resolver
    result = _probe("sub.example.com")
    assert result.response is not None
    assert result.response.status_code == 302
    # The HTTPS attempt halts at hop 0 without following redirect to external domain;
    # because HTTPS succeeded (last_response is set and scheme_failed is False), HTTP fallback is not attempted.
    assert mock_get.call_count == 1
    assert "sub.example.com" in mock_get.call_args[0][0]
    # Explicitly verify the external parking domain was never contacted
    assert all(
        "external-parking.com" not in call.args[0] for call in mock_get.call_args_list
    )


@patch("tools.subdomain_takeover_tool.requests.get")
def test_probe_preserves_rejected_out_of_scope_redirect(mock_get):
    """The rejected out-of-scope Location is recorded in probe metadata without being requested."""
    from tools.subdomain_takeover_tool import _probe

    redirect_resp = Mock(
        status_code=302,
        headers={"Location": "https://external-parking.com/landing"},
    )
    redirect_resp.url = "https://sub.example.com"
    mock_get.return_value = redirect_resp

    result = _probe("sub.example.com")

    assert result.response is redirect_resp
    # redirect_chain only lists URLs that were actually requested; the rejected
    # target is preserved separately so it cannot be mistaken for a fetched hop.
    assert result.redirect_chain == ("https://sub.example.com",)
    assert result.rejected_redirect_url == "https://external-parking.com/landing"
    assert mock_get.call_count == 1
    assert all(
        "external-parking.com" not in call.args[0] for call in mock_get.call_args_list
    )


@patch("tools.subdomain_takeover_tool.requests.get")
def test_probe_preserves_rejected_redirect_after_in_scope_hops(mock_get):
    """In-scope hops are followed; only the out-of-scope terminal Location is preserved unfetched."""
    from tools.subdomain_takeover_tool import _probe

    first = Mock(
        status_code=302,
        headers={"Location": "https://www.sub.example.com/next"},
    )
    first.url = "https://sub.example.com"
    second = Mock(
        status_code=302,
        headers={"Location": "https://external-parking.com/landing"},
    )
    second.url = "https://www.sub.example.com/next"
    mock_get.side_effect = [first, second]

    result = _probe("sub.example.com")

    assert result.redirect_chain == (
        "https://sub.example.com",
        "https://www.sub.example.com/next",
    )
    assert result.rejected_redirect_url == "https://external-parking.com/landing"
    # Both in-scope URLs were fetched; the external target was not.
    assert mock_get.call_count == 2
    assert [call.args[0] for call in mock_get.call_args_list] == [
        "https://sub.example.com",
        "https://www.sub.example.com/next",
    ]


def test_ssrf_protection_blocks_private_and_loopback_ips():
    """Item 9: Subdomains resolving to loopback or RFC 1918 private IPs are blocked for SSRF protection."""
    from tools.subdomain_takeover_tool import _check_host_ssrf, _probe

    # Direct private and loopback IP literals
    assert _check_host_ssrf("127.0.0.1") is not None
    assert _check_host_ssrf("10.0.0.1") is not None
    assert _check_host_ssrf("192.168.1.100") is not None
    assert _check_host_ssrf("169.254.169.254") is not None
    assert _check_host_ssrf("::1") is not None

    # Public IP literals are safe
    assert _check_host_ssrf("93.184.216.34") is None

    # Resolving to private IP via dnspython record objects
    private_record = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.A, "10.10.10.10"
    )
    resolver = Mock()
    resolver.resolve.return_value = _ResolverAnswer([private_record], ttl=60)
    err = _check_host_ssrf("internal.example.com", resolver=resolver)
    assert err is not None
    assert "private/reserved IP" in err
    # Confirm short-circuiting on the first "A" record detection before querying "AAAA"
    assert resolver.resolve.call_count == 1

    # _probe returns SSRFBlocked error and avoids making any HTTP requests
    with patch("tools.subdomain_takeover_tool.requests.get") as mock_get:
        probe_res = _probe("internal.example.com", resolver=resolver)
        assert probe_res.response is None
        assert any("SSRFBlocked" in e["error"] for e in probe_res.errors)
        mock_get.assert_not_called()


@pytest.mark.xfail(
    reason="Known TOCTOU/DNS rebinding limitation: requests.get resolution is decoupled from pre-validation"
)
def test_ssrf_toctou_dns_rebinding_risk():
    """Document known TOCTOU risk where DNS resolves to public IP during pre-check but rebinds to private IP during requests.get."""
    from tools.subdomain_takeover_tool import _check_host_ssrf, _probe

    public_record = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"
    )
    resolver = Mock()
    # Pre-check passes because hostname resolves to a public IP
    resolver.resolve.return_value = _ResolverAnswer([public_record], ttl=60)
    err = _check_host_ssrf("rebind.example.com", resolver=resolver)
    assert err is None

    # Simulate DNS rebinding during actual HTTP fetch:
    # Pre-check passed, but during requests.get the connection targets an internal resource
    with patch("tools.subdomain_takeover_tool.requests.get") as mock_get:
        mock_resp = Mock(
            status_code=200,
            text="internal private console",
            headers={},
            is_redirect=False,
        )
        mock_get.return_value = mock_resp

        probe_res = _probe("rebind.example.com", resolver=resolver)
        # Without socket-level pinning/validation, requests.get connects through, so SSRFBlocked is not asserted
        assert probe_res.response is None
        assert any("SSRFBlocked" in e["error"] for e in probe_res.errors)


# ---------------------------------------------------------------------------
# Issue #7 multi-signal regression tests for all 6 non-Fastly fingerprints
# Each test verifies that missing any ONE signal blocks a confirmed takeover.
# ---------------------------------------------------------------------------


def _make_fingerprint(service_name):
    from tools.subdomain_takeover_tool import VULNERABLE_FINGERPRINTS

    return next(f for f in VULNERABLE_FINGERPRINTS if f["service"] == service_name)


@pytest.mark.parametrize(
    "service,cname,body,status,headers",
    [
        (
            "GitHub Pages",
            "user.github.io",
            "There isn't a GitHub Pages site here.",
            404,
            {"Server": "GitHub.com"},
        ),
        (
            "Heroku",
            "myapp.herokuapp.com",
            "No such app",
            404,
            {"X-Request-Id": "aabbccdd-1234"},
        ),
        (
            "AWS S3",
            "bucket.s3.amazonaws.com",
            "NoSuchBucket",
            404,
            {"Server": "AmazonS3"},
        ),
        (
            "Azure",
            "site.azurewebsites.net",
            "404 Web Site not found",
            404,
            {"X-Ms-Request-Id": "abc123"},
        ),
        (
            "Ghost",
            "pub.ghost.io",
            "404 Domain Not Found",
            404,
            {"X-Ghost-Cache-Status": "MISS"},
        ),
        (
            "Shopify",
            "store.myshopify.com",
            "Sorry, this shop",
            404,
            {"X-Shopid": "987654"},
        ),
    ],
)
def test_multi_signal_fingerprint_confirmed(service, cname, body, status, headers):
    """Issue #7: All signals present => confirmed for each of the 6 non-Fastly services."""
    from tools.subdomain_takeover_tool import _confirms_takeover

    fingerprint = _make_fingerprint(service)
    mock_probe = Mock()
    mock_probe.errors = ()
    mock_probe.response = Mock(status_code=status, text=body, headers=headers)
    with patch("tools.subdomain_takeover_tool._probe", return_value=mock_probe):
        res = _confirms_takeover("sub.example.com", fingerprint)
    assert res.status.value == "confirmed", (
        f"{service}: expected confirmed with all signals"
    )


@pytest.mark.parametrize(
    "service,cname,body,status,headers",
    [
        (
            "GitHub Pages",
            "user.github.io",
            "There isn't a GitHub Pages site here.",
            404,
            {"Server": "GitHub.com"},
        ),
        (
            "Heroku",
            "myapp.herokuapp.com",
            "No such app",
            404,
            {"X-Request-Id": "aabbccdd-1234"},
        ),
        (
            "AWS S3",
            "bucket.s3.amazonaws.com",
            "NoSuchBucket",
            404,
            {"Server": "AmazonS3"},
        ),
        (
            "Azure",
            "site.azurewebsites.net",
            "404 Web Site not found",
            404,
            {"X-Ms-Request-Id": "abc123"},
        ),
        (
            "Ghost",
            "pub.ghost.io",
            "404 Domain Not Found",
            404,
            {"X-Ghost-Cache-Status": "MISS"},
        ),
        (
            "Shopify",
            "store.myshopify.com",
            "Sorry, this shop",
            404,
            {"X-Shopid": "987654"},
        ),
    ],
)
@pytest.mark.parametrize("missing_signal", ["status", "body", "headers"])
def test_multi_signal_fingerprint_missing_signal_no_confirm(
    service, cname, body, status, headers, missing_signal
):
    """Issue #7: Missing any ONE signal => no_indicator (not confirmed) for each service."""
    from tools.subdomain_takeover_tool import _confirms_takeover

    fingerprint = _make_fingerprint(service)
    mock_probe = Mock()
    mock_probe.errors = ()
    # Corrupt the signal under test
    bad_status = 200 if missing_signal == "status" else status
    bad_body = "This site is live" if missing_signal == "body" else body
    bad_headers = {} if missing_signal == "headers" else headers
    mock_probe.response = Mock(
        status_code=bad_status, text=bad_body, headers=bad_headers
    )
    with patch("tools.subdomain_takeover_tool._probe", return_value=mock_probe):
        res = _confirms_takeover("sub.example.com", fingerprint)
    assert res.status.value == "no_indicator", (
        f"{service}: expected no_indicator when {missing_signal!r} signal is absent"
    )


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_vulnerable_finding_includes_structured_evidence(
    mock_enum, mock_resolver_class, mock_get
):
    """Confirmed findings carry probe evidence and a confidence rating separate from severity."""
    mock_enum.return_value = _enumeration_result(["blog.example.com"])
    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain("example.ghost.io.")
    mock_resolver_class.return_value = resolver

    response = Mock()
    response.status_code = 404
    response.text = "404 Domain Not Found"
    response.headers = {"x-ghost-cache-status": "MISS"}
    response.url = "https://blog.example.com/"
    mock_get.return_value = response

    result = subdomain_takeover("example.com")

    assert result["total_vulnerable"] == 1
    finding = result["vulnerable"][0]
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "high"
    evidence = finding["evidence"]
    assert evidence["url"] == "https://blog.example.com"
    assert evidence["final_url"] == "https://blog.example.com/"
    assert evidence["status_code"] == 404
    assert evidence["matched_indicator"] == {
        "type": "body",
        "value": "404 Domain Not Found",
    }
    assert evidence["redirect_chain"] == ["https://blog.example.com"]
    assert evidence["rejected_redirect_url"] is None
    assert evidence["cross_host_redirect"] is False


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_cross_host_redirect_is_recorded_and_lowers_confidence(
    mock_enum, mock_resolver_class, mock_get
):
    """An indicator matched after a redirect to a different in-scope host is weaker evidence."""
    mock_enum.return_value = _enumeration_result(["blog.example.com"])
    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain("example.ghost.io.")
    mock_resolver_class.return_value = resolver

    redirect_resp = Mock(
        status_code=302,
        headers={"Location": "https://www.blog.example.com/landing"},
    )
    redirect_resp.url = "https://blog.example.com"
    response = Mock()
    response.status_code = 404
    response.text = "404 Domain Not Found"
    response.headers = {"x-ghost-cache-status": "MISS"}
    response.url = "https://www.blog.example.com/landing"
    mock_get.side_effect = [redirect_resp, response]

    result = subdomain_takeover("example.com")

    finding = result["vulnerable"][0]
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "medium"
    evidence = finding["evidence"]
    assert evidence["cross_host_redirect"] is True
    assert evidence["final_url"] == "https://www.blog.example.com/landing"
    assert evidence["redirect_chain"] == [
        "https://blog.example.com",
        "https://www.blog.example.com/landing",
    ]
    assert evidence["matched_indicator"] == {
        "type": "body",
        "value": "404 Domain Not Found",
    }


@patch("tools.subdomain_takeover_tool.requests.get")
def test_status_only_indicator_yields_medium_confidence(mock_get):
    """A bare status-code match is weaker evidence than a service-specific body marker."""
    from tools.subdomain_takeover_tool import _confirms_takeover, _ProbeStatus

    response = Mock()
    response.status_code = 404
    response.url = "https://app.example.com/"
    mock_get.return_value = response

    result = _confirms_takeover(
        "app.example.com",
        {"service": "Custom", "indicator": {"status": 404}},
    )

    assert result.status is _ProbeStatus.CONFIRMED
    assert result.confidence == "medium"
    assert result.evidence["matched_indicator"] == {"type": "status", "value": 404}
    assert result.evidence["status_code"] == 404
    assert result.evidence["cross_host_redirect"] is False


@patch("tools.subdomain_takeover_tool.requests.get")
def test_status_match_after_cross_host_redirect_is_low_confidence(mock_get):
    """A status-only match on content served by a different host is the weakest evidence."""
    from tools.subdomain_takeover_tool import _confirms_takeover, _ProbeStatus

    redirect_resp = Mock(
        status_code=302,
        headers={"Location": "https://www.app.example.com/"},
    )
    redirect_resp.url = "https://app.example.com"
    response = Mock()
    response.status_code = 404
    response.url = "https://www.app.example.com/"
    mock_get.side_effect = [redirect_resp, response]

    result = _confirms_takeover(
        "app.example.com",
        {"service": "Custom", "indicator": {"status": 404}},
    )

    assert result.status is _ProbeStatus.CONFIRMED
    assert result.confidence == "low"
    assert result.evidence["cross_host_redirect"] is True


@patch("tools.subdomain_takeover_tool.requests.get")
def test_no_indicator_result_still_carries_probe_evidence(mock_get):
    """Even a negative probe records what was observed for debugging."""
    from tools.subdomain_takeover_tool import _confirms_takeover, _ProbeStatus

    response = Mock()
    response.status_code = 200
    response.text = "Welcome to a live site"
    response.url = "https://app.example.com/"
    mock_get.return_value = response

    result = _confirms_takeover(
        "app.example.com",
        {"service": "Ghost", "indicator": {"body": "404 Domain Not Found"}},
    )

    assert result.status is _ProbeStatus.NO_INDICATOR
    assert result.confidence is None
    assert result.evidence["status_code"] == 200
    assert result.evidence["matched_indicator"] is None
    assert result.evidence["url"] == "https://app.example.com"


@patch("tools.subdomain_takeover_tool.requests.get")
@patch("tools.subdomain_takeover_tool.dns.resolver.Resolver")
@patch("tools.subdomain_takeover_tool.dns_enumeration")
def test_probe_failure_evidence_records_attempted_urls(
    mock_enum, mock_resolver_class, mock_get
):
    """Failed probes keep the attempted URL alongside each transport error."""
    import requests as real_requests

    mock_enum.return_value = _enumeration_result(["app.example.com"])
    resolver = Mock()
    resolver.resolve.side_effect = _cname_chain("app.azurewebsites.net.")
    mock_resolver_class.return_value = resolver

    mock_get.side_effect = real_requests.exceptions.ConnectionError("unreachable")

    result = subdomain_takeover("example.com")

    probe_errors = result["unknown"][0]["probe_errors"]
    assert [error["url"] for error in probe_errors] == [
        "https://app.example.com",
        "http://app.example.com",
    ]


@patch("tools.subdomain_takeover_tool.requests.get")
def test_rejected_redirect_becomes_terminal_hop_in_evidence(mock_get):
    """A rejected out-of-scope Location ends the evidence chain, becomes final_url, and drops confidence."""
    from tools.subdomain_takeover_tool import _confirms_takeover, _ProbeStatus

    redirect_resp = Mock(
        status_code=302,
        headers={"Location": "https://external-parking.com/landing"},
    )
    redirect_resp.url = "https://app.example.com"
    mock_get.return_value = redirect_resp

    result = _confirms_takeover(
        "app.example.com",
        {"service": "Custom", "indicator": {"status": 302}},
    )

    assert result.status is _ProbeStatus.CONFIRMED
    assert result.confidence == "low"
    evidence = result.evidence
    # The rejected target is reported as the terminal hop so the evidence
    # exposes the redirect, and is flagged separately as never requested.
    assert evidence["redirect_chain"] == [
        "https://app.example.com",
        "https://external-parking.com/landing",
    ]
    assert evidence["rejected_redirect_url"] == "https://external-parking.com/landing"
    assert evidence["final_url"] == "https://external-parking.com/landing"
    assert evidence["cross_host_redirect"] is True
    # The external target is evidence only — it was never requested.
    assert mock_get.call_count == 1
    assert all(
        "external-parking.com" not in call.args[0] for call in mock_get.call_args_list
    )


@patch("tools.subdomain_takeover_tool.requests.get")
def test_body_match_with_rejected_redirect_is_medium_confidence(mock_get):
    """A body marker on a response whose redirect was rejected still downgrades confidence."""
    from tools.subdomain_takeover_tool import _confirms_takeover, _ProbeStatus

    redirect_resp = Mock(
        status_code=302,
        headers={"Location": "https://external-parking.com/landing"},
        text="Redirecting to the new site",
    )
    redirect_resp.url = "https://app.example.com"
    mock_get.return_value = redirect_resp

    result = _confirms_takeover(
        "app.example.com",
        {"service": "Custom", "indicator": {"body": "Redirecting"}},
    )

    assert result.status is _ProbeStatus.CONFIRMED
    assert result.confidence == "medium"
    assert result.evidence["matched_indicator"] == {
        "type": "body",
        "value": "Redirecting",
    }
    assert (
        result.evidence["rejected_redirect_url"]
        == "https://external-parking.com/landing"
    )
    assert result.evidence["cross_host_redirect"] is True
    assert all(
        "external-parking.com" not in call.args[0] for call in mock_get.call_args_list
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
