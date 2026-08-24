"""Subdomain Takeover Checker Tool.

Discovers subdomains via the existing DNS enumeration logic, resolves each
subdomain's CNAME record, matches it against known-vulnerable service
fingerprints (GitHub Pages, Heroku, S3, Azure, Ghost, Shopify, Fastly), and
confirms the takeover with an HTTP request checking for the service's
takeover-indicating response.
"""
from dataclasses import dataclass
from enum import Enum
import re

import dns.resolver
import requests

from tools.dns_tool import PUBLIC_RESOLVERS, dns_enumeration
from utils.helpers import is_valid_domain, normalize_domain

# Match region labels by shape rather than a fixed list so newly added AWS
# regions stay covered. Keeping service-specific labels out of this slot
# prevents non-bucket AWS endpoints from being interpreted as bucket regions.
_AWS_REGION = r"[a-z]{2}(?:-[a-z]+)+-\d+"

# Restrict the fingerprint to documented S3 bucket endpoint families that can
# return NoSuchBucket for an unclaimed bucket. Anchoring the hostname prevents
# unrelated AWS services from being treated as S3.
# References:
# https://docs.aws.amazon.com/general/latest/gr/s3.html
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/transfer-acceleration-getting-started.html
# https://docs.amazonaws.cn/en_us/AmazonS3/latest/userguide/VirtualHosting.html
# https://docs.amazonaws.cn/en_us/AmazonS3/latest/userguide/static-website-hosting-china.html
# https://github.com/boto/botocore/blob/develop/botocore/data/endpoints.json
_S3_ENDPOINT_RE = re.compile(
    rf"(?:^|\.)(?:s3(?:[.-]{_AWS_REGION}|\.dualstack\.{_AWS_REGION})?"
    rf"|s3-fips(?:\.dualstack)?\.{_AWS_REGION}"
    rf"|s3-accelerate(?:\.dualstack)?"
    rf"|s3-website[.-]{_AWS_REGION})\.amazonaws\.com$"
    rf"|(?:^|\.)(?:s3(?:[.-]{_AWS_REGION}|\.dualstack\.{_AWS_REGION})?"
    rf"|s3-website\.{_AWS_REGION})\.amazonaws\.com\.cn$"
)

# (cname_contains or cname_pattern, service, takeover indicator)
# indicator key "status" matches on the HTTP status code, "body" on response text.
VULNERABLE_FINGERPRINTS = [
    {"cname_contains": "github.io", "service": "GitHub Pages", "indicator": {"body": "There isn't a GitHub Pages site here."}},
    {"cname_contains": "herokuapp.com", "service": "Heroku", "indicator": {"body": "No such app"}},
    {"cname_pattern": _S3_ENDPOINT_RE, "service": "AWS S3", "indicator": {"body": "NoSuchBucket"}},
    {"cname_contains": "azurewebsites.net", "service": "Azure", "indicator": {"body": "404 Web Site not found"}},
    {"cname_contains": "ghost.io", "service": "Ghost", "indicator": {"body": "404 Domain Not Found"}},
    {"cname_contains": "myshopify.com", "service": "Shopify", "indicator": {"body": "Sorry, this shop"}},
    {"cname_contains": "fastly.net", "service": "Fastly", "indicator": {"body": "Fastly error"}},
]

_REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
_REQUEST_TIMEOUT = 10


class _ProbeStatus(str, Enum):
    CONFIRMED = "confirmed"
    NO_INDICATOR = "no_indicator"
    UNABLE_TO_PROBE = "unable_to_probe"


@dataclass(frozen=True)
class _ProbeResult:
    response: requests.Response | None
    errors: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class _TakeoverResult:
    status: _ProbeStatus
    probe_errors: tuple[dict[str, str], ...] = ()


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_RESOLVERS
    return resolver


def _resolve_cname(subdomain: str, resolver) -> str | None:
    """Return the subdomain's CNAME target, or None if it has none."""
    try:
        answers = resolver.resolve(subdomain, "CNAME", lifetime=5, tcp=True)
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


def _match_fingerprint(cname: str) -> dict | None:
    cname = cname.lower().rstrip(".")
    for fingerprint in VULNERABLE_FINGERPRINTS:
        pattern = fingerprint.get("cname_pattern")
        if pattern is not None:
            if pattern.search(cname):
                return fingerprint
        elif fingerprint["cname_contains"] in cname:
            return fingerprint
    return None


def _probe(subdomain: str) -> _ProbeResult:
    """Fetch the subdomain over HTTPS first, falling back to HTTP.

    Many hosted services only serve (or redirect to) HTTPS, so try that first
    and fall back to plain HTTP only when the HTTPS connection itself fails.
    Returns the response and any errors if neither scheme connects.
    """
    errors = []
    for scheme in ("https", "http"):
        try:
            response = requests.get(
                f"{scheme}://{subdomain}",
                headers=_REQUEST_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            return _ProbeResult(response=response)
        except requests.exceptions.RequestException as exc:
            errors.append({
                "scheme": scheme,
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue
    return _ProbeResult(response=None, errors=tuple(errors))


def _confirms_takeover(subdomain: str, fingerprint: dict) -> _TakeoverResult:
    """Return the tri-state takeover result and probe failure evidence."""
    probe = _probe(subdomain)
    if probe.response is None:
        return _TakeoverResult(_ProbeStatus.UNABLE_TO_PROBE, probe.errors)

    indicator = fingerprint["indicator"]
    if "status" in indicator:
        confirmed = probe.response.status_code == indicator["status"]
    else:
        confirmed = indicator["body"].lower() in probe.response.text.lower()
    status = _ProbeStatus.CONFIRMED if confirmed else _ProbeStatus.NO_INDICATOR
    return _TakeoverResult(status)


def subdomain_takeover(domain: str) -> dict:
    """
    Check discovered subdomains for potential takeover vulnerabilities.
    A subdomain takeover occurs when a subdomain's CNAME points to an external
    service (GitHub Pages, Heroku, S3 etc.) that is no longer active.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    # Subdomain discovery reuses the existing DNS enumeration tool.
    enumeration = dns_enumeration(domain)
    if not enumeration.get("success"):
        return {
            "success": False,
            "error": enumeration.get("error", "DNS enumeration failed"),
        }

    subdomains = enumeration.get("subdomains_found", [])
    resolver = _make_resolver()

    vulnerable = []
    safe = []
    unknown = []

    for subdomain in subdomains:
        cname = _resolve_cname(subdomain, resolver)
        if not cname:
            safe.append(subdomain)
            continue

        fingerprint = _match_fingerprint(cname)
        if not fingerprint:
            safe.append(subdomain)
            continue

        probe_result = _confirms_takeover(subdomain, fingerprint)
        if probe_result.status is _ProbeStatus.CONFIRMED:
            vulnerable.append({
                "subdomain": subdomain,
                "cname": cname,
                "service": fingerprint["service"],
                "reason": f"CNAME points to unclaimed {fingerprint['service']} service",
                "severity": "HIGH",
            })
        elif probe_result.status is _ProbeStatus.NO_INDICATOR:
            safe.append(subdomain)
        else:
            unknown.append({
                "subdomain": subdomain,
                "reason": "Unable to complete HTTP probe over HTTPS or HTTP",
                "probe_errors": list(probe_result.probe_errors),
            })

    return {
        "success": True,
        "domain": domain,
        "subdomains_checked": len(subdomains),
        "vulnerable": vulnerable,
        "safe": safe,
        "unknown": unknown,
        "total_vulnerable": len(vulnerable),
    }
