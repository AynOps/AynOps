"""Subdomain Takeover Checker Tool.

Discovers subdomains via the existing DNS enumeration logic, resolves each
subdomain's CNAME record, matches it against known-vulnerable service
fingerprints (GitHub Pages, Heroku, S3, Azure, Ghost, Shopify, Fastly), and
confirms the takeover with an HTTP request checking for the service's
takeover-indicating response.
"""

import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

import dns.exception
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
_MAX_CNAME_DEPTH = 5


class _ProbeStatus(str, Enum):
    CONFIRMED = "confirmed"
    NO_INDICATOR = "no_indicator"
    UNABLE_TO_PROBE = "unable_to_probe"


@dataclass(frozen=True)
class _ProbeResult:
    response: requests.Response | None
    request_url: str | None = None
    errors: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class _TakeoverResult:
    status: _ProbeStatus
    probe_errors: tuple[dict[str, str], ...] = ()
    evidence: dict | None = None
    confidence: str | None = None


@dataclass(frozen=True)
class _CnameResolution:
    cname: str | None = None
    chain: tuple[str, ...] = ()
    error: str | None = None


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_RESOLVERS
    return resolver


def _resolve_cname(subdomain: str, resolver) -> _CnameResolution:
    """Resolve a bounded CNAME chain and distinguish absence from failure."""
    current = subdomain.lower().rstrip(".")
    seen = {current}
    chain = []

    while True:
        try:
            answers = resolver.resolve(current, "CNAME", lifetime=5, tcp=True)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return _CnameResolution(
                cname=chain[-1] if chain else None,
                chain=tuple(chain),
            )
        except dns.exception.DNSException as exc:
            return _CnameResolution(
                cname=chain[-1] if chain else None,
                chain=tuple(chain),
                error=f"{type(exc).__name__}: {exc}",
            )

        target = str(answers[0]).rstrip(".")
        normalized_target = target.lower()
        chain.append(target)
        if normalized_target in seen:
            return _CnameResolution(
                cname=target,
                chain=tuple(chain),
                error="CNAME loop detected",
            )
        if len(chain) > _MAX_CNAME_DEPTH:
            return _CnameResolution(
                cname=target,
                chain=tuple(chain),
                error=f"CNAME chain exceeds maximum depth of {_MAX_CNAME_DEPTH}",
            )
        seen.add(normalized_target)
        current = normalized_target


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
        url = f"{scheme}://{subdomain}"
        try:
            response = requests.get(
                url,
                headers=_REQUEST_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            return _ProbeResult(response=response, request_url=url)
        except requests.exceptions.RequestException as exc:
            errors.append({
                "scheme": scheme,
                "url": url,
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue
    return _ProbeResult(response=None, errors=tuple(errors))


def _response_url(response) -> str | None:
    """Return the response's URL, tolerating test doubles that lack one."""
    url = getattr(response, "url", None)
    return url if isinstance(url, str) else None


def _redirect_chain(response) -> tuple[str, ...]:
    """Return every URL requested across followed redirects, ending at the final URL."""
    urls = []
    history = getattr(response, "history", None)
    if isinstance(history, (list, tuple)):
        for hop in history:
            hop_url = _response_url(hop)
            if hop_url is not None:
                urls.append(hop_url)
    final_url = _response_url(response)
    if final_url is not None:
        urls.append(final_url)
    return tuple(urls)


def _assess_confidence(matched_indicator: dict | None, cross_host_redirect: bool) -> str:
    """Rate how conclusively the probe evidence supports a real takeover.

    Severity describes the impact if the finding is exploitable; confidence
    describes how strong the evidence is. A service-specific body marker
    served by the probed host is the strongest signal. Matching only a bare
    status code is weaker, and matching content served after a redirect to a
    different host is weaker still because the fingerprint may reflect a
    third-party site rather than the scanned subdomain.
    """
    weak_signal = matched_indicator is None or matched_indicator["type"] != "body"
    if weak_signal and cross_host_redirect:
        return "low"
    if weak_signal or cross_host_redirect:
        return "medium"
    return "high"


def _confirms_takeover(subdomain: str, fingerprint: dict) -> _TakeoverResult:
    """Return the tri-state takeover result with probe evidence and confidence."""
    probe = _probe(subdomain)
    if probe.response is None:
        return _TakeoverResult(_ProbeStatus.UNABLE_TO_PROBE, probe.errors)

    response = probe.response
    indicator = fingerprint["indicator"]
    if "status" in indicator:
        confirmed = response.status_code == indicator["status"]
        matched_indicator = (
            {"type": "status", "value": indicator["status"]} if confirmed else None
        )
    else:
        confirmed = indicator["body"].lower() in response.text.lower()
        matched_indicator = (
            {"type": "body", "value": indicator["body"]} if confirmed else None
        )

    redirect_chain = _redirect_chain(response)
    final_url = _response_url(response) or probe.request_url
    final_host = (urlparse(final_url).hostname or "").lower() if final_url else ""
    cross_host_redirect = bool(final_host) and final_host != subdomain.lower()

    evidence = {
        "url": probe.request_url,
        "final_url": final_url,
        "status_code": response.status_code,
        "redirect_chain": list(redirect_chain),
        "cross_host_redirect": cross_host_redirect,
        "matched_indicator": matched_indicator,
    }

    if not confirmed:
        return _TakeoverResult(_ProbeStatus.NO_INDICATOR, evidence=evidence)
    return _TakeoverResult(
        _ProbeStatus.CONFIRMED,
        evidence=evidence,
        confidence=_assess_confidence(matched_indicator, cross_host_redirect),
    )


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
    not_vulnerable = []
    unknown = []
    cname_chains = {}

    for subdomain in subdomains:
        cname_result = _resolve_cname(subdomain, resolver)
        if cname_result.chain:
            cname_chains[subdomain] = list(cname_result.chain)
        if cname_result.error is not None:
            unknown.append({
                "subdomain": subdomain,
                "reason": "Unable to resolve CNAME record",
                "dns_error": cname_result.error,
            })
            continue
        if cname_result.cname is None:
            not_vulnerable.append(subdomain)
            continue
        cname = cname_result.cname

        fingerprint = _match_fingerprint(cname)
        if not fingerprint:
            unknown.append({
                "subdomain": subdomain,
                "reason": "CNAME points to an unsupported service",
            })
            continue

        probe_result = _confirms_takeover(subdomain, fingerprint)
        if probe_result.status is _ProbeStatus.CONFIRMED:
            vulnerable.append({
                "subdomain": subdomain,
                "cname": cname,
                "service": fingerprint["service"],
                "reason": f"CNAME points to unclaimed {fingerprint['service']} service",
                "severity": "HIGH",
                "confidence": probe_result.confidence,
                "evidence": probe_result.evidence,
            })
        elif probe_result.status is _ProbeStatus.NO_INDICATOR:
            not_vulnerable.append(subdomain)
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
        "not_vulnerable": not_vulnerable,
        "unknown": unknown,
        "cname_chains": cname_chains,
        "total_vulnerable": len(vulnerable),
    }
