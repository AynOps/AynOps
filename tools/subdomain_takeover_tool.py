"""Subdomain Takeover Checker Tool.

Discovers subdomains via the existing DNS enumeration logic, resolves each
subdomain's CNAME record, matches it against known-vulnerable service
fingerprints (GitHub Pages, Heroku, S3, Azure, Ghost, Shopify, Fastly), and
confirms the takeover with an HTTP request checking for the service's
takeover-indicating response.

Scope:
This tool assumes public internet targets only and will refuse to probe
private/internal IP ranges (RFC 1918, loopback, link-local, multicast).
"""

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urljoin, urlparse

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

_GITHUB_PAGES_RE = re.compile(r"(?:^|\.)github\.io$")
_HEROKU_RE = re.compile(r"(?:^|\.)(?:herokuapp\.com|herokussl\.com|herokudns\.com)$")
_AZURE_RE = re.compile(
    r"(?:^|\.)(?:azurewebsites\.net|cloudapp\.net|trafficmanager\.net)$"
)
_GHOST_RE = re.compile(r"(?:^|\.)ghost\.io$")
_SHOPIFY_RE = re.compile(r"(?:^|\.)myshopify\.com$")
_FASTLY_RE = re.compile(r"(?:^|\.)(?:fastly\.net|fastlylb\.net)$")

# Vulnerable service fingerprints with regex patterns and multi-signal takeover indicators.
# Every entry uses at least two independent signals so that a single vendor copy-change
# cannot produce a false positive. This fully addresses Issue #7.
#
# Indicator keys:
#   "status"  — exact HTTP status code (int)
#   "body"    — case-insensitive substring present in the response body
#   "headers" — dict of header-name -> required substring (case-insensitive)
#
# Signal rationale per service:
#   GitHub Pages : 404 + canonical error phrase + "GitHub Pages" server identity header
#   Heroku       : 404 + canonical error phrase + Heroku request-id header present
#   AWS S3       : 404 + "NoSuchBucket" XML error code + S3 server identity header
#   Azure        : 404 + canonical error phrase + Azure service header
#   Ghost        : 404 + canonical error phrase + Ghost platform header
#   Shopify      : 404 + canonical error phrase + Shopify powered-by header
#   Fastly       : 500 + canonical error phrase + Fastly cache node header
VULNERABLE_FINGERPRINTS = [
    {
        "cname_pattern": _GITHUB_PAGES_RE,
        "service": "GitHub Pages",
        "indicator": {
            "status": 404,
            "body": "There isn't a GitHub Pages site here.",
            "headers": {"server": "GitHub.com"},
        },
    },
    {
        "cname_pattern": _HEROKU_RE,
        "service": "Heroku",
        "indicator": {
            "status": 404,
            "body": "No such app",
            "headers": {"x-request-id": ""},
        },
    },
    {
        "cname_pattern": _S3_ENDPOINT_RE,
        "service": "AWS S3",
        "indicator": {
            "status": 404,
            "body": "NoSuchBucket",
            "headers": {"server": "AmazonS3"},
        },
    },
    {
        "cname_pattern": _AZURE_RE,
        "service": "Azure",
        "indicator": {
            "status": 404,
            "body": "404 Web Site not found",
            "headers": {"x-ms-request-id": ""},
        },
    },
    {
        "cname_pattern": _GHOST_RE,
        "service": "Ghost",
        "indicator": {
            "status": 404,
            "body": "404 Domain Not Found",
            "headers": {"x-ghost-cache-status": ""},
        },
    },
    {
        "cname_pattern": _SHOPIFY_RE,
        "service": "Shopify",
        "indicator": {
            "status": 404,
            "body": "Sorry, this shop",
            "headers": {"x-shopid": ""},
        },
    },
    {
        "cname_pattern": _FASTLY_RE,
        "service": "Fastly",
        "indicator": {
            "status": 500,
            "body": "Fastly error: unknown domain",
            "headers": {"x-served-by": "cache"},
        },
    },
]

_REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
_REQUEST_TIMEOUT = 10
_MAX_CNAME_DEPTH = 5
_MAX_REDIRECT_HOPS = 3


class _ProbeStatus(str, Enum):
    CONFIRMED = "confirmed"
    NO_INDICATOR = "no_indicator"
    UNABLE_TO_PROBE = "unable_to_probe"


@dataclass(frozen=True)
class _ProbeResult:
    response: requests.Response | None
    request_url: str | None = None
    redirect_chain: tuple[str, ...] = ()
    errors: tuple[dict[str, str], ...] = ()
    # Absolute URL of a redirect target the scope guard refused to follow.
    # Recorded for evidence only — it is never requested.
    rejected_redirect_url: str | None = None


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


def _is_private_or_reserved_ip(ip_str: str) -> bool:
    """Return True if ip_str is a valid IP address in private/loopback/reserved space."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


def _check_host_ssrf(hostname: str, resolver=None) -> str | None:
    """Check if hostname is or resolves to private/reserved IP space. Return error string if unsafe."""
    # Check if hostname itself is a private or reserved IP literal
    if _is_private_or_reserved_ip(hostname):
        return f"Host {hostname} is a private/reserved IP address"

    if resolver is not None:
        for rtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(hostname, rtype, lifetime=3)
                for ans in answers:
                    ip_str = str(ans).strip()
                    if _is_private_or_reserved_ip(ip_str):
                        return (
                            f"Host {hostname} resolved to private/reserved IP {ip_str}"
                        )
            except Exception:  # noqa: S112 - intentional fail-open during pre-check;
                # unreachable or failing hosts will safely fail downstream in requests.
                continue

    return None


def _resolve_cname(subdomain: str, resolver) -> _CnameResolution:
    """Resolve a bounded CNAME chain using UDP-first resolution and distinguish absence from failure."""
    current = subdomain.lower().rstrip(".")
    seen = {current}
    chain = []

    while True:
        try:
            answers = resolver.resolve(current, "CNAME", lifetime=5)
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
        if pattern is not None and pattern.search(cname):
            return fingerprint
    return None


def _probe(subdomain: str, resolver=None) -> _ProbeResult:
    """Fetch the subdomain over HTTPS first, falling back to HTTP.

    Inspects redirect chains up to 3 hops without crossing into unsafe IP space
    or diverging to unrelated target hostnames. A redirect target rejected by
    the scope guard is preserved in ``rejected_redirect_url`` without being
    requested. Returns the response and any errors if neither scheme connects.
    """
    errors = []
    subdomain_clean = subdomain.strip().rstrip(".")
    ssrf_err = _check_host_ssrf(subdomain_clean, resolver)
    if ssrf_err:
        return _ProbeResult(
            response=None,
            errors=({"scheme": "all", "error": f"SSRFBlocked: {ssrf_err}"},),
        )

    for scheme in ("https", "http"):
        request_url = f"{scheme}://{subdomain_clean}"
        current_url = request_url
        visited_urls = set()
        redirect_chain = []
        hops = 0
        last_response = None
        scheme_failed = False
        rejected_redirect_url = None

        while hops <= _MAX_REDIRECT_HOPS:
            visited_urls.add(current_url)
            redirect_chain.append(current_url)
            parsed = urlparse(current_url)
            host = (parsed.hostname or subdomain_clean).lower()

            hop_ssrf = _check_host_ssrf(host, resolver)
            if hop_ssrf:
                errors.append(
                    {
                        "scheme": scheme,
                        "url": current_url,
                        "error": f"SSRFBlocked: {hop_ssrf}",
                    }
                )
                scheme_failed = True
                break

            try:
                # Note: requests.get below resolves the host independently via system DNS.
                # This pre-check minimizes SSRF exposure, though a residual TOCTOU window
                # remains without socket IP pinning.
                response = requests.get(
                    current_url,
                    headers=_REQUEST_HEADERS,
                    timeout=_REQUEST_TIMEOUT,
                    allow_redirects=False,
                )
                last_response = response
            except requests.exceptions.RequestException as exc:
                errors.append(
                    {
                        "scheme": scheme,
                        "url": current_url,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                scheme_failed = True
                break

            if getattr(response, "status_code", None) in (301, 302, 303, 307, 308):
                location = None
                headers = getattr(response, "headers", None)
                if headers and hasattr(headers, "get"):
                    raw_loc = headers.get("Location")
                    if isinstance(raw_loc, str) and raw_loc.strip():
                        location = raw_loc.strip()

                if not location:
                    break

                next_url = urljoin(current_url, location)
                next_parsed = urlparse(next_url)
                next_host = (next_parsed.hostname or "").lower()

                # Stop redirect following if target leaves the original target subdomain scope
                target_scope = subdomain_clean.lower()
                if (
                    next_host
                    and next_host != target_scope
                    and not next_host.endswith("." + target_scope)
                ):
                    # Preserve the rejected Location as evidence without
                    # requesting it — fetching it would defeat the scope guard.
                    rejected_redirect_url = next_url
                    break

                if next_url in visited_urls:
                    break

                current_url = next_url
                hops += 1
                continue
            else:
                break

        if not scheme_failed and last_response is not None:
            return _ProbeResult(
                response=last_response,
                request_url=request_url,
                redirect_chain=tuple(redirect_chain),
                rejected_redirect_url=rejected_redirect_url,
            )

    return _ProbeResult(response=None, errors=tuple(errors))


def _response_url(response) -> str | None:
    """Return the response's URL, tolerating test doubles that lack one."""
    url = getattr(response, "url", None)
    return url if isinstance(url, str) else None


def _assess_confidence(
    matched_indicator: dict | None, cross_host_redirect: bool
) -> str:
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


def _confirms_takeover(
    subdomain: str, fingerprint: dict, resolver=None
) -> _TakeoverResult:
    """Return the tri-state takeover result with probe evidence and confidence."""
    probe = _probe(subdomain, resolver=resolver)
    if probe.response is None:
        return _TakeoverResult(_ProbeStatus.UNABLE_TO_PROBE, probe.errors)

    response = probe.response
    indicator = fingerprint["indicator"]
    confirmed = True
    if (
        "status" in indicator
        and getattr(response, "status_code", None) != indicator["status"]
    ):
        confirmed = False
    if "body" in indicator:
        text = getattr(response, "text", "")
        if isinstance(text, str):
            if indicator["body"].lower() not in text.lower():
                confirmed = False
        else:
            confirmed = False
    if "headers" in indicator:
        raw_headers = getattr(response, "headers", {})
        # Support both CaseInsensitiveDict (requests) and plain dicts (tests)
        headers = (
            {str(k).lower(): v for k, v in raw_headers.items()}
            if hasattr(raw_headers, "items")
            else raw_headers
        )
        for header, expected in indicator["headers"].items():
            actual = headers.get(header.lower()) if hasattr(headers, "get") else None
            if actual is None:
                # Header must be present; absence is not a match
                confirmed = False
                break
            if expected != "" and (
                not isinstance(actual, str) or expected.lower() not in actual.lower()
            ):
                # Header present but value doesn't contain the required substring
                confirmed = False
                break

    # Report the strongest declaring signal that matched: a service-specific
    # body marker is stronger evidence than a bare status code or header.
    matched_indicator = None
    if confirmed:
        if "body" in indicator:
            matched_indicator = {"type": "body", "value": indicator["body"]}
        elif "status" in indicator:
            matched_indicator = {"type": "status", "value": indicator["status"]}
        elif "headers" in indicator:
            matched_indicator = {"type": "headers", "value": indicator["headers"]}

    request_url = probe.request_url if isinstance(probe.request_url, str) else None
    chain = (
        list(probe.redirect_chain)
        if isinstance(probe.redirect_chain, (list, tuple))
        else []
    )
    rejected_redirect_url = getattr(probe, "rejected_redirect_url", None)
    if not isinstance(rejected_redirect_url, str):
        rejected_redirect_url = None
    # A redirect target rejected by the scope guard is reported as the
    # chain's terminal hop so the evidence exposes where the redirect
    # pointed; it was never requested (see rejected_redirect_url).
    if rejected_redirect_url is not None:
        chain.append(rejected_redirect_url)

    final_url = (
        rejected_redirect_url
        or _response_url(response)
        or (chain[-1] if chain else request_url)
    )
    final_host = (urlparse(final_url).hostname or "").lower() if final_url else ""
    target_host = subdomain.strip().rstrip(".").lower()
    cross_host_redirect = bool(final_host) and final_host != target_host

    evidence = {
        "url": request_url,
        "final_url": final_url,
        "status_code": getattr(response, "status_code", None),
        "redirect_chain": chain,
        "rejected_redirect_url": rejected_redirect_url,
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
            unknown.append(
                {
                    "subdomain": subdomain,
                    "reason": "Unable to resolve CNAME record",
                    "dns_error": cname_result.error,
                }
            )
            continue
        if cname_result.cname is None:
            not_vulnerable.append(subdomain)
            continue
        cname = cname_result.cname

        fingerprint = _match_fingerprint(cname)
        if not fingerprint:
            unknown.append(
                {
                    "subdomain": subdomain,
                    "reason": "CNAME points to an unsupported service",
                }
            )
            continue

        probe_result = _confirms_takeover(subdomain, fingerprint, resolver=resolver)
        if probe_result.status is _ProbeStatus.CONFIRMED:
            vulnerable.append(
                {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": fingerprint["service"],
                    "reason": f"CNAME points to unclaimed {fingerprint['service']} service",
                    "severity": "HIGH",
                    "confidence": probe_result.confidence,
                    "evidence": probe_result.evidence,
                }
            )
        elif probe_result.status is _ProbeStatus.NO_INDICATOR:
            not_vulnerable.append(subdomain)
        else:
            unknown.append(
                {
                    "subdomain": subdomain,
                    "reason": "Unable to complete HTTP probe over HTTPS or HTTP",
                    "probe_errors": list(probe_result.probe_errors),
                }
            )

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
