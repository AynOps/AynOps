"""Subdomain Takeover Checker Tool.

Discovers subdomains via the existing DNS enumeration logic, resolves each
subdomain's CNAME record, matches it against known-vulnerable service
fingerprints (GitHub Pages, Heroku, S3, Azure, Ghost, Shopify, Fastly), and
confirms the takeover with an HTTP request checking for the service's
takeover-indicating response.
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
_AZURE_RE = re.compile(r"(?:^|\.)(?:azurewebsites\.net|cloudapp\.net|trafficmanager\.net)$")
_GHOST_RE = re.compile(r"(?:^|\.)ghost\.io$")
_SHOPIFY_RE = re.compile(r"(?:^|\.)myshopify\.com$")
_FASTLY_RE = re.compile(r"(?:^|\.)(?:fastly\.net|fastlylb\.net)$")

# Vulnerable service fingerprints with regex patterns and multi-signal takeover indicators.
# Indicator keys: "status" matches HTTP status code, "body" matches text substring, "headers" matches response headers.
VULNERABLE_FINGERPRINTS = [
    {"cname_pattern": _GITHUB_PAGES_RE, "service": "GitHub Pages", "indicator": {"body": "There isn't a GitHub Pages site here."}},
    {"cname_pattern": _HEROKU_RE, "service": "Heroku", "indicator": {"body": "No such app"}},
    {"cname_pattern": _S3_ENDPOINT_RE, "service": "AWS S3", "indicator": {"body": "NoSuchBucket"}},
    {"cname_pattern": _AZURE_RE, "service": "Azure", "indicator": {"body": "404 Web Site not found"}},
    {"cname_pattern": _GHOST_RE, "service": "Ghost", "indicator": {"body": "404 Domain Not Found"}},
    {"cname_pattern": _SHOPIFY_RE, "service": "Shopify", "indicator": {"body": "Sorry, this shop"}},
    {"cname_pattern": _FASTLY_RE, "service": "Fastly", "indicator": {"body": "Fastly error: unknown domain"}},
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
    errors: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class _TakeoverResult:
    status: _ProbeStatus
    probe_errors: tuple[dict[str, str], ...] = ()


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
                        return f"Host {hostname} resolved to private/reserved IP {ip_str}"
            except Exception:
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
        if pattern is not None:
            if pattern.search(cname):
                return fingerprint
        elif "cname_contains" in fingerprint and fingerprint["cname_contains"] in cname:
            return fingerprint
    return None


def _probe(subdomain: str, resolver=None) -> _ProbeResult:
    """Fetch the subdomain over HTTPS first, falling back to HTTP.

    Inspects redirect chains up to 3 hops without crossing into unsafe IP space
    or diverging to unrelated target hostnames.
    Returns the response and any errors if neither scheme connects.
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
        current_url = f"{scheme}://{subdomain_clean}"
        visited_urls = set()
        hops = 0
        last_response = None
        scheme_failed = False

        while hops <= _MAX_REDIRECT_HOPS:
            visited_urls.add(current_url)
            parsed = urlparse(current_url)
            host = (parsed.hostname or subdomain_clean).lower()

            hop_ssrf = _check_host_ssrf(host, resolver)
            if hop_ssrf:
                errors.append({
                    "scheme": scheme,
                    "error": f"SSRFBlocked: {hop_ssrf}",
                })
                scheme_failed = True
                break

            try:
                response = requests.get(
                    current_url,
                    headers=_REQUEST_HEADERS,
                    timeout=_REQUEST_TIMEOUT,
                    allow_redirects=False,
                )
                last_response = response
            except requests.exceptions.RequestException as exc:
                errors.append({
                    "scheme": scheme,
                    "error": f"{type(exc).__name__}: {exc}",
                })
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

                # Stop redirect following if target leaves the subdomain scope
                if next_host and next_host != host and not next_host.endswith("." + host):
                    break

                if next_url in visited_urls:
                    break

                current_url = next_url
                hops += 1
                continue
            else:
                break

        if not scheme_failed and last_response is not None:
            return _ProbeResult(response=last_response)

    return _ProbeResult(response=None, errors=tuple(errors))


def _confirms_takeover(subdomain: str, fingerprint: dict, resolver=None) -> _TakeoverResult:
    """Return the tri-state takeover result and probe failure evidence."""
    probe = _probe(subdomain, resolver=resolver)
    if probe.response is None:
        return _TakeoverResult(_ProbeStatus.UNABLE_TO_PROBE, probe.errors)

    indicator = fingerprint["indicator"]
    confirmed = True
    if "status" in indicator:
        if getattr(probe.response, "status_code", None) != indicator["status"]:
            confirmed = False
    if "body" in indicator:
        text = getattr(probe.response, "text", "")
        if isinstance(text, str):
            if indicator["body"].lower() not in text.lower():
                confirmed = False
        else:
            confirmed = False
    if "headers" in indicator:
        headers = getattr(probe.response, "headers", {})
        for header, expected in indicator["headers"].items():
            actual = headers.get(header, "") if hasattr(headers, "get") else ""
            if not isinstance(actual, str) or expected.lower() not in actual.lower():
                confirmed = False
                break

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

        probe_result = _confirms_takeover(subdomain, fingerprint, resolver=resolver)
        if probe_result.status is _ProbeStatus.CONFIRMED:
            vulnerable.append({
                "subdomain": subdomain,
                "cname": cname,
                "service": fingerprint["service"],
                "reason": f"CNAME points to unclaimed {fingerprint['service']} service",
                "severity": "HIGH",
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
