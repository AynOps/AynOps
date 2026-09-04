"""HTTP Security Headers Analyzer Tool.

Analyzes the actual values of HTTP security headers and flags
misconfigurations with severity ratings.
"""
from __future__ import annotations

from urllib.parse import urljoin
from curl_cffi import requests
from curl_cffi.requests.errors import RequestsError
from typing import Any, List, Dict

from utils.helpers import is_valid_domain, normalize_domain

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_MAX_REDIRECT_HOPS = 8

# Sensitive Permissions-Policy features worth flagging when wildcarded
# to all origins. Not exhaustive, these are the ones with the most
# direct privacy/security impact if left unrestricted.
_SENSITIVE_PERMISSIONS_FEATURES = (
    "camera", "microphone", "geolocation", "payment", "usb",
)

_GOOD_REFERRER_POLICIES = {
    "no-referrer",
    "strict-origin-when-cross-origin",
    "same-origin",
    "strict-origin",
}

_ALL_VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}

_WAF_BLOCK_PAGE_HEADER_SIGNATURES = (
    ("cf-mitigated", "challenge", "Cloudflare", None),
)

# Body-content signatures: (substring to search for in the lowercased
# response body, provider label, minimum status code required or None).
# A single needle is a str; a tuple means ALL listed substrings must be
# present (AND semantics).
#
# Needed because some providers' block pages aren't distinguishable via
# headers alone: Imperva/Incapsula's X-Iinfo and X-CDN headers are
# present on BOTH normal and blocked responses (confirmed: geico.com
# shows X-Iinfo on its 200 homepage AND its 403 block page, just with a
# different internal value each time), so headers can't tell them apart.
# The block page's body is distinctive instead; it embeds
# <iframe src="/_Incapsula_Resource?..."> that never appears in real
# page content. Confirmed live against geico.com (403, plain
# non-impersonated request), and independently corroborated by a
# third-party anti-bot-bypass reference (scrapfly.io) and a 2020
# GitHub issue (chromedp/chromedp#561) showing the identical HTML
# structure, so this isn't a one-site coincidence. status_code >= 400
# required for the same reason as Akamai's entry above: only 1 directly
# confirmed live sample, no proof this string is exclusive to block
# pages, so an error-class status is required as a second signal
# rather than trusting the body substring alone.
#
# Akamai is detected by BODY fingerprint, not the Server header, for the
# opposite reason: `Server: AkamaiGHost` identifies Akamai's edge
# infrastructure, not mitigation. Every response served from an
# Akamai-fronted origin carries it, including ordinary 401/403/404/5xx
# responses that pass straight through the edge (issue #194), so
# `Server: AkamaiGHost` + status >= 400 misclassified regular errors as
# blocks and aborted analysis. Akamai's own deny page instead embeds
# two markers together — an "Access Denied" heading and a
# "Reference #" error identifier — that an origin error page does not
# pair with the edge header. Requiring BOTH substrings on an error
# status keeps genuine blocks detected while ordinary errors are
# analyzed normally.
_WAF_BLOCK_PAGE_BODY_SIGNATURES = (
    ("_incapsula_resource", "Imperva", 400),
    (("access denied", "reference #"), "Akamai", 400),
)


def _detect_waf_block_page(raw_headers: dict, status_code: int, body: str) -> str | None:
    """Return the provider name if this response (headers and/or body)
    looks like a WAF's own block/challenge page rather than real site
    content, else None. Header signatures are checked first since
    they're a cheap dict lookup; body signatures require a substring
    search over the full response body.
    """
    for header_name, expected_value, provider, min_status in _WAF_BLOCK_PAGE_HEADER_SIGNATURES:
        if raw_headers.get(header_name, "").lower() != expected_value:
            continue
        if min_status is not None and status_code < min_status:
            continue
        return provider

    body_lower = body.lower()
    for needles, provider, min_status in _WAF_BLOCK_PAGE_BODY_SIGNATURES:
        required = (needles,) if isinstance(needles, str) else needles
        if not all(needle in body_lower for needle in required):
            continue
        if min_status is not None and status_code < min_status:
            continue
        return provider

    return None


def _walk_redirect_chain(url: str, max_hops: int = _MAX_REDIRECT_HOPS) -> List[Dict[str, Any]]:
    """Manually follow redirects one hop at a time, capturing each
    response's status, headers, and body along the way.

    Body is captured (not just headers) because some WAF block pages
    aren't distinguishable via headers alone; see
    _WAF_BLOCK_PAGE_BODY_SIGNATURES. This adds no extra network cost:
    resp.text is already downloaded as part of the same GET, it just
    wasn't being read anywhere before. Body is intentionally NOT
    included in headers_analyzer's public redirect_chain output, it's
    only used internally for the block-page check to avoid bloating
    the return payload with full page HTML on every call.

    curl_cffi's built-in allow_redirects=True (like every other HTTP
    client's auto-follow) only ever surfaces the FINAL response. If an
    intermediate hop, the redirect response itself carries
    different security headers than the destination ( many sites apply
    a baseline header set at a load-balancer/WAF layer that issues
    the redirect, then different page-specific headers on the destination),
    that's invisible with auto-follow. This was a confirmed, real source
    of "differs from DevTools" reports, since DevTools shows every hop
    in the chain as a separate entry.
    """
    hops: List[Dict[str, Any]] = []
    current_url = url
    seen = set()

    while len(hops) < max_hops:
        if current_url in seen:
            break  # redirect loop guard
        seen.add(current_url)

        resp = requests.get(
            current_url, timeout=10, impersonate="chrome", allow_redirects=False
        )
        hops.append({
            "url": current_url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers.items()),
            "body": resp.text,
        })

        if resp.status_code in _REDIRECT_STATUSES:
            location = resp.headers.get("location")
            if not location:
                break
            current_url = urljoin(current_url, location)
            continue
        break

    return hops


def headers_analyzer(domain: str) -> dict:
    """Analyze HTTP security headers for a domain.

    Returns a dict with header analysis including present/absent status,
    actual values, issues found, and severity ratings.

    Parameters
    ----------
    domain
        The domain to analyze (e.g. "example.com")

    Returns
    -------
    dict
        On success: ``{"success": True, "domain": ..., "requested_url": ...,
        "final_url": ..., "redirected": bool, "redirect_chain": [...],
        "headers": {...}}``.

        ``headers`` is the severity analysis of the final hop (the actual
        page a browser would land on). ``redirect_chain`` lists every hop
        walked to get there, each with its own ``url``, ``status_code``,
        raw ``headers``, and an ``analysis`` (same structure and rules as
        the top-level ``headers``, run against that hop's own response;
        see ``_analyze_raw_headers`` for the caveat on interpreting
        findings from non-final hops). The last entry in ``redirect_chain``
        always mirrors the top-level ``headers`` exactly.

        On failure: ``{"success": False, "error": ...}``.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    requested_url = f"https://{domain}"

    try:
        # impersonate="chrome" matches a real Chrome TLS fingerprint and
        # negotiates modern HTTP (h2/h3) instead of a bare-Python TLS
        # signature over HTTP/1.1. Many sites behind a WAF (Cloudflare
        # especially) serve a JS bot-challenge page instead of the real
        # site to clients that don't look like a real browser at the
        # TLS/protocol level, confirmed against a real production site:
        # a plain non-impersonated client got Cloudflare's challenge page
        # (cf-mitigated: challenge) with its own unrelated security
        # headers, while impersonate="chrome" reached the real site. Same
        # library/pattern already used in crt_sh_tool.py for this reason.
        hops = _walk_redirect_chain(requested_url)

        if not hops:
            return {"success": False, "error": "No response received"}

        final_hop = hops[-1]

        # If the chain ends ON a redirect status, we never actually reached
        # real page content, this happens when a redirect loop is
        # detected (e.g. a misconfigured server that 301s to itself) or
        # when the hop cap is hit mid-chain. Confirmed via testing: without
        # this check, the tool would silently analyze the REDIRECT
        # response's own headers (often minimal/unrelated to the page) as
        # if they were the site's real security configuration, and report
        # redirected=False even though a redirect demonstrably occurred.
        if final_hop["status_code"] in _REDIRECT_STATUSES:
            return {
                "success": False,
                "error": (
                    f"Could not reach final page content -- redirect chain "
                    f"did not resolve (stopped after {len(hops)} hop(s) at "
                    f"a {final_hop['status_code']} response, either due to "
                    f"a redirect loop or exceeding the {_MAX_REDIRECT_HOPS}-hop "
                    f"limit). The headers on that response are not the "
                    f"site's actual configuration."
                ),
            }

        final_url = final_hop["url"]
        domain = final_url.split("/")[2]
        redirected = len(hops) > 1

        # curl_cffi (like the `requests` library it mirrors) already
        # combines a header that appears more than once in a response into
        # one comma-joined value while parsing, matching what DevTools
        # displays. This matters because a header appearing more than once
        # (e.g. two Content-Security-Policy directives layered from
        # different sources, a CDN and the origin server) must not be
        # silently collapsed down to just one of them; every combined
        # directive has to be visible for the analysis below to be
        # accurate.
        raw_headers = {k.lower(): v for k, v in final_hop["headers"].items()}

        # Defensive check: if a WAF challenge/block page gets served
        # instead of the real site despite impersonation, its headers
        # belong to that page, not the site; analyzing them as if they
        # were the site's real security posture would be actively
        # misleading. Checked via a small signature table so adding a
        # new provider is a one-line addition, not new branching logic.
        blocked_by = _detect_waf_block_page(
            raw_headers, final_hop["status_code"], final_hop["body"]
        )
        if blocked_by:
            return {
                "success": False,
                "error": (
                    f"Received a bot-detection challenge/block page instead "
                    f"of the real site ({blocked_by} detected). Headers "
                    f"from this page do not reflect the site's actual "
                    f"configuration, so no analysis was performed."
                ),
            }

    except RequestsError as e:
        return {"success": False, "error": f"Connection failed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

    headers = _analyze_raw_headers(raw_headers)

    redirect_chain = []
    for h in hops:
        # Computed once, reused for both the raw view and the analysis
        # below, avoids lowercasing the same dict twice per hop.
        hop_headers = {k.lower(): v for k, v in h["headers"].items()}
        redirect_chain.append({
            "url": h["url"],
            "status_code": h["status_code"],
            "headers": hop_headers,
            "analysis": _analyze_raw_headers(hop_headers),
        })

    return {
        "success": True,
        "domain": domain,
        "requested_url": requested_url,
        "final_url": final_url,
        "redirected": redirected,
        "redirect_chain": redirect_chain,
        "headers": headers,
    }


def _analyze_raw_headers(raw_headers: dict) -> dict:
    """Run every header check against one response's headers.

    Takes a single hop's lowercased headers dict and returns the same
    ``headers`` analysis structure used at the top level of
    ``headers_analyzer``'s result. Factored out so the exact same rules
    apply whether it's being run on the final page or an intermediate
    redirect hop.

    Caveat this does NOT attempt to solve: content-dependent headers
    (CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy,
    Referrer-Policy) are checked the same way on every hop, including
    bare redirect responses that never carry them because there's no
    page content at that layer to protect. A load-balancer-issued 301
    will near-universally show "CSP missing, severity high" here;
    that's an accurate description of THAT response, not a finding
    about the site. Building a per-status-code significance model to
    suppress that would be a separate, more speculative feature; this
    function stays a plain, uniform ruleset and leaves interpretation
    of intermediate-hop findings to the caller.
    """
    headers: dict[str, Any] = {}

    # --- Strict-Transport-Security ---
    hsts = raw_headers.get("strict-transport-security", "")
    if hsts:
        hsts_lower = hsts.lower()
        issues = []
        severity = "low"
        if "max-age=" in hsts_lower:
            try:
                max_age = int(hsts_lower.split("max-age=")[1].split(";")[0].strip())
                if max_age < 0:
                    issues.append(f"max-age is {max_age}, which is invalid (must be non-negative)")
                    severity = "high"
                elif max_age == 0:
                    issues.append("max-age is 0 — this actively disables HSTS, removing protection")
                    severity = "high"
                elif max_age < 31536000:
                    issues.append(f"max-age is {max_age}, recommend 31536000 (1 year)")
                    severity = "medium"
            except (ValueError, IndexError):
                issues.append("Could not parse max-age value")
                severity = "medium"
        else:
            issues.append("max-age directive is missing")
            severity = "high"
        if "includesubdomains" not in hsts_lower:
            issues.append("includeSubDomains directive is missing")
            if severity == "low":
                severity = "medium"
        headers["strict-transport-security"] = {
            "present": True,
            "value": hsts,
            "issue": "; ".join(issues) if issues else "None",
            "severity": severity,
        }
    else:
        headers["strict-transport-security"] = {
            "present": False,
            "value": "",
            "issue": "HSTS header is missing. Without it, browsers may connect over plain HTTP.",
            "severity": "high",
        }

    # --- Content-Security-Policy ---
    csp = raw_headers.get("content-security-policy", "")
    # Also check report-only variant if no enforcing CSP found
    if not csp:
        csp = raw_headers.get("content-security-policy-report-only", "")
        report_only = True
    else:
        report_only = False
    if csp:
        csp_lower = csp.lower()
        issues = []
        severity = "low"
        if "'unsafe-inline'" in csp_lower:
            issues.append("Contains 'unsafe-inline' which negates XSS protection")
            severity = "high"
        if "'unsafe-eval'" in csp_lower:
            issues.append("Contains 'unsafe-eval' which allows eval()")
            severity = "high"
        has_wildcard = False
        for directive_str in csp_lower.split(';'):
            tokens = directive_str.split()
            if not tokens:
                continue
            name = tokens[0]
            if name in ('default-src', 'script-src') and '*' in tokens[1:]:
                has_wildcard = True
                break

        if has_wildcard:
            issues.append("Wildcard (*) source defeats the purpose of CSP")
            severity = "high"
        # A CSP without a restrictive default-src (neither 'self' nor
        # 'none') leaves an implicit fallback that's effectively
        # unrestricted for any directive not explicitly listed.
        if "default-src 'none'" not in csp_lower and "default-src 'self'" not in csp_lower:
            issues.append("No restrictive default-src directive found")
            if severity == "low":
                severity = "medium"
        if report_only:
            issues.insert(0, "CSP is report-only mode — violations are reported but not enforced")
            if severity == "low":
                severity = "medium"
        headers["content-security-policy"] = {
            "present": True,
            "value": csp[:200] + ("..." if len(csp) > 200 else ""),
            "issue": "; ".join(issues) if issues else "None",
            "severity": severity,
        }
    else:
        headers["content-security-policy"] = {
            "present": False,
            "value": "",
            "issue": "CSP header is missing. Without it, no restrictions on resource loading.",
            "severity": "high",
        }

    # --- X-Frame-Options ---
    xfo = raw_headers.get("x-frame-options", "")
    if xfo:
        xfo_upper = xfo.upper().strip()
        if xfo_upper in ("DENY", "SAMEORIGIN"):
            headers["x-frame-options"] = {
                "present": True,
                "value": xfo,
                "issue": "None",
                "severity": "low",
            }
        else:
            headers["x-frame-options"] = {
                "present": True,
                "value": xfo,
                "issue": f"Unexpected value '{xfo}', expected DENY or SAMEORIGIN",
                "severity": "medium",
            }
    else:
        headers["x-frame-options"] = {
            "present": False,
            "value": "",
            "issue": "X-Frame-Options is missing. Page can be embedded in iframes (clickjacking).",
            "severity": "medium",
        }

    # --- X-Content-Type-Options ---
    xcto = raw_headers.get("x-content-type-options", "")
    if xcto and xcto.lower().strip() == "nosniff":
        headers["x-content-type-options"] = {
            "present": True,
            "value": xcto,
            "issue": "None",
            "severity": "low",
        }
    else:
        headers["x-content-type-options"] = {
            "present": False,
            "value": xcto,
            "issue": "X-Content-Type-Options is missing or not set to 'nosniff'. Browsers may MIME-sniff responses.",
            "severity": "medium",
        }

    # --- Referrer-Policy ---
    rp = raw_headers.get("referrer-policy", "")
    if rp:
        tokens = [t.strip() for t in rp.lower().split(",") if t.strip()]
        effective_policy = None
        for token in reversed(tokens):
            if token in _ALL_VALID_REFERRER_POLICIES:
                effective_policy = token
                break
        if effective_policy is None and tokens:
            effective_policy = tokens[-1]

        if effective_policy in _GOOD_REFERRER_POLICIES:
            headers["referrer-policy"] = {
                "present": True,
                "value": rp,
                "issue": "None",
                "severity": "low",
            }
        else:
            headers["referrer-policy"] = {
                "present": True,
                "value": rp,
                "issue": f"Policy '{rp}' may leak more referrer information than necessary",
                "severity": "medium",
            }
    else:
        headers["referrer-policy"] = {
            "present": False,
            "value": "",
            "issue": "Referrer-Policy is missing. Full referrer URLs may leak to third parties.",
            "severity": "low",
        }

    # --- Permissions-Policy ---
    pp = raw_headers.get("permissions-policy", "")
    if pp:
        pp_lower = pp.lower()
        issues = []
        severity = "low"
        # Previously: presence alone was treated as "issue: None, severity:
        # low", regardless of content. Unlike every other header in this
        # file, which evaluates actual values, not just presence. A policy
        # wildcarding a sensitive feature to all origins (e.g. "camera=*")
        # provides essentially no restriction despite being "present".
        for feature in _SENSITIVE_PERMISSIONS_FEATURES:
            if f"{feature}=*" in pp_lower:
                issues.append(f"'{feature}' is granted to all origins (wildcard) — consider restricting")
                severity = "medium"
        headers["permissions-policy"] = {
            "present": True,
            "value": pp[:100] + ("..." if len(pp) > 100 else ""),
            "issue": "; ".join(issues) if issues else "None",
            "severity": severity,
        }
    else:
        headers["permissions-policy"] = {
            "present": False,
            "value": "",
            "issue": "Permissions-Policy is missing. Powerful browser APIs are unrestricted.",
            "severity": "low",
        }

    # --- Information disclosure headers
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        val = raw_headers.get(hdr, "")
        if val:
            headers[hdr.lower()] = {
                "present": True,
                "value": val,
                "issue": f"{hdr} header exposes technology information",
                "severity": "low",
            }

    return headers
