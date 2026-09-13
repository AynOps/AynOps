from __future__ import annotations
import concurrent.futures
import datetime
import dns.resolver
import dns.exception
from typing import Any, Dict, List, Tuple
from utils.helpers import is_valid_domain, normalize_domain

# Base generic defaults
BASE_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "dkim", "mail", "smtp", "s1", "s2", "mandrill", "mxvault",
    "zoho", "amazonses",
]

def _query_txt(name: str) -> Tuple[List[str], bool]:
    """Return (txt_record_strings, resolution_failed) for a DNS name."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0
    
    try:
        answers = resolver.resolve(name, "TXT")
        records = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
        return records, False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], False
    except (dns.resolver.Timeout, dns.exception.DNSException):
        try:
            resolver.nameservers = ['1.1.1.1', '8.8.8.8']
            answers = resolver.resolve(name, "TXT")
            records = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
            return records, False
        except Exception:
            return [], True
    except Exception:
        return [], True


def _discover_dynamic_selectors(domain: str) -> List[str]:
    """
    Inspects MX records to append smart infrastructure-specific selectors.
    For example, if a domain uses Google Workspace, it adds specific internal 
    Google infrastructure selectors.
    """
    dynamic_selectors = set()
    
    # 1. Inject temporal/historical pattern-matching common in enterprise setups (e.g., 2023, 2024, 2025, 2026)
    current_year = datetime.datetime.now().year
    for year in range(current_year - 3, current_year + 1):
        dynamic_selectors.add(f"google{year}")
        dynamic_selectors.add(str(year))
        for month in ["01", "03", "06", "09", "12"]:
            dynamic_selectors.add(f"{year}{month}")
            dynamic_selectors.add(f"{year}{month}01")

    # 2. Extract context via MX records
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        mx_answers = resolver.resolve(domain, "MX")
        mx_hosts = [str(mx.exchange).lower() for mx in mx_answers]
        
        for host in mx_hosts:
            if "google" in host or "aspmx" in host:
                # Add known custom variants Google uses internally for corporate components
                dynamic_selectors.update(["google", "20230601", "20161025", "scph0615"])
            if "pphosted" in host or "proofpoint" in host:
                dynamic_selectors.update(["pp", "proofpoint", "selector"])
            if "protection.outlook" in host:
                dynamic_selectors.update(["selector1", "msft", "microsoft"])
    except Exception:
        pass  # Fail gracefully if MX discovery hits a hitch

    return list(dynamic_selectors)


import base64

def _is_valid_base64(val: str) -> bool:
    """Validate that val contains valid base64-encoded data per RFC 4648."""
    normalized = "".join(val.split())
    if not normalized:
        return False
    missing_padding = (4 - len(normalized) % 4) % 4
    if missing_padding:
        normalized += "=" * missing_padding
    try:
        decoded = base64.b64decode(normalized, validate=True)
        return len(decoded) > 0
    except Exception:
        return False


def _parse_dkim_record(record: str) -> Tuple[str, Dict[str, str]]:
    """
    Parse a TXT record for DKIM tags per RFC 6376:
    https://datatracker.ietf.org/doc/html/rfc6376

    Returns (status, tags) where status is one of:
    - 'active': v=DKIM1 (or omitted v) with valid base64 p= key
    - 'revoked': v=DKIM1 (or omitted v) with empty p= key
    - 'malformed': invalid syntax, unsupported version, duplicate tags, v not first tag, or invalid public key
    - 'not_dkim': unrelated TXT record
    """
    parts = [p.strip() for p in record.split(";") if p.strip()]
    if not parts:
        return "not_dkim", {}

    # RFC 6376 §3.2 & §3.6.1: Tag names are strictly alpha-num sequences without
    # internal or surrounding whitespace before the '='.
    # Check if this record is attempting to be a DKIM key record.
    has_dkim_indicator = False
    for part in parts:
        if "=" in part:
            raw_k, _ = part.split("=", 1)
            stripped_k = raw_k.strip()
            if stripped_k in ("v", "p"):
                has_dkim_indicator = True
                break

    if not has_dkim_indicator:
        return "not_dkim", {}

    tags: Dict[str, str] = {}
    first_tag: str | None = None

    for part in parts:
        if "=" not in part:
            return "malformed", tags

        raw_k, raw_v = part.split("=", 1)

        # RFC 6376 §3.2: Tag names are strictly defined as alpha-num sequences
        # without internal or surrounding whitespace. A space before '=' is invalid.
        if not raw_k.isalnum():
            return "malformed", tags

        tag_name = raw_k  # Case-sensitive tag name
        tag_value = raw_v.strip()

        if first_tag is None:
            first_tag = tag_name

        # Duplicate tags invalidate the entire tag list per RFC 6376 §3.2
        if tag_name in tags:
            return "malformed", tags

        tags[tag_name] = tag_value

    # RFC 6376 §3.6.1: If 'v=' tag is present, it MUST be the first tag in the record
    # and MUST be exactly 'DKIM1' (case-sensitive).
    if "v" in tags:
        if first_tag != "v":
            return "malformed", tags
        if tags["v"] != "DKIM1":
            return "malformed", tags

    # RFC 6376 §3.6.1: 'v' tag is optional (defaults to DKIM1).
    # 'p' tag is REQUIRED in a DKIM key record.
    if "p" not in tags:
        return "malformed", tags

    p_val = tags["p"]
    if not p_val:
        # Empty p= value indicates a revoked key per RFC 6376 §3.6.1
        return "revoked", tags

    if _is_valid_base64(p_val):
        return "active", tags

    return "malformed", tags


def _is_spf_record(record: str) -> bool:
    """RFC 7208 §4.1: Record must begin with lowercase 'v=spf1' as its first whitespace-delimited token."""
    tokens = record.strip().split()
    return len(tokens) > 0 and tokens[0] == "v=spf1"


def _spf_policy(record: str) -> str:
    """
    Tokenize SPF record and evaluate mechanisms sequentially left-to-right per RFC 7208 Section 4.6.2.
    Returns:
    - 'fail' for -all
    - 'softfail' for ~all
    - 'neutral' for ?all
    - 'pass' for +all or bare all
    - 'redirect' if record contains a redirect= modifier without an all mechanism
    - 'missing' if record starts with v=spf1 but contains no 'all' or 'redirect' mechanism
    - 'unknown' for invalid/unparseable records
    """
    tokens = record.strip().split()
    if not tokens or tokens[0] != "v=spf1":
        return "unknown"

    has_redirect = False
    for token in tokens[1:]:
        t_lower = token.lower()
        if t_lower in ("-all", "~all", "?all", "+all", "all"):
            if t_lower == "-all":
                return "fail"
            if t_lower == "~all":
                return "softfail"
            if t_lower == "?all":
                return "neutral"
            if t_lower in ("+all", "all"):
                return "pass"
        elif t_lower.startswith("redirect="):
            has_redirect = True

    if has_redirect:
        return "redirect"
    return "missing"


def _check_spf(domain: str, recommendations: List[str]) -> Dict[str, Any]:
    txt_records, failed = _query_txt(domain)

    if failed:
        recommendations.append("Could not verify SPF — DNS lookup timed out.")
        return {"found": False, "valid": False, "record": None, "records": [], "policy": None, "score": 0}

    spf_records = [r for r in txt_records if _is_spf_record(r)]

    if not spf_records:
        recommendations.append("SPF not found — add an SPF record.")
        return {"found": False, "valid": False, "record": None, "records": [], "policy": None, "score": 0}

    if len(spf_records) > 1:
        recommendations.append(
            "Multiple SPF records found — SPF configuration is invalid. Consolidate the SPF mechanisms into a single SPF record."
        )
        return {
            "found": True,
            "valid": False,
            "record": None,
            "records": spf_records,
            "policy": None,
            "score": 0,
        }

    record = spf_records[0]
    policy = _spf_policy(record)

    spf_score = 30
    if policy == "softfail":
        spf_score = 20
        recommendations.append("SPF uses softfail (~all) — consider a hard fail (-all) for stronger protection")
    elif policy in ("neutral", "pass"):
        spf_score = 10
        if policy == "pass":
            recommendations.append("SPF policy is 'pass' (+all) — provides little protection.")
        else:
            recommendations.append(f"SPF policy is '{policy}' — provides little protection.")
    elif policy == "redirect":
        spf_score = 25
        recommendations.append("SPF uses redirect modifier — SPF policy is delegated to the target domain.")
    elif policy == "missing":
        spf_score = 5
        recommendations.append("SPF record has no terminating 'all' mechanism — default policy is undefined.")
    elif policy == "unknown":
        spf_score = 0
        recommendations.append("SPF record has an unrecognized or invalid 'all' mechanism.")

    return {
        "found": True,
        "valid": policy != "unknown",
        "record": record,
        "records": spf_records,
        "policy": policy,
        "score": spf_score,
    }


def _is_dmarc_record(record: str) -> bool:
    """RFC 7489 / RFC 9989: First tag MUST be v=DMARC1 (case-sensitive tag and value)."""
    parts = [p.strip() for p in record.split(";") if p.strip()]
    if not parts:
        return False
    first_part = parts[0]
    if "=" not in first_part:
        return False
    raw_k, raw_v = first_part.split("=", 1)
    return raw_k == "v" and raw_v.strip() == "DMARC1"


def _check_dmarc(domain: str, recommendations: List[str]) -> Dict[str, Any]:
    txt_records, failed = _query_txt(f"_dmarc.{domain}")

    if failed:
        recommendations.append("Could not verify DMARC — DNS lookup timed out.")
        return {"found": False, "valid": False, "record": None, "records": [], "policy": None, "score": 0}

    dmarc_records = [r for r in txt_records if _is_dmarc_record(r)]

    if not dmarc_records:
        recommendations.append("DMARC not found — add a DMARC record.")
        return {"found": False, "valid": False, "record": None, "records": [], "policy": None, "score": 0}

    if len(dmarc_records) > 1:
        recommendations.append(
            "Multiple DMARC records found — DMARC configuration is ambiguous. Publish a single DMARC policy record."
        )
        return {
            "found": True,
            "valid": False,
            "record": None,
            "records": dmarc_records,
            "policy": None,
            "score": 0,
        }

    record = dmarc_records[0]
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    raw_policy = tags.get("p")
    valid = True
    if raw_policy is None:
        policy = "none"
        recommendations.append(
            "DMARC record is missing the 'p=' tag. While the new RFC 9989 standard defaults "
            "this to 'none', legacy mail systems may ignore this record entirely."
        )
    else:
        policy_lower = raw_policy.lower()
        if policy_lower in ("reject", "quarantine", "none"):
            policy = policy_lower
        else:
            policy = "invalid"
            valid = False
            recommendations.append(
                f"DMARC policy 'p={raw_policy}' is invalid — must be 'none', 'quarantine', or 'reject'."
            )

    dmarc_score = 10
    if policy == "reject":
        dmarc_score = 35
    elif policy == "quarantine":
        dmarc_score = 25
        recommendations.append("DMARC policy is 'quarantine' — failing mail goes to spam.")

    if "rua" not in tags:
        dmarc_score = max(0, dmarc_score - 5)
        recommendations.append("DMARC has no rua= reporting address.")
    elif not tags["rua"]:
        dmarc_score = max(0, dmarc_score - 5)
        recommendations.append("DMARC has an empty rua= tag with no reporting address.")

    return {
        "found": True,
        "valid": valid,
        "record": record,
        "records": dmarc_records,
        "policy": policy,
        "score": dmarc_score,
    }


def _check_dkim(domain: str, recommendations: List[str]) -> Dict[str, Any]:
    # Combine baseline guesses with dynamically generated infrastructure keys
    dynamic_keys = _discover_dynamic_selectors(domain)
    selectors_to_check = list(set(BASE_DKIM_SELECTORS + dynamic_keys))

    def check_selector(selector: str) -> Tuple[str, str | None]:
        records, _failed = _query_txt(f"{selector}._domainkey.{domain}")
        found_status = None
        for r in records:
            status, _tags = _parse_dkim_record(r)
            if status == "active":
                return selector, "active"
            elif status == "revoked":
                found_status = "revoked"
            elif status == "malformed" and found_status != "revoked":
                found_status = "malformed"
        return selector, found_status

    # Threading prevents the added dynamic keys from slowing down execution time
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(selectors_to_check)) as executor:
        results = executor.map(check_selector, selectors_to_check)
        results_list = list(results)
        found_selectors = [s for s, status in results_list if status == "active"]
        revoked_selectors = [s for s, status in results_list if status == "revoked"]
        malformed_selectors = [s for s, status in results_list if status == "malformed"]

    found = len(found_selectors) > 0
    dkim_score = 35 if found else 0

    if not found:
        if revoked_selectors:
            recommendations.append(
                f"DKIM key(s) revoked for selector(s): {', '.join(revoked_selectors)} — configure an active public key."
            )
        elif malformed_selectors:
            recommendations.append(
                f"DKIM record(s) malformed for selector(s): {', '.join(malformed_selectors)} — verify DKIM syntax and public key configuration."
            )
        else:
            recommendations.append("DKIM not found — add DKIM record to prevent spoofing")

    return {
        "found": found,
        "selectors_checked": selectors_to_check,
        "found_selectors": found_selectors,
        "revoked_selectors": revoked_selectors,
        "malformed_selectors": malformed_selectors,
        "score": dkim_score,
    }


def email_security_check(domain: str) -> dict:
    """
    Check SPF, DKIM, and DMARC DNS records for a domain to assess
    basic email anti-spoofing configuration.

    DKIM detection is best-effort here. It checks a fixed list of common
    selectors used by major email providers, since DKIM selectors
    cannot be discovered via DNS without already knowing them.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    try:
        recommendations: List[str] = []

        spf = _check_spf(domain, recommendations)
        dmarc = _check_dmarc(domain, recommendations)
        dkim = _check_dkim(domain, recommendations)

        raw_score = spf.pop("score") + dmarc.pop("score") + dkim.pop("score")

        if raw_score >= 90:
            rating = "Excellent"
        elif raw_score >= 70:
            rating = "Good"
        elif raw_score >= 40:
            rating = "Fair"
        else:
            rating = "Critical"

        return {
            "success": True,
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "security_score": f"{raw_score}%",
            "rating": rating,
            "recommendations": recommendations,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}