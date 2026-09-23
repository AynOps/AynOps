from __future__ import annotations

import base64
import concurrent.futures
import datetime
import re
from typing import Any

import dns.exception
import dns.resolver

from utils import is_valid_domain, normalize_domain

# Base generic defaults
BASE_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "dkim",
    "mail",
    "smtp",
    "s1",
    "s2",
    "mandrill",
    "mxvault",
    "zoho",
    "amazonses",
]

# RFC 6376 §3.2: a DKIM tag name starts with a letter followed by
# letters, digits, or underscores (extension tags such as "x_foo"
# are valid). Tag names are case-sensitive and may not contain
# whitespace. Reference: https://datatracker.ietf.org/doc/html/rfc6376
_DKIM_TAG_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")

# RFC 7208 §4.6.2: the "all" mechanism always matches and ends evaluation.
# A bare "all" is equivalent to "+all".
_SPF_ALL_POLICIES = {
    "-all": "fail",
    "~all": "softfail",
    "?all": "neutral",
    "+all": "pass",
    "all": "pass",
}


def _query_txt(name: str) -> tuple[list[str], bool]:
    """Return (txt_record_strings, resolution_failed) for a DNS name."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0

    try:
        answers = resolver.resolve(name, "TXT")
        records = [
            b"".join(r.strings).decode("utf-8", errors="replace") for r in answers
        ]
        return records, False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], False
    except (dns.resolver.Timeout, dns.exception.DNSException):
        try:
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
            answers = resolver.resolve(name, "TXT")
            records = [
                b"".join(r.strings).decode("utf-8", errors="replace") for r in answers
            ]
            return records, False
        except Exception:
            return [], True
    except Exception:
        return [], True


def _discover_dynamic_selectors(domain: str) -> list[str]:
    """
    Inspects MX records to append smart infrastructure-specific selectors.
    For example, if a domain uses Google Workspace, it adds specific internal
    Google infrastructure selectors.
    """
    dynamic_selectors = set()

    # 1. Inject temporal/historical pattern-matching common in enterprise setups (e.g., 2023, 2024, 2025, 2026)
    current_year = datetime.datetime.now(datetime.UTC).year
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
    except Exception:  # noqa: S110 - MX-derived selector hints are best-effort; failure is non-fatal
        pass  # Fail gracefully if MX discovery hits a hitch

    return list(dynamic_selectors)


def _is_valid_base64_key(value: str) -> bool:
    """
    Return whether a DKIM p= value is plausible base64-encoded public-key
    data (RFC 4648). Whitespace is ignored; missing padding is restored.
    A full cryptographic key parse is intentionally out of scope.
    """
    compact = "".join(value.split())
    if not compact:
        return False
    compact += "=" * (-len(compact) % 4)
    try:
        decoded = base64.b64decode(compact, validate=True)
    except ValueError:
        return False
    return len(decoded) > 0


def _parse_dkim_record(record: str) -> tuple[str, dict[str, str]]:
    """
    Classify a TXT record fetched from <selector>._domainkey.<domain>.

    Tag-aware parsing per RFC 6376 (https://datatracker.ietf.org/doc/html/rfc6376):
      - tag names are case-sensitive and must match [A-Za-z][A-Za-z0-9_]*
      - duplicate tag names invalidate the record
      - v= is optional but, when present, MUST be the first tag and MUST be
        exactly "DKIM1"
      - p= (the public key) is required

    Returns (status, tags) where status is one of:
      - "active":    well-formed record with a non-empty base64 p= key
      - "revoked":   well-formed record whose p= tag is present but empty
      - "malformed": a DKIM-intended record that fails the rules above
      - "not_dkim":  a TXT record that does not attempt DKIM (no p= tag and
        no v= tag advertising a DKIM version)
    """
    parts = [part.strip() for part in record.split(";") if part.strip()]
    if not parts:
        return "not_dkim", {}

    # Only treat the record as a DKIM attempt when it carries a recognizable
    # DKIM signal — a p= tag, or a v= tag advertising a DKIM version.
    # Anything else is an unrelated TXT record.
    has_dkim_indicator = False
    for part in parts:
        name, _, value = part.partition("=")
        if name.strip() == "p" or (
            name.strip() == "v" and value.strip().lower().startswith("dkim")
        ):
            has_dkim_indicator = True
            break
    if not has_dkim_indicator:
        return "not_dkim", {}

    tags: dict[str, str] = {}
    first_tag: str | None = None
    for part in parts:
        if "=" not in part:
            return "malformed", tags
        name, value = part.split("=", 1)
        # A tag name must be an exact match — whitespace such as "v = DKIM1"
        # or a miscased "P=" does not produce a valid tag.
        if not _DKIM_TAG_NAME.fullmatch(name):
            return "malformed", tags
        if name in tags:
            return "malformed", tags
        if first_tag is None:
            first_tag = name
        tags[name] = value.strip()

    if "v" in tags and (first_tag != "v" or tags["v"] != "DKIM1"):
        return "malformed", tags

    if "p" not in tags:
        return "malformed", tags
    if not tags["p"]:
        return "revoked", tags
    if not _is_valid_base64_key(tags["p"]):
        return "malformed", tags
    return "active", tags


def _is_spf_record(record: str) -> bool:
    """
    RFC 7208 §4.5: an SPF record begins with a version section of exactly
    "v=spf1", terminated by whitespace or the end of the record. Records
    like "V=SPF1 ..." or "v=spf1foo" are not SPF records and are discarded.
    """
    tokens = record.strip().split()
    return bool(tokens) and tokens[0] == "v=spf1"


def _spf_policy(record: str) -> str:
    """
    Return the policy implied by the record's "all" mechanism.

    Mechanisms are evaluated left to right per RFC 7208 §4.6.2 — the first
    "all" mechanism reached always matches, so later tokens are ignored.
    Qualifiers map to: "-all" fail, "~all" softfail, "?all" neutral,
    "+all"/bare "all" pass.

    Returns "redirect" when no "all" exists but a redirect= modifier
    delegates the policy (RFC 7208 §6.1), "missing" when neither is
    present, and "unknown" when the record is not a valid SPF record.
    """
    tokens = record.strip().split()
    if not tokens or tokens[0] != "v=spf1":
        return "unknown"

    has_redirect = False
    for token in tokens[1:]:
        lowered = token.lower()
        if lowered in _SPF_ALL_POLICIES:
            return _SPF_ALL_POLICIES[lowered]
        if lowered.startswith("redirect="):
            has_redirect = True

    return "redirect" if has_redirect else "missing"


def _check_spf(domain: str, recommendations: list[str]) -> dict[str, Any]:
    txt_records, failed = _query_txt(domain)

    if failed:
        recommendations.append("Could not verify SPF — DNS lookup timed out.")
        return {
            "found": False,
            "valid": False,
            "record": None,
            "records": [],
            "policy": None,
            "score": 0,
        }

    spf_records = [r for r in txt_records if _is_spf_record(r)]

    if not spf_records:
        recommendations.append("SPF not found — add an SPF record.")
        return {
            "found": False,
            "valid": False,
            "record": None,
            "records": [],
            "policy": None,
            "score": 0,
        }

    # RFC 7208 §4.5: a domain MUST NOT publish more than one SPF record.
    # Report all candidates instead of silently using the first one.
    if len(spf_records) > 1:
        recommendations.append(
            "Multiple SPF records found — SPF configuration is invalid. "
            "Consolidate the SPF mechanisms into a single SPF record."
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
        recommendations.append(
            "SPF uses softfail (~all) — consider a hard fail (-all) for stronger protection"
        )
    elif policy in ("neutral", "pass"):
        spf_score = 10
        if policy == "pass":
            recommendations.append(
                "SPF policy is 'pass' (+all) — any server can send mail for this domain."
            )
        else:
            recommendations.append(
                "SPF policy is 'neutral' (?all) — provides little protection."
            )
    elif policy == "redirect":
        spf_score = 25
        recommendations.append(
            "SPF uses a redirect modifier — policy enforcement is delegated to the target domain."
        )
    elif policy == "missing":
        spf_score = 5
        recommendations.append(
            "SPF record has no 'all' mechanism — the default policy for unmatched senders is undefined."
        )
    elif policy == "unknown":
        spf_score = 0
        recommendations.append(
            "SPF record could not be parsed — verify the record syntax."
        )

    return {
        "found": True,
        "valid": policy != "unknown",
        "record": record,
        "records": spf_records,
        "policy": policy,
        "score": spf_score,
    }


def _is_dmarc_record(record: str) -> bool:
    """
    RFC 7489 §6.3 / RFC 9989: a DMARC policy record must begin with a
    v=DMARC1 tag as its first tag.
    """
    parts = [part.strip() for part in record.split(";") if part.strip()]
    if not parts or "=" not in parts[0]:
        return False
    name, value = parts[0].split("=", 1)
    return name == "v" and value.strip() == "DMARC1"


def _check_dmarc(domain: str, recommendations: list[str]) -> dict[str, Any]:
    txt_records, failed = _query_txt(f"_dmarc.{domain}")

    if failed:
        recommendations.append("Could not verify DMARC — DNS lookup timed out.")
        return {
            "found": False,
            "valid": False,
            "record": None,
            "records": [],
            "policy": None,
            "score": 0,
        }

    dmarc_records = [r for r in txt_records if _is_dmarc_record(r)]

    if not dmarc_records:
        recommendations.append("DMARC not found — add a DMARC record.")
        return {
            "found": False,
            "valid": False,
            "record": None,
            "records": [],
            "policy": None,
            "score": 0,
        }

    # Only one DMARC policy record may exist per domain — preserve all of
    # them rather than arbitrarily evaluating the first.
    if len(dmarc_records) > 1:
        recommendations.append(
            "Multiple DMARC records found — DMARC configuration is ambiguous. "
            "Publish a single DMARC policy record."
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

    valid = True
    raw_policy = tags.get("p")
    if raw_policy is None:
        # RFC 9989 §4.7: a record without p= is treated as p=none.
        policy = "none"
        recommendations.append(
            "DMARC record has no 'p=' tag — it defaults to 'none' under RFC 9989, "
            "but explicitly publishing a policy avoids ambiguous handling."
        )
    else:
        policy = raw_policy.lower()
        if policy not in ("none", "quarantine", "reject"):
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
        recommendations.append(
            "DMARC policy is 'quarantine' — failing mail goes to spam."
        )

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


def _check_dkim(domain: str, recommendations: list[str]) -> dict[str, Any]:
    # Combine baseline guesses with dynamically generated infrastructure keys
    dynamic_keys = _discover_dynamic_selectors(domain)
    selectors_to_check = sorted(set(BASE_DKIM_SELECTORS + dynamic_keys))

    def check_selector(selector: str) -> tuple[str, str | None]:
        records, _failed = _query_txt(f"{selector}._domainkey.{domain}")
        status_seen = None
        for r in records:
            status, _tags = _parse_dkim_record(r)
            if status == "active":
                return selector, "active"
            if status == "revoked":
                status_seen = "revoked"
            elif status == "malformed" and status_seen != "revoked":
                status_seen = "malformed"
        return selector, status_seen

    # Threading prevents the added dynamic keys from slowing down execution time
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(selectors_to_check)
    ) as executor:
        results = list(executor.map(check_selector, selectors_to_check))

    found_selectors = [s for s, status in results if status == "active"]
    revoked_selectors = [s for s, status in results if status == "revoked"]
    malformed_selectors = [s for s, status in results if status == "malformed"]

    found = len(found_selectors) > 0
    dkim_score = 35 if found else 0

    if not found:
        if revoked_selectors:
            recommendations.append(
                f"DKIM key(s) revoked for selector(s): {', '.join(revoked_selectors)} — publish an active public key."
            )
        if malformed_selectors:
            recommendations.append(
                f"DKIM record(s) malformed for selector(s): {', '.join(malformed_selectors)} — check record syntax and key data."
            )
        if not revoked_selectors and not malformed_selectors:
            # Selector guessing is best-effort — absence here is not proof
            # that DKIM is unconfigured.
            recommendations.append(
                "No DKIM record found for common selectors — DKIM may still be "
                "configured under a selector that was not checked."
            )

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
        recommendations: list[str] = []

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
