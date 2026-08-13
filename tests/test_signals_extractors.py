"""Tests for the per-tool signal extractors in tools/signals/.

These tests pin down the contract that each extractor mutates the shared
`signals` dict in the way the threat-analysis prompt expects. They are
especially important for the ip_abuse_score signal, which was silently
always 0 between PR #84 and the fix that moved the assignment into
ip_reputation_extractor (the AbuseIPDB-backed canonical source).
"""
from unittest.mock import patch

from tools.headers_tool import headers_analyzer
from tools.signals.asn import asn_extractor
from tools.signals.ip_reputation import ip_reputation_extractor
from tools.signals.tech_stack import techstack_extractor
from tools.signals.extractor import extract_signals
from tools.signals.registry import TOOL_REGISTRY


def _base_signals():
    """Return a fresh signals dict matching extract_signals' initial shape."""
    return {
        "domain_expiry_days": None,
        "dns_missing_records": [],
        "open_ports": [],
        "ssl_days_remaining": None,
        "software_detected": [],
        "ip_abuse_score": 0,
        "subdomain_count": 0,
        "missing_security_headers": [],
        "email_security": {},
        "ip_reputation_flagged": False,
        "asn_number": None,
        "asn_org": None,
        "asn_ip": None,
        "asn_country": None,
        "auto_warnings": [],
    }


# ── ip_reputation_extractor ──────────────────────────────────────────────

def test_ip_reputation_extractor_populates_abuse_score():
    """ip_reputation_extractor must assign abuse_confidence_score to ip_abuse_score.

    Regression test for the bug introduced by PR #84: the signal was
    never assigned here, so it stayed at the initial value of 0 regardless
    of the real AbuseIPDB confidence score.
    """
    result = {
        "success": True,
        "is_malicious": False,
        "abuse_confidence_score": 87,
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 87
    assert signals["ip_reputation_flagged"] is False


def test_ip_reputation_extractor_coerces_string_score_to_int():
    """abuse_confidence_score may arrive as a string; the extractor must coerce."""
    result = {
        "success": True,
        "is_malicious": False,
        "abuse_confidence_score": "42",
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 42


def test_ip_reputation_extractor_defaults_score_to_zero_on_invalid_value():
    """A non-numeric abuse_confidence_score must fall back to 0."""
    result = {
        "success": True,
        "is_malicious": False,
        "abuse_confidence_score": "not-a-number",
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 0


def test_ip_reputation_extractor_defaults_score_to_zero_when_key_missing():
    """A missing abuse_confidence_score key must fall back to 0.

    AbuseIPDB responses normally include the field, but defensive coding
    requires the extractor to tolerate its absence (int(None) raises
    TypeError, which the try/except catches).
    """
    result = {
        "success": True,
        "is_malicious": False,
        # abuse_confidence_score intentionally omitted
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 0


def test_ip_reputation_extractor_skips_on_unsuccessful_result():
    """An unsuccessful ip_reputation result must not touch the signals dict."""
    result = {"success": False, "error": "AbuseIPDB API request failed"}
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    # ip_abuse_score stays at its initial value
    assert signals["ip_abuse_score"] == 0
    assert signals["ip_reputation_flagged"] is False
    assert signals["auto_warnings"] == []


def test_ip_reputation_extractor_flags_malicious_warning():
    """When is_malicious is True, a MALICIOUS warning must be appended."""
    result = {
        "success": True,
        "is_malicious": True,
        "abuse_confidence_score": 95,
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 95
    assert signals["ip_reputation_flagged"] is True
    assert any("MALICIOUS" in w for w in signals["auto_warnings"])


def test_ip_reputation_extractor_elevated_warning_above_20():
    """When not flagged but score > 20, an elevated-risk warning must fire."""
    result = {
        "success": True,
        "is_malicious": False,
        "abuse_confidence_score": 35,
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert any("elevated risk" in w for w in signals["auto_warnings"])


# ── asn_extractor ────────────────────────────────────────────────────────

def test_asn_extractor_does_not_touch_ip_abuse_score():
    """asn_extractor must NOT zero out ip_abuse_score.

    The asn_tool result does not carry an abuse score. The previous
    implementation looked up `abuse_score` (which never existed) and fell
    back to 0, silently overwriting any value that had been or would be
    set by ip_reputation_extractor. This test locks in the fix: asn_extractor
    leaves ip_abuse_score untouched.
    """
    result = {
        "success": True,
        "ip": "1.2.3.4",
        "asn": "AS64500",
        "org": "Test Org",
        "country": "Testland",
    }
    signals = _base_signals()
    signals["ip_abuse_score"] = 73  # pretend ip_reputation already ran
    asn_extractor(result, signals)
    assert signals["ip_abuse_score"] == 73  # unchanged


def test_asn_extractor_skips_on_unsuccessful_result():
    """An unsuccessful asn result must not touch the signals dict."""
    result = {"success": False, "error": "Failed to resolve domain"}
    signals = _base_signals()
    asn_extractor(result, signals)
    assert signals["ip_abuse_score"] == 0
    assert signals["auto_warnings"] == []


# ── extract_signals integration ──────────────────────────────────────────

def test_extract_signals_populates_ip_abuse_score_from_ip_reputation():
    """End-to-end: extract_signals must populate ip_abuse_score from the
    ip_reputation tool result, not from the asn tool result.

    This is the integration test that would have caught the original PR #84
    regression: asn runs in Wave 1, ip_reputation runs in Wave 3, and the
    extractor order follows the registry. Even though asn_extractor runs
    first, the final ip_abuse_score value must come from ip_reputation.
    """
    results = {
        "whois": {"success": False},
        "dns": {"success": False},
        "ssl": {"success": False},
        "email_security": {"success": False},
        "asn": {
            "success": True,
            "ip": "1.2.3.4",
            "asn": "AS64500",
            "org": "Test Org",
            "country": "Testland",
        },
        "ports": {"success": False},
        "techstack": {"success": False},
        "headers": {"success": False},
        "ct_logs": {"success": False},
        "ip_reputation": {
            "success": True,
            "is_malicious": False,
            "abuse_confidence_score": 88,
        },
    }
    signals = extract_signals(results)
    assert signals["ip_abuse_score"] == 88
    assert signals["ip_reputation_flagged"] is False


def test_extract_signals_leaves_ip_abuse_score_at_zero_when_ip_reputation_missing():
    """When ip_reputation did not run or failed, ip_abuse_score stays at 0."""
    results = {
        "whois": {"success": False},
        "dns": {"success": False},
        "ssl": {"success": False},
        "email_security": {"success": False},
        "asn": {
            "success": True,
            "ip": "1.2.3.4",
            "asn": "AS64500",
            "org": "Test Org",
        },
        "ports": {"success": False},
        "techstack": {"success": False},
        "headers": {"success": False},
        "ct_logs": {"success": False},
        "ip_reputation": {"success": False, "error": "API down"},
    }
    signals = extract_signals(results)
    assert signals["ip_abuse_score"] == 0


def test_asn_extractor_populates_metadata_signals():
    """Successful ASN lookups must populate asn_* signal fields."""
    result = {
        "success": True,
        "ip": "1.2.3.4",
        "asn": "AS64500",
        "organization": "Example Networks",
        "country": "US",
    }
    signals = _base_signals()
    asn_extractor(result, signals)
    assert signals["asn_number"] == "AS64500"
    assert signals["asn_org"] == "Example Networks"
    assert signals["asn_ip"] == "1.2.3.4"
    assert signals["asn_country"] == "US"
    assert signals["ip_abuse_score"] == 0

def test_asn_extractor_skips_metadata_on_failure():
    """Failed ASN lookups leave asn_* fields unset."""
    result = {"success": False, "error": "Failed to resolve domain"}
    signals = _base_signals()
    asn_extractor(result, signals)
    assert signals["asn_number"] is None
    assert signals["asn_org"] is None
    assert signals["asn_ip"] is None
    assert signals["asn_country"] is None


# ── techstack_extractor ──────────────────────────────────────────────────

def test_techstack_extractor_flattens_list_valued_technologies():
    """List-valued technology entries must be flattened into individual names."""
    result = {
        "success": True,
        "status_code": 200,
        "technologies": {
            "web_server": "nginx",
            "cms": ["WordPress"],
            "analytics": ["Google Analytics"],
            "javascript_frameworks": ["React", "Vue.js"],
        },
    }
    signals = _base_signals()
    techstack_extractor(result, signals)

    prompt_line = f"Software detected  : {', '.join(signals['software_detected'])}"
    assert prompt_line == (
        "Software detected  : nginx, WordPress, Google Analytics, React, Vue.js"
    )
    assert "['WordPress']" not in prompt_line
    assert '"React"' not in prompt_line


def test_techstack_extractor_skips_empty_and_none_technologies():
    """Empty lists, None, 'Unknown' and 'None' values must not add entries."""
    result = {
        "success": True,
        "status_code": 200,
        "technologies": {
            "web_server": "nginx",
            "cms": [],
            "analytics": None,
            "powered_by": "Unknown",
            "javascript_frameworks": ["React", None, "", "Unknown"],
        },
    }
    signals = _base_signals()
    techstack_extractor(result, signals)

    assert signals["software_detected"] == ["nginx", "React"]



# ── headers_extractor ────────────────────────────────────────────────────

_RAW_HEADERS_ALL_PRESENT = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=()",
}


def _registry_entry(name):
    """Return the TOOL_REGISTRY entry called `name`, asserting it exists."""
    entry = next((t for t in TOOL_REGISTRY if t.get("name") == name), None)
    assert entry is not None, (
        f"no {name!r} entry in TOOL_REGISTRY — registered tools: "
        f"{[t.get('name') for t in TOOL_REGISTRY]}"
    )
    return entry


def _headers_result(raw_headers, status_code=200):
    """Run the real headers_analyzer over one canned HTTP response."""
    hop = {
        "url": "https://example.com/",
        "status_code": status_code,
        "headers": dict(raw_headers),
        "body": "",
    }
    with patch("tools.headers_tool._walk_redirect_chain", return_value=[hop]):
        return headers_analyzer("example.com")


def _raw_headers_without(*omitted):
    """The fully hardened header set minus the named headers."""
    dropped = {h.lower() for h in omitted}
    return {k: v for k, v in _RAW_HEADERS_ALL_PRESENT.items() if k.lower() not in dropped}


def _registry_results(**overrides):
    """A full_recon-shaped results dict: every registered tool failed,
    except the ones overridden here."""
    results = {t["name"]: {"success": False, "error": "not run in this test"}
               for t in TOOL_REGISTRY}
    results.update(overrides)
    return results


def test_headers_analyzer_is_registered_for_full_recon():
    """full_recon can only collect security headers if headers_analyzer is
    in the signal registry with an extractor."""
    entry = _registry_entry("headers")
    assert entry["fn"] is headers_analyzer
    assert callable(entry.get("extractor")), "headers entry has no extractor"
    assert entry["args"]("example.com", {}) == ("example.com",)
    assert entry["wave"] == 2


def test_extract_signals_populates_missing_headers_from_headers_analyzer():
    """The signal must carry exactly the headers headers_analyzer reports absent."""
    results = _registry_results(
        headers=_headers_result(
            _raw_headers_without("Content-Security-Policy", "X-Frame-Options")
        )
    )
    signals = extract_signals(results)

    assert signals["missing_security_headers"] == [
        "content-security-policy",
        "x-frame-options",
    ]


def test_extract_signals_reports_no_missing_headers_when_all_present():
    """A fully hardened site must not be reported as missing headers."""
    results = _registry_results(headers=_headers_result(_RAW_HEADERS_ALL_PRESENT))
    signals = extract_signals(results)

    assert signals["missing_security_headers"] == []


def test_extract_signals_ignores_headers_from_a_4xx_final_hop():
    """A 4xx response is an error page, not the site, so its absent headers
    must not become a finding or a warning."""
    results = _registry_results(headers=_headers_result({}, status_code=403))
    signals = extract_signals(results)

    assert signals["missing_security_headers"] == []
    assert signals["auto_warnings"] == []


def test_extract_signals_ignores_headers_from_a_5xx_final_hop():
    """A 5xx response never reached page content, so its absent headers must
    not become a finding or a warning."""
    results = _registry_results(headers=_headers_result({}, status_code=503))
    signals = extract_signals(results)

    assert signals["missing_security_headers"] == []
    assert signals["auto_warnings"] == []


def test_techstack_success_does_not_clear_the_headers_signal():
    """A successful techstack run must leave headers_analyzer's signal intact."""
    results = _registry_results(
        headers=_headers_result(_raw_headers_without("Content-Security-Policy")),
        techstack={
            "success": True,
            "domain": "example.com",
            "url": "https://example.com",
            "status_code": 200,
            "technologies": {"web_server": "nginx"},
        },
    )
    signals = extract_signals(results)

    assert signals["missing_security_headers"] == ["content-security-policy"]
    assert signals["software_detected"] == ["nginx"]


def test_headers_extractor_ignores_failed_runs():
    """A failed headers_analyzer run must leave the signal at its default,
    so the prompt's 'Insufficient data' rule can still apply."""
    extractor = _registry_entry("headers")["extractor"]
    signals = _base_signals()
    extractor({"success": False, "error": "Connection failed"}, signals)

    assert signals["missing_security_headers"] == []
    assert signals["auto_warnings"] == []


def test_headers_extractor_ignores_malformed_results():
    """A success without a usable headers analysis must not crash or invent data."""
    extractor = _registry_entry("headers")["extractor"]
    signals = _base_signals()
    extractor({"success": True, "domain": "example.com"}, signals)

    assert signals["missing_security_headers"] == []
    assert signals["auto_warnings"] == []


def test_headers_extractor_warns_hard_on_four_or_more_missing():
    """Four or more absent headers is the 'significant hardening gap' tier."""
    extractor = _registry_entry("headers")["extractor"]
    signals = _base_signals()
    extractor(
        _headers_result(
            _raw_headers_without(
                "Content-Security-Policy",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            )
        ),
        signals,
    )

    assert len(signals["missing_security_headers"]) == 4
    assert len(signals["auto_warnings"]) == 1
    assert "4 security headers missing" in signals["auto_warnings"][0]
    assert "significant hardening gap" in signals["auto_warnings"][0]


def test_headers_extractor_warns_softly_on_two_missing():
    """Two or three absent headers is the plain-listing tier."""
    extractor = _registry_entry("headers")["extractor"]
    signals = _base_signals()
    extractor(
        _headers_result(_raw_headers_without("Content-Security-Policy", "Referrer-Policy")),
        signals,
    )

    assert len(signals["auto_warnings"]) == 1
    assert signals["auto_warnings"][0] == (
        "2 security headers missing: content-security-policy, referrer-policy"
    )


def test_headers_extractor_does_not_warn_on_a_single_missing_header():
    """One absent header is reported in the signal but is not a warning."""
    extractor = _registry_entry("headers")["extractor"]
    signals = _base_signals()
    extractor(_headers_result(_raw_headers_without("Permissions-Policy")), signals)

    assert signals["missing_security_headers"] == ["permissions-policy"]
    assert signals["auto_warnings"] == []


def test_techstack_extractor_does_not_touch_the_headers_signal():
    """tech_stack_detect no longer returns security_headers, so its
    extractor must not write missing_security_headers at all — whatever
    order the registry runs the extractors in."""
    signals = _base_signals()
    signals["missing_security_headers"] = ["content-security-policy"]
    techstack_extractor(
        {
            "success": True,
            "domain": "example.com",
            "url": "https://example.com",
            "status_code": 200,
            "technologies": {"web_server": "nginx"},
        },
        signals,
    )

    assert signals["missing_security_headers"] == ["content-security-policy"]
    assert signals["auto_warnings"] == []
