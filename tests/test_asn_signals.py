"""Regression tests for ASN signal extraction."""

from tools.signals.asn import asn_extractor
from tools.signals.extractor import extract_signals
from tools.signals.registry import TOOL_REGISTRY


def test_asn_extractor_populates_asn_signals():
    signals = {"asn_number": None, "asn_isp": None, "ip_abuse_score": 73}
    result = {
        "success": True,
        "asn": "AS64500",
        "isp": "Example ISP",
        "org": "Example Org",
        "country": "Testland",
    }

    asn_extractor(result, signals)

    assert signals["asn_number"] == "AS64500"
    assert signals["asn_isp"] == "Example ISP"
    assert signals["ip_abuse_score"] == 73


def test_asn_extractor_preserves_signals_when_lookup_fails():
    signals = {"asn_number": None, "asn_isp": None}

    asn_extractor({"success": False, "error": "lookup failed"}, signals)

    assert signals == {"asn_number": None, "asn_isp": None}


def test_asn_extractor_handles_missing_optional_values():
    signals = {"asn_number": "old", "asn_isp": "old"}

    asn_extractor({"success": True}, signals)

    assert signals["asn_number"] is None
    assert signals["asn_isp"] is None


def test_extract_signals_exposes_asn_defaults():
    results = {
        tool["name"]: {"success": False} for tool in TOOL_REGISTRY
    }
    signals = extract_signals(results)

    assert signals["asn_number"] is None
    assert signals["asn_isp"] is None
