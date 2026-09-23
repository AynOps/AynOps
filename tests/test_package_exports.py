"""Tests for package-level exports centralized in __init__.py files."""

import tools
import tools.fingerprint
import tools.prompts
import tools.signals
import utils


def test_utils_package_exports():
    expected_utils = {
        "get_cvss_details",
        "get_english_description",
        "is_valid_domain",
        "normalize_domain",
        "safe_parse_datetime",
    }
    assert set(utils.__all__) == expected_utils
    for name in expected_utils:
        assert hasattr(utils, name)


def test_tools_prompts_package_exports():
    expected_prompts = {
        "THREAT_ANALYSIS_PROMPT",
    }
    assert set(tools.prompts.__all__) == expected_prompts
    for name in expected_prompts:
        assert hasattr(tools.prompts, name)


def test_tools_fingerprint_package_exports():
    expected_fingerprint = {
        "cookies_layer",
        "fingerprint",
        "headers_layer",
        "html_layer",
        "meta_layer",
    }
    assert set(tools.fingerprint.__all__) == expected_fingerprint
    for name in expected_fingerprint:
        assert hasattr(tools.fingerprint, name)


def test_tools_package_exports():
    expected_tools = {
        "PUBLIC_RESOLVERS",
        "TOOL_REGISTRY",
        "asn_lookup",
        "cert_transparency",
        "cloud_exposure_check",
        "cve_lookup",
        "dns_enumeration",
        "email_security_check",
        "extract_signals",
        "full_recon",
        "headers_analyzer",
        "hibp_check",
        "ip_reputation",
        "port_scan",
        "robots_txt_inspect",
        "ssl_inspect",
        "subdomain_takeover",
        "tech_stack_detect",
        "trace_redirects",
        "whois_lookup",
    }
    assert set(tools.__all__) == expected_tools
    for name in expected_tools:
        assert hasattr(tools, name)


def test_tools_signals_package_exports():
    expected_signals = {
        "TOOL_REGISTRY",
        "asn_extractor",
        "crt_extractor",
        "dns_extractor",
        "email_security_extractor",
        "extract_ip",
        "extract_signals",
        "headers_extractor",
        "ip_reputation_extractor",
        "portscan_extractor",
        "ssl_extractor",
        "techstack_extractor",
        "whois_extractor",
    }
    assert set(tools.signals.__all__) == expected_signals
    for name in expected_signals:
        assert hasattr(tools.signals, name)
