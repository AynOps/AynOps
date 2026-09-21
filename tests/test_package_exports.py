"""Tests for package-level exports centralized in __init__.py files."""

import tools.fingerprint
import tools.prompts
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
