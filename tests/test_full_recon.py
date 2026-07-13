import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

# Import the functions to test. Adjust 'tools.fullrecon_tool' to match your actual module layout.
from tools.fullrecon_tool import _format_signals_block, full_recon


# ==========================================
# FIXTURES & MOCK DATA
# ==========================================

@pytest.fixture
def mock_signals_full():
    """Provides a complete signals dictionary with all fields populated."""
    return {
        "auto_warnings": ["Critical exposed admin panel", "Expired root certificate"],
        "domain_expiry_days": 45,
        "ssl_days_remaining": 12,
        "open_ports": ["80", "443", "8080"],
        "software_detected": ["nginx 1.18.0", "OpenSSL 1.1.1"],
        "subdomain_count": 14,
        "ip_abuse_score": 12,
        "ip_reputation_flagged": True,
        "missing_security_headers": ["Content-Security-Policy", "X-Frame-Options"],
        "dns_missing_records": ["DMARC", "CAA"],
        "email_security": {
            "security_score": 75,
            "rating": "B",
            "spf_found": True,
            "spf_policy": "~all",
            "dkim_found": False,
            "dmarc_found": True,
            "dmarc_policy": "quarantine"
        },
        "cves_found": [
            {"id": "CVE-2023-0001", "cvss": 9.8, "summary": "Remote Code Execution"},
            {"id": "CVE-2023-0002", "cvss": 7.5, "summary": "Dos Vulnerability"},
            {"id": "CVE-2023-0003", "cvss": 5.3, "summary": "Information Disclosure"},
            {"id": "CVE-2023-0004", "cvss": 4.2, "summary": "XSS Vulnerability"},
            {"id": "CVE-2023-0005", "cvss": 9.1, "summary": "SQL Injection"},
            {"id": "CVE-2023-0006", "cvss": 3.1, "summary": "Minor Information Leak"}
        ]
    }


@pytest.fixture
def mock_signals_empty():
    """Provides a minimal signals dictionary to test defaults and missing fields."""
    return {
        "open_ports": [],
        "software_detected": []
    }


# ==========================================
# TESTS FOR _format_signals_block
# ==========================================

def test_format_signals_block_full(mock_signals_full):
    """Verifies formatting when all data points and lists are populated."""
    output = _format_signals_block(mock_signals_full)
    
    # Verify warnings block
    assert "⚠️  AUTO-WARNINGS (highest priority):" in output
    assert "  • Critical exposed admin panel" in output
    
    # Verify core counters/strings
    assert "Domain expiry      : 45 days" in output
    assert "Open ports         : 80, 443, 8080" in output
    assert "IP flagged malicious: True" in output
    
    # Verify security headers and DNS strings
    assert "Missing sec headers: 2 — Content-Security-Policy, X-Frame-Options" in output
    assert "Missing DNS records : DMARC, CAA" in output
    
    # Verify email block nested items
    assert "Email security score: 75 (B)" in output
    assert "  SPF  : ✓ found — policy: ~all" in output
    assert "  DKIM : ✗ missing" in output
    assert "  DMARC: ✓ found — policy: quarantine" in output
    
    # Verify CVE threshold cap logic (must show exactly 5 + overflow indicator)
    assert "CVEs found (6):" in output
    assert "  • CVE-2023-0001 (CVSS 9.8)" in output
    assert "  • CVE-2023-0005 (CVSS 9.1)" in output
    assert "  • CVE-2023-0006" not in output
    assert "  … and 1 more" in output


def test_format_signals_block_empty(mock_signals_empty):
    """Verifies that missing or unpopulated fields render standard text fallbacks safely."""
    output = _format_signals_block(mock_signals_empty)
    
    assert "⚠️  AUTO-WARNINGS" not in output
    assert "Domain expiry      : unknown days" in output
    assert "SSL days remaining : unknown days" in output
    assert "Open ports         : none detected" in output
    assert "Software detected  : none" in output
    assert "Missing sec headers: 0 — none" in output
    assert "Missing DNS records : none" in output
    assert "CVEs found         : none" in output


# ==========================================
# TESTS FOR full_recon
# ==========================================

@patch("tools.fullrecon_tool.is_valid_domain")
def test_full_recon_invalid_domain(mock_is_valid):
    """Validates immediate shortcut error handling when domain syntax fails validation."""
    mock_is_valid.return_value = False
    
    result = full_recon("invalid_domain!!")
    
    assert result == {"success": False, "error": "Invalid domain format"}
    mock_is_valid.assert_called_once_with("invalid_domain!!")


@patch("tools.fullrecon_tool.THREAT_ANALYSIS_PROMPT")
@patch("tools.fullrecon_tool.extract_signals")
@patch("tools.fullrecon_tool.TOOL_REGISTRY")
@patch("tools.fullrecon_tool.is_valid_domain")
def test_full_recon_success(mock_is_valid, mock_registry, mock_extract, mock_prompt):
    """Simulates a completely successful run across multiple dependency waves."""
    mock_is_valid.return_value = True
    mock_prompt.format.return_value = "Formatted AI Prompt String"
    mock_extract.return_value = {"open_ports": [], "software_detected": []}

    # Define mock execution actions for tools
    tool_1_fn = MagicMock(return_value={"success": True, "data": "wave1_out"})
    tool_2_fn = MagicMock(return_value={"success": True, "data": "wave2_out"})

    # Set up our mocked dynamic tool registry structure
    mock_registry.__iter__.return_value = [
        {
            "name": "dns_scan",
            "wave": 1,
            "fn": tool_1_fn,
            "args": lambda dom, res: (dom,)
        },
        {
            "name": "port_scan",
            "wave": 2,
            "fn": tool_2_fn,
            "args": lambda dom, res: (dom, res["dns_scan"]),
            "should_run": lambda dom, res: "dns_scan" in res
        }
    ]

    result = full_recon("example.com")

    assert result["success"] is True
    assert result["domain"] == "example.com"
    assert "Z" in result["scanned_at"]  # Assures ISO 8601 UTC notation format
    
    # Check tool execution tracking records
    assert result["tool_coverage"] == {
        "dns_scan": "success",
        "port_scan": "success"
    }
    assert result["tools_summary"] == {
        "total": 2,
        "succeeded": 2,
        "skipped": 0,
        "failed": 0
    }
    
    # Assert dependency sequence arguments resolved cleanly
    tool_1_fn.assert_called_once_with("example.com")
    tool_2_fn.assert_called_once_with("example.com", {"success": True, "data": "wave1_out"})


@patch("tools.fullrecon_tool.extract_signals")
@patch("tools.fullrecon_tool.TOOL_REGISTRY")
@patch("tools.fullrecon_tool.is_valid_domain")
def test_full_recon_skips_and_failures(mock_is_valid, mock_registry, mock_extract):
    """Verifies system edge behaviors when tools throw generic exceptions or skip cleanly."""
    mock_is_valid.return_value = True
    mock_extract.return_value = {"open_ports": [], "software_detected": []}

    # Set up tool behavior variables
    failing_fn = MagicMock(side_effect=RuntimeError("Connection Timeout failure"))
    skipped_fn = MagicMock()

    mock_registry.__iter__.return_value = [
        {
            "name": "failing_tool",
            "wave": 1,
            "fn": failing_fn,
            "args": lambda dom, res: (dom,)
        },
        {
            "name": "skipped_tool",
            "wave": 2,
            "fn": skipped_fn,
            "args": lambda dom, res: (dom,),
            "should_run": lambda dom, res: False,  # Force evaluate to skip condition
            "skip_reason": "Prerequisite data missing"
        }
    ]

    result = full_recon("target.com")

    # The function engine itself must succeed even if tools fall flat
    assert result["success"] is True
    
    # Assert coverage mapping translated the tool execution states properly
    assert result["tool_coverage"]["failing_tool"] == "failed — Connection Timeout failure"
    assert result["tool_coverage"]["skipped_tool"] == "skipped — Prerequisite data missing"
    
    # Check aggregated numerical stats outputs
    assert result["tools_summary"] == {
        "total": 2,
        "succeeded": 0,
        "skipped": 1,
        "failed": 1
    }
    
    # Ensure skipped target functions never entered execution path
    skipped_fn.assert_not_called()