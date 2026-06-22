import unittest
from unittest.mock import patch, Mock
import pytest
from curl_cffi.requests.errors import RequestsError
from tools.crt_sh_tool import cert_transparency

@patch("tools.crt_sh_tool.requests.get")
def test_cert_transparency_success(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name_value": "api.example.com\ndev.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        }
    ]
    mock_get.return_value = mock_response

    result = cert_transparency("example.com")

    assert result["success"] is True
    assert result["source"] == "crt.sh"
    assert "api.example.com" in result["unique_subdomains"]
    assert "dev.example.com" in result["unique_subdomains"]


def test_invalid_domain():
    result = cert_transparency("not a domain")
    assert result["success"] is False


# Patch BOTH the primary curl_cffi requests AND the standard_requests fallback
@patch("tools.crt_sh_tool.standard_requests.get")
@patch("tools.crt_sh_tool.requests.get")
def test_timeout_with_fallback_success(mock_primary_get, mock_fallback_get):
    mock_primary_get.side_effect = RequestsError("Operation timed out", 28)

    mock_fallback_response = Mock()
    mock_fallback_response.status_code = 200
    mock_fallback_response.text = "api.example.com,1.1.1.1\nvpn.example.com,2.2.2.2"
    mock_fallback_get.return_value = mock_fallback_response

    result = cert_transparency("example.com")

    assert result["success"] is True
    assert result["source"] == "hackertarget_fallback"
    assert "api.example.com" in result["unique_subdomains"]
    assert "vpn.example.com" in result["unique_subdomains"]


@patch("tools.crt_sh_tool.standard_requests.get")
@patch("tools.crt_sh_tool.requests.get")
def test_timeout_with_fallback_failure(mock_primary_get, mock_fallback_get):
    mock_primary_get.side_effect = RequestsError("Operation timed out", 28)

    mock_fallback_response = Mock()
    mock_fallback_response.status_code = 200
    mock_fallback_response.text = "API count exceeded - Increase Plan or Log In"
    mock_fallback_get.return_value = mock_fallback_response

    result = cert_transparency("example.com")

    assert result["success"] is False
    assert "error" in result


@patch("tools.crt_sh_tool.standard_requests.get")
@patch("tools.crt_sh_tool.requests.get")
def test_http_error_trigger_fallback(mock_primary_get, mock_fallback_get):
    mock_primary_get.side_effect = RequestsError("HTTP 502 Bad Gateway", 502)

    mock_fallback_response = Mock()
    mock_fallback_response.status_code = 200
    mock_fallback_response.text = "fallback.example.com,3.3.3.3"
    mock_fallback_get.return_value = mock_fallback_response

    result = cert_transparency("example.com")

    assert result["success"] is True
    assert result["source"] == "hackertarget_fallback"
    assert "fallback.example.com" in result["unique_subdomains"]


@patch("tools.crt_sh_tool.requests.get")
def test_wildcard_subdomain(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name_value": "*.api.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        }
    ]
    mock_get.return_value = mock_response

    result = cert_transparency("example.com")

    assert ".api.example.com" in result["wildcards_found"]
    assert result["unique_subdomains"] == []


@patch("tools.crt_sh_tool.requests.get")
def test_wildcard_on_root_domain_is_captured(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name_value": "*.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        }
    ]
    mock_get.return_value = mock_response

    result = cert_transparency("example.com")

    assert ".example.com" in result["wildcards_found"]
    assert result["unique_subdomains"] == []
    assert result["total_unique_subdomains"] == 0

@patch("tools.crt_sh_tool.requests.get")
def test_mixed_wildcard_and_concrete_subdomain(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name_value": "*.example.com\napi.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        }
    ]
    mock_get.return_value = mock_response

    result = cert_transparency("example.com")

    assert ".example.com" in result["wildcards_found"]
    assert "api.example.com" in result["unique_subdomains"]

@patch("tools.crt_sh_tool.requests.get")
def test_unrelated_wildcard_is_filtered_out(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name_value": "*.unrelated-domain.net",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        }
    ]
    mock_get.return_value = mock_response

    result = cert_transparency("example.com")
    
    assert result["wildcards_found"] == []
    assert result["unique_subdomains"] == []

@patch("tools.crt_sh_tool.requests.get")
def test_wildcard_suffix_collision_is_filtered_out(mock_get):
    """*.example.com should NOT appear when querying ample.com"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name_value": "*.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        }
    ]
    mock_get.return_value = mock_response

    result = cert_transparency("ample.com")

    assert result["wildcards_found"] == []

if __name__ == "__main__":
    unittest.main(verbosity=2)