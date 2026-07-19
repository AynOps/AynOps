from unittest.mock import Mock, patch

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
    # Pure CT path should not use browser impersonation.
    assert "impersonate" not in mock_get.call_args.kwargs


def test_invalid_domain():
    result = cert_transparency("not a domain")
    assert result["success"] is False


@patch("tools.crt_sh_tool.requests.get")
def test_timeout_returns_clear_ct_error(mock_get):
    mock_get.side_effect = RequestsError("Operation timed out", 28)

    result = cert_transparency("example.com")

    assert result["success"] is False
    assert result["domain"] == "example.com"
    assert result["error"] == "Certificate Transparency lookup failed."
    assert result.get("source") != "hackertarget_fallback"


@patch("tools.crt_sh_tool.requests.get")
def test_http_error_returns_clear_ct_error(mock_get):
    mock_get.side_effect = RequestsError("HTTP 502 Bad Gateway", 502)

    result = cert_transparency("example.com")

    assert result["success"] is False
    assert result["error"] == "Certificate Transparency lookup failed."


@patch("tools.crt_sh_tool.requests.get")
def test_invalid_json_returns_clear_ct_error(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.raise_for_status.return_value = None
    mock_response.json.side_effect = ValueError("No JSON")
    mock_get.return_value = mock_response

    result = cert_transparency("example.com")

    assert result["success"] is False
    assert result["error"] == "Certificate Transparency lookup failed."


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
