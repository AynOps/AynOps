import unittest
from unittest.mock import patch, Mock
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
        },
        {
            "name_value": "api.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        },
        {
            "name_value": "*.example.com\nwww.example.com\nexample.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-02-01T00:00:00",
            "not_after": "2026-05-01T00:00:00",
        }
    ]
    mock_get.return_value = mock_response

    result = cert_transparency("example.com")

    assert result["success"] is True
    assert result["source"] == "crt.sh"
    assert result["domain"] == "example.com"
    assert "api.example.com" in result["unique_subdomains"]
    assert "dev.example.com" in result["unique_subdomains"]
    assert "www.example.com" in result["unique_subdomains"]
    assert result["unique_subdomains"] == ["api.example.com", "dev.example.com", "www.example.com"]
    assert result["wildcards_found"] == [".example.com"]
    assert result["total_unique_subdomains"] == 3
    assert result["total_certificates"] == 3
    assert result["returned_certificates"] == 3
    assert result["truncated"] is False
    assert result["certificates"] == [
        {
            "subdomain": "api.example.com",
            "issuer": "Let's Encrypt",
            "not_before": "2026-01-01",
            "not_after": "2026-04-01",
        },
        {
            "subdomain": "dev.example.com",
            "issuer": "Let's Encrypt",
            "not_before": "2026-01-01",
            "not_after": "2026-04-01",
        },
        {
            "subdomain": "www.example.com",
            "issuer": "Let's Encrypt",
            "not_before": "2026-02-01",
            "not_after": "2026-05-01",
        },
    ]


def test_invalid_domain():
    result = cert_transparency("not a domain")
    assert result["success"] is False
    assert result["error"] == "Invalid domain format"


@patch("tools.crt_sh_tool.requests.get")
def test_requests_error_returns_network_error(mock_get):
    mock_get.side_effect = RequestsError("Operation timed out", 28)

    result = cert_transparency("example.com")

    assert result["success"] is False
    assert result["domain"] == "example.com"
    assert result["error"].startswith("Network error:")


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

    assert result["success"] is True
    assert result["wildcards_found"] == [".api.example.com"]
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

    assert result["wildcards_found"] == [".example.com"]
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

    assert result["wildcards_found"] == [".example.com"]
    assert "api.example.com" in result["unique_subdomains"]
    assert result["total_unique_subdomains"] == 1

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
    assert result["total_certificates"] == 0

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


@patch("tools.crt_sh_tool.requests.get")
def test_results_are_truncated_at_50_certificates(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name_value": f"host{i}.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        }
        for i in range(51)
    ]
    mock_get.return_value = mock_response

    result = cert_transparency("example.com")

    assert result["success"] is True
    assert result["total_certificates"] == 51
    assert result["returned_certificates"] == 50
    assert result["truncated"] is True
    assert len(result["certificates"]) == 50
    assert result["total_unique_subdomains"] == 51

if __name__ == "__main__":
    unittest.main(verbosity=2)