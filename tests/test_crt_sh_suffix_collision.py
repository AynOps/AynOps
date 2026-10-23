import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from crt_sh_tool import cert_transparency  # noqa: E402


def _mock_response(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_suffix_collision_domains_are_not_reported_as_subdomains():
    payload = [
        {
            "issuer_name": "Test CA",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2025-01-01T00:00:00",
            "name_value": (
                "example.com\n"
                "www.example.com\n"
                "notexample.com\n"
                "evil-example.com\n"
                "example.com.evil.org\n"
                "*.example.com\n"
                "*.notexample.com\n"
            ),
        }
    ]

    with patch("crt_sh_tool.requests.get", return_value=_mock_response(payload)):
        result = cert_transparency("example.com")

    assert result["success"] is True
    assert result["unique_subdomains"] == ["www.example.com"]
    assert result["total_unique_subdomains"] == 1
    assert result["wildcards_found"] == [".example.com"]
    assert [c["subdomain"] for c in result["certificates"]] == ["www.example.com"]


def test_legitimate_nested_subdomains_are_reported():
    payload = [
        {
            "issuer_name": "Test CA",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2025-01-01T00:00:00",
            "name_value": "a.b.example.com\n*.a.example.com",
        }
    ]

    with patch("crt_sh_tool.requests.get", return_value=_mock_response(payload)):
        result = cert_transparency("example.com")

    assert result["success"] is True
    assert result["unique_subdomains"] == ["a.b.example.com"]
    assert result["wildcards_found"] == [".a.example.com"]
