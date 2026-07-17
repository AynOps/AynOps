import pytest
from unittest.mock import patch, MagicMock
from tools.robots_txt_tool import robots_txt_inspect
import requests

def test_robots_txt_inspect_invalid_domain():
    result = robots_txt_inspect("invalid domain")
    assert result["success"] is False
    assert "Invalid domain format" in result["error"]

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_happy_path_https(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = """
User-agent: *
Disallow: /
Disallow: /admin
Disallow: /backup/
Disallow: /admin
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap2.xml
"""
    mock_get.return_value = mock_response
    
    result = robots_txt_inspect("example.com")
    
    assert result["success"] is True
    assert result["domain"] == "example.com"
    # / should be filtered out, duplicates should be removed, order preserved
    assert result["disallowed_paths"] == ["/admin", "/backup/"]
    assert result["sitemaps"] == ["https://example.com/sitemap.xml", "https://example.com/sitemap2.xml"]

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_fallback_to_http(mock_get):
    # First call (HTTPS) raises an exception, second call (HTTP) succeeds
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "User-agent: *\nDisallow: /private"
    
    # Configure side_effect: first call raises RequestException, second returns mock_response
    mock_get.side_effect = [requests.RequestException("Connection error"), mock_response]
    
    result = robots_txt_inspect("example.com")
    
    assert result["success"] is True
    assert result["domain"] == "example.com"
    assert result["disallowed_paths"] == ["/private"]
    assert mock_get.call_count == 2

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_failure(mock_get):
    mock_get.side_effect = requests.RequestException("Timeout")
    
    result = robots_txt_inspect("example.com")
    
    assert result["success"] is False
    assert "Failed to fetch robots.txt" in result["error"]
