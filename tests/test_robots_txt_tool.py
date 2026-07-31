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
    mock_response.url = "https://example.com/robots.txt"
    mock_response.text = """
    User-agent: *
    Disallow: /admin # No admins allowed
    Allow: /admin/public
    Disallow: /backup/

    User-agent: Googlebot
    Disallow: /secret/
    Sitemap: https://example.com/sitemap.xml
    """
    mock_get.return_value = mock_response
    
    result = robots_txt_inspect("example.com")
    
    assert result["success"] is True
    assert result["domain"] == "example.com"
    assert result["robots_url"] == "https://example.com/robots.txt"
    
    # Check top level aggregations
    assert "/admin" in result["disallowed_paths"]
    assert "/backup/" in result["disallowed_paths"]
    assert "/secret/" in result["disallowed_paths"]
    assert result["allowed_paths"] == ["/admin/public"]
    assert result["sitemaps"] == ["https://example.com/sitemap.xml"]
    
    # Check rule sets
    assert len(result["rules"]) == 2
    assert result["rules"][0]["user_agent"] == "*"
    assert result["rules"][0]["disallow"] == ["/admin", "/backup/"]
    assert result["rules"][0]["allow"] == ["/admin/public"]
    
    assert result["rules"][1]["user_agent"] == "Googlebot"
    assert result["rules"][1]["disallow"] == ["/secret/"]
    assert result["rules"][1]["allow"] == []

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_fallback_to_http(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "http://example.com/robots.txt"
    mock_response.text = "User-agent: *\nDisallow: /private"
    
    mock_get.side_effect = [requests.RequestException("Connection error"), mock_response]
    
    result = robots_txt_inspect("example.com")
    
    assert result["success"] is True
    assert result["domain"] == "example.com"
    assert result["robots_url"] == "http://example.com/robots.txt"
    assert result["disallowed_paths"] == ["/private"]
    assert mock_get.call_count == 2

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_failure(mock_get):
    mock_get.side_effect = requests.RequestException("Timeout")

    result = robots_txt_inspect("example.com")

    assert result["success"] is False
    assert "Failed to fetch robots.txt" in result["error"]

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_parses_crawl_delay_and_host(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com/robots.txt"
    mock_response.text = (
        "User-agent: *\n"
        "Crawl-delay: 10\n"
        "Host: example.com\n"
        "Disallow: /private\n"
    )
    mock_get.return_value = mock_response

    result = robots_txt_inspect("example.com")

    assert result["success"] is True
    assert result["rules"][0]["crawl_delay"] == "10"
    assert result["host"] == "example.com"
    assert result["disallowed_paths"] == ["/private"]

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_crawl_delay_and_host_absent_when_not_present(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com/robots.txt"
    mock_response.text = "User-agent: *\nDisallow: /private\n"
    mock_get.return_value = mock_response

    result = robots_txt_inspect("example.com")

    assert result["success"] is True
    assert result["host"] is None
    assert result["rules"][0]["crawl_delay"] is None

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_crawl_delay_uses_last_seen_value(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com/robots.txt"
    mock_response.text = (
        "User-agent: *\n"
        "Crawl-delay: 5\n"
        "User-agent: Googlebot\n"
        "Crawl-delay: 30\n"
    )
    mock_get.return_value = mock_response

    result = robots_txt_inspect("example.com")

    assert result["success"] is True
    assert result["rules"][0]["crawl_delay"] == "5"
    assert result["rules"][1]["crawl_delay"] == "30"


@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_groups_multiple_user_agents(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com/robots.txt"
    mock_response.text = (
        "User-agent: Googlebot\n"
        "User-agent: Bingbot\n"
        "Disallow: /private\n"
        "Allow: /public\n"
    )
    mock_get.return_value = mock_response

    result = robots_txt_inspect("example.com")

    assert result["success"] is True
    assert len(result["rules"]) == 1
    assert result["rules"][0]["user_agents"] == ["Googlebot", "Bingbot"]
    assert result["rules"][0]["disallow"] == ["/private"]
    assert result["rules"][0]["allow"] == ["/public"]
