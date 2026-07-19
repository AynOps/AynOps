import requests
from utils.helpers import is_valid_domain


def robots_txt_inspect(domain: str) -> dict:
    """
    Fetch and parse the robots.txt file for a given domain to reveal hidden directories and sitemaps.
    """
    try:
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        url_https = f"https://{domain}/robots.txt"
        url_http = f"http://{domain}/robots.txt"

        response = None
        try:
            response = requests.get(url_https, timeout=10.0, headers=headers)
            response.raise_for_status()
        except requests.RequestException:
            # Fallback to HTTP
            response = requests.get(url_http, timeout=10.0, headers=headers)
            response.raise_for_status()

        content = response.text
        robots_url = response.url

        # Parse robots.txt into per-User-agent rule groups.
        # Consecutive User-agent lines share the following directives.
        rules = []
        current_agents: list[str] = []
        current_allow: list[str] = []
        current_disallow: list[str] = []
        current_crawl_delay = None
        seen_directive_in_group = False

        sitemaps = []
        crawl_delay = None  # last-seen top-level value (backward compatible)
        host = None

        def flush_group() -> None:
            nonlocal current_agents, current_allow, current_disallow
            nonlocal current_crawl_delay, seen_directive_in_group
            if not current_agents:
                return
            allow = list(dict.fromkeys(current_allow))
            disallow = list(dict.fromkeys(current_disallow))
            for agent in current_agents:
                rules.append(
                    {
                        "user_agent": agent,
                        "allow": list(allow),
                        "disallow": list(disallow),
                        "crawl_delay": current_crawl_delay,
                    }
                )
            current_agents = []
            current_allow = []
            current_disallow = []
            current_crawl_delay = None
            seen_directive_in_group = False

        for line in content.splitlines():
            # Strip inline comments first
            if "#" in line:
                line = line.split("#", 1)[0]
            line = line.strip()

            if not line:
                continue

            line_lower = line.lower()

            if line_lower.startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip()
                if not agent:
                    continue
                # A User-agent after directives starts a new rule group.
                if seen_directive_in_group:
                    flush_group()
                current_agents.append(agent)

            elif line_lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    current_disallow.append(path)
                seen_directive_in_group = True

            elif line_lower.startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    current_allow.append(path)
                seen_directive_in_group = True

            elif line_lower.startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                if sitemap:
                    sitemaps.append(sitemap)

            elif line_lower.startswith("crawl-delay:"):
                # Crawl-delay is non-standard; honor it per User-agent group.
                value = line.split(":", 1)[1].strip()
                if value:
                    current_crawl_delay = value
                    crawl_delay = value  # keep last-seen top-level for compatibility
                seen_directive_in_group = True

            elif line_lower.startswith("host:"):
                # Host is non-standard but widely recognized (originally Yandex).
                value = line.split(":", 1)[1].strip()
                if value:
                    host = value

        # Flush the final group even when it only has Crawl-delay / empty paths.
        flush_group()

        # Top-level summary aggregates unique paths across all groups.
        all_allowed = []
        all_disallowed = []
        for r in rules:
            all_allowed.extend(r["allow"])
            all_disallowed.extend(r["disallow"])

        return {
            "success": True,
            "domain": domain,
            "robots_url": robots_url,
            "allowed_paths": list(dict.fromkeys(all_allowed)),
            "disallowed_paths": list(dict.fromkeys(all_disallowed)),
            "sitemaps": list(dict.fromkeys(sitemaps)),
            "crawl_delay": crawl_delay,
            "host": host,
            "rules": rules,
        }

    except requests.RequestException as e:
        return {"success": False, "error": f"Failed to fetch robots.txt: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
