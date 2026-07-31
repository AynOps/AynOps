import requests
from utils.helpers import is_valid_domain, normalize_domain

def save_rule(rule: dict, rules: list) -> None:
    """Normalize a parsed rule group and append it to the collected rules."""
    if not rule["user_agents"]:
        return

    has_directives = (rule["allow"] or rule['disallow'] or rule['crawl_delay'] is not None)

    if not has_directives:
        return

    if len(rule["user_agents"]) == 1:
        data = {
            "user_agent": rule["user_agents"][0],
            "allow": list(dict.fromkeys(rule["allow"])),
            "disallow": list(dict.fromkeys(rule["disallow"])),
            "crawl_delay": rule["crawl_delay"],
        }
    else:
        data = {
            "user_agents": list(dict.fromkeys(rule["user_agents"])),
            "allow": list(dict.fromkeys(rule["allow"])),
            "disallow": list(dict.fromkeys(rule["disallow"])),
            "crawl_delay": rule["crawl_delay"],
        }

    rules.append(data)


def robots_txt_inspect(domain: str) -> dict:
    """
    Fetch and parse the robots.txt file for a given domain to reveal hidden directories and sitemaps.
    """
    try:
        domain = normalize_domain(domain)
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        url_https = f"https://{domain}/robots.txt"
        url_http = f"http://{domain}/robots.txt"
        
        try:
            response = requests.get(url_https, timeout=10.0, headers=headers)
            response.raise_for_status()
        except requests.RequestException:
            # Fallback to HTTP
            response = requests.get(url_http, timeout=10.0, headers=headers)
            response.raise_for_status()
            
        content = response.text
        robots_url = response.url
        
        rules = []
        current_rule = {
            "user_agents": [],
            "allow": [],
            "disallow": [],
            "crawl_delay": None,
        }

        seen_directive_in_group = False

        sitemaps = []
        host = None

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

                # New group starts only after directives have appeared
                if seen_directive_in_group:
                    save_rule(current_rule, rules)

                    current_rule = {
                        "user_agents": [],
                        "allow": [],
                        "disallow": [],
                        "crawl_delay": None,
                    }

                    seen_directive_in_group = False

                current_rule["user_agents"].append(agent)
                
            elif line_lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()

                if path:
                    current_rule["disallow"].append(path)

                seen_directive_in_group = True
                    
            elif line_lower.startswith("allow:"):
                path = line.split(":", 1)[1].strip()

                if path:
                    current_rule["allow"].append(path)

                seen_directive_in_group = True
                    
            elif line_lower.startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                if sitemap:
                    sitemaps.append(sitemap)

            elif line_lower.startswith("crawl-delay:"):
                value = line.split(":", 1)[1].strip()

                if value:
                    current_rule["crawl_delay"] = value

                seen_directive_in_group = True

            elif line_lower.startswith("host:"):
                # `Host:` is a non-standard but widely-recognized directive
                # (originally from Yandex) used to specify the primary mirror.
                value = line.split(":", 1)[1].strip()
                if value:
                    host = value

        save_rule(current_rule, rules)

        # For backward compatibility and top-level summary, aggregate all unique paths
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
            "host": host,
            "rules": rules
        }

    except requests.RequestException as e:
        return {"success": False, "error": f"Failed to fetch robots.txt: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}