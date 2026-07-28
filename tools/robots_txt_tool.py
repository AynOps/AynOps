import requests
from utils.helpers import is_valid_domain, normalize_domain

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
        
        # Parse robots.txt into rule groups keyed by User-agent.
        # Consecutive User-agent lines belong to the same group (RFC 9309 §2.1).
        rules = []
        current_agents = []
        current_allow = []
        current_disallow = []
        current_crawl_delay = None
        in_agent_block = False  # True while we are reading consecutive User-agent lines
        
        sitemaps = []
        host = None

        def flush_group():
            nonlocal current_agents, current_allow, current_disallow, current_crawl_delay, in_agent_block
            if current_agents:
                rules.append({
                    "user_agent": current_agents if len(current_agents) > 1 else current_agents[0],
                    "allow": list(dict.fromkeys(current_allow)),
                    "disallow": list(dict.fromkeys(current_disallow)),
                    "crawl_delay": current_crawl_delay,
                })
            current_agents = []
            current_allow = []
            current_disallow = []
            current_crawl_delay = None
            in_agent_block = False

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
                if in_agent_block:
                    # Consecutive User-agent: same group
                    current_agents.append(agent)
                else:
                    # New group starts — flush the previous one
                    flush_group()
                    current_agents = [agent]
                    in_agent_block = True
                
            elif line_lower.startswith("disallow:"):
                in_agent_block = False
                path = line.split(":", 1)[1].strip()
                if path:
                    current_disallow.append(path)
                    
            elif line_lower.startswith("allow:"):
                in_agent_block = False
                path = line.split(":", 1)[1].strip()
                if path:
                    current_allow.append(path)
                    
            elif line_lower.startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                if sitemap:
                    sitemaps.append(sitemap)

            elif line_lower.startswith("crawl-delay:"):
                in_agent_block = False
                value = line.split(":", 1)[1].strip()
                if value:
                    current_crawl_delay = value

            elif line_lower.startswith("host:"):
                value = line.split(":", 1)[1].strip()
                if value:
                    host = value

        # Flush the last group
        flush_group()

        # For backward compatibility and top-level summary, aggregate all unique paths
        all_allowed = []
        all_disallowed = []
        crawl_delay = None
        for r in rules:
            all_allowed.extend(r["allow"])
            all_disallowed.extend(r["disallow"])
            if r["crawl_delay"] is not None:
                crawl_delay = r["crawl_delay"]
            
        return {
            "success": True,
            "domain": domain,
            "robots_url": robots_url,
            "allowed_paths": list(dict.fromkeys(all_allowed)),
            "disallowed_paths": list(dict.fromkeys(all_disallowed)),
            "sitemaps": list(dict.fromkeys(sitemaps)),
            "crawl_delay": crawl_delay,
            "host": host,
            "rules": rules
        }

    except requests.RequestException as e:
        return {"success": False, "error": f"Failed to fetch robots.txt: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
