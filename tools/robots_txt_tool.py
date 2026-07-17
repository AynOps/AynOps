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
        disallowed = []
        sitemaps = []
        
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                # Filter out generic or empty entries
                if path and path != "/":
                    disallowed.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                if sitemap:
                    sitemaps.append(sitemap)
        
        return {
            "success": True,
            "domain": domain,
            "disallowed_paths": list(dict.fromkeys(disallowed)),
            "sitemaps": list(dict.fromkeys(sitemaps))
        }

    except requests.RequestException as e:
        return {"success": False, "error": f"Failed to fetch robots.txt: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
