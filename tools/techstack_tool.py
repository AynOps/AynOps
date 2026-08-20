import requests
from tools.fingerprint import fingerprint
from utils.helpers import is_valid_domain, normalize_domain

def tech_stack_detect(domain: str) -> dict:
    """
    Detect technology stack of a website.
    Identifies web server, frameworks, CMS, CDN, and analytics.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    try:
        url = f"https://{domain}"
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        technologies = fingerprint(headers, resp.text)

        return {
            "success": True,
            "domain": domain,
            "url": resp.url,
            "status_code": resp.status_code,
            "technologies": technologies,
        }

    except requests.exceptions.SSLError as e:
        return {"success": False, "error": f"SSL error: {str(e)}"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Could not connect to the domain"}
    except Exception as e:
        return {"success": False, "error": str(e)}
