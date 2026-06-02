import requests
from utils.helpers import get_cvss_details , get_english_description

def cve_lookup(software: str, version: str) -> dict:
    """
    Look up known CVEs for a software name and version using the NVD API.
    """
    software = software.strip()
    version = version.strip()

    if not software or not version:
        return {"success": False, "error": "Software and version are required"}

    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": f"{software} {version}"},
            timeout=60,
            headers={"User-Agent": "CyberSecurity-MCP-Server/1.0"},
        )
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cvss = get_cvss_details(cve)
            cves.append({
                "cve_id": cve.get("id"),
                "severity": cvss["severity"],
                "score": cvss["score"],
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "description": get_english_description(cve),
            })

        return {
            "success": True,
            "software": software,
            "version": version,
            "total_results": data.get("totalResults", len(cves)),
            "cves": cves,
        }

    except requests.exceptions.HTTPError as e:
        return {"success": False, "error": f"NVD API request failed: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "NVD API request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Could not connect to NVD API: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
