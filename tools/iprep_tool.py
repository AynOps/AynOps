import ipaddress
import requests
import os

def ip_reputation(ip_address: str) -> dict:
    """
    Check whether an IP address is reported as malicious using AbuseIPDB.
    Requires ABUSEIPDB_API_KEY in the environment.
    """
    try:
        ip = str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        return {"success": False, "error": "Invalid IP address format"}

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "ABUSEIPDB_API_KEY environment variable is required",
        }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json().get("data", {})

        abuse_score = data.get("abuseConfidenceScore", 0)
        return {
            "success": True,
            "ip": ip,
            "is_malicious": abuse_score >= 25,
            "abuse_confidence_score": abuse_score,
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "last_reported_at": data.get("lastReportedAt"),
        }

    except requests.exceptions.HTTPError as e:
        return {"success": False, "error": f"AbuseIPDB API request failed: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "AbuseIPDB API request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Could not connect to AbuseIPDB API: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}