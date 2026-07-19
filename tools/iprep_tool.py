import ipaddress
import os

import requests


def _classify_reputation(
    *,
    is_whitelisted: bool | None,
    abuse_score: int,
    total_reports: int,
) -> str:
    """Return a human-readable reputation label.

    Priority:
    1. trusted  - explicitly whitelisted by AbuseIPDB
    2. high-risk - high abuse confidence
    3. suspicious - moderate confidence or many reports with some confidence
    4. low-risk - some reports but very low confidence
    5. clean - no meaningful abuse signal
    """
    if is_whitelisted:
        return "trusted"
    if abuse_score >= 75:
        return "high-risk"
    if abuse_score >= 25:
        return "suspicious"
    if total_reports > 0 and abuse_score > 0:
        return "low-risk"
    if total_reports > 0:
        return "low-risk"
    return "clean"


def ip_reputation(ip_address: str) -> dict:
    """
    Check whether an IP address is reported as malicious using AbuseIPDB.
    Requires ABUSEIPDB_API_KEY in the environment.

    Returns both the legacy is_malicious boolean and a richer reputation
    classification based on whitelist metadata and abuse confidence.
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

        abuse_score = data.get("abuseConfidenceScore", 0) or 0
        total_reports = data.get("totalReports", 0) or 0
        is_whitelisted = data.get("isWhitelisted")
        reputation = _classify_reputation(
            is_whitelisted=is_whitelisted,
            abuse_score=int(abuse_score),
            total_reports=int(total_reports),
        )

        return {
            "success": True,
            "ip": ip,
            # Keep legacy flag for compatibility; whitelist overrides malicious.
            "is_malicious": bool(abuse_score >= 25 and not is_whitelisted),
            "reputation": reputation,
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "num_distinct_users": data.get("numDistinctUsers"),
            "is_whitelisted": is_whitelisted,
            "is_public": data.get("isPublic"),
            "is_tor": data.get("isTor"),
            "ip_version": data.get("ipVersion"),
            "hostnames": data.get("hostnames") or [],
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
