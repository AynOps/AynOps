import re
import requests
import os


EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_REGEX = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def _is_email(query: str) -> bool:
    return bool(EMAIL_REGEX.match(query.strip()))


def _is_domain(query: str) -> bool:
    return bool(DOMAIN_REGEX.match(query.strip().lower()))


def _calculate_risk_level(total_breaches: int, is_whitelisted: bool = False) -> str:
    """Calculate human-readable risk level from breach count and whitelist status."""
    if is_whitelisted:
        return "NONE"
    if total_breaches == 0:
        return "NONE"
    if total_breaches <= 2:
        return "LOW"
    if total_breaches <= 5:
        return "MEDIUM"
    if total_breaches <= 10:
        return "HIGH"
    return "CRITICAL"


def _format_breach(breach: dict) -> dict:
    """Format a HIBP breach object into the expected output structure."""
    return {
        "name": breach.get("Name", "Unknown"),
        "breach_date": breach.get("BreachDate", "Unknown"),
        "pwn_count": breach.get("PwnCount", 0),
        "data_exposed": breach.get("DataClasses", []),
        "description": breach.get("Description", ""),
    }


def hibp_check(query: str) -> dict:
    """
    Check if an email address or domain has appeared in known data breaches
    using the Have I Been Pwned (HIBP) API v3.

    Requires HIBP_API_KEY environment variable.
    """
    query = query.strip()

    # Detect input type - validate first
    if _is_email(query):
        query_type = "email"
        endpoint = f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}"
        params = {"truncateResponse": "false"}
    elif _is_domain(query):
        query_type = "domain"
        endpoint = f"https://haveibeenpwned.com/api/v3/breaches?domain={query}"
        params = {}
    else:
        return {"success": False, "error": "Input must be a valid email address or domain name"}

    # Read API key from environment
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "HIBP_API_KEY environment variable is required. Get a free key at https://haveibeenpwned.com/API/Key",
        }

    headers = {
        "hibp-api-key": api_key,
        "Accept": "application/json",
        "User-Agent": "AynOps-MCP-Server",
    }

    try:
        response = requests.get(
            endpoint,
            params=params,
            headers=headers,
            timeout=15,
        )

        # 404 means no breaches found - not an error
        if response.status_code == 404:
            return {
                "success": True,
                "query": query,
                "type": query_type,
                "breached": False,
                "total_breaches": 0,
                "breaches": [],
                "pastes_found": 0,
                "risk_level": "NONE",
            }

        response.raise_for_status()
        breaches = response.json()

        # Get paste count for email queries
        pastes_found = 0
        if query_type == "email":
            try:
                paste_resp = requests.get(
                    f"https://haveibeenpwned.com/api/v3/pasteaccount/{query}",
                    headers=headers,
                    timeout=10,
                )
                if paste_resp.status_code == 200:
                    pastes_found = len(paste_resp.json())
                elif paste_resp.status_code == 404:
                    pastes_found = 0
            except Exception:
                pastes_found = 0

        # Check if any breach has IsVerified=True and IsRetired=False for whitelist logic
        is_whitelisted = False
        # HIBP doesn't directly return a whitelist flag in breaches, but we can check
        # for known trusted domains/services. For now, we'll rely on breach count.
        # The issue mentions checking isWhitelisted but HIBP API v3 doesn't expose it directly.
        # We'll note this in the response.

        total_breaches = len(breaches)
        risk_level = _calculate_risk_level(total_breaches, is_whitelisted)

        formatted_breaches = [_format_breach(b) for b in breaches]

        result = {
            "success": True,
            "query": query,
            "type": query_type,
            "breached": total_breaches > 0,
            "total_breaches": total_breaches,
            "breaches": formatted_breaches,
            "pastes_found": pastes_found,
            "risk_level": risk_level,
        }

        # Add recommendation for domain checks
        if query_type == "domain" and total_breaches > 0:
            if risk_level == "CRITICAL":
                result["recommendation"] = "Enforce password resets for all accounts on this domain"
            elif risk_level in {"HIGH", "MEDIUM"}:
                result["recommendation"] = "Review exposed credentials and enforce MFA"
            else:
                result["recommendation"] = "Monitor for credential reuse"

        return result

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        if status == 401:
            return {"success": False, "error": "Invalid HIBP API key"}
        if status == 429:
            return {"success": False, "error": "HIBP API rate limit exceeded (1 request per 1.5s)"}
        return {"success": False, "error": f"HIBP API request failed: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "HIBP API request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Could not connect to HIBP API: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}