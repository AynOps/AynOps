import os
import re

import requests

from utils.helpers import is_valid_domain

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_USER_AGENT = "AynOps-MCP-Server"
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _risk_level(total_breaches: int) -> str:
    if total_breaches <= 0:
        return "NONE"
    if total_breaches <= 2:
        return "LOW"
    if total_breaches <= 5:
        return "MEDIUM"
    if total_breaches <= 10:
        return "HIGH"
    return "CRITICAL"


def _detect_query_type(query: str) -> str | None:
    q = query.strip()
    if not q:
        return None
    if _EMAIL_PATTERN.fullmatch(q):
        return "email"
    if is_valid_domain(q):
        return "domain"
    return None


def _normalize_breach(item: dict) -> dict:
    return {
        "name": item.get("Name") or item.get("Title") or "Unknown",
        "breach_date": item.get("BreachDate"),
        "pwn_count": item.get("PwnCount"),
        "data_exposed": item.get("DataClasses") or [],
        "description": item.get("Description") or "",
    }


def hibp_check(query: str) -> dict:
    """Check if an email or domain appears in Have I Been Pwned breach data.

    Requires HIBP_API_KEY in the environment.
    """
    query = (query or "").strip()
    query_type = _detect_query_type(query)
    if query_type is None:
        return {
            "success": False,
            "error": "Invalid input. Provide an email address or domain name.",
        }

    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "HIBP_API_KEY environment variable is required",
        }

    headers = {
        "hibp-api-key": api_key,
        "user-agent": HIBP_USER_AGENT,
        "accept": "application/json",
    }

    try:
        if query_type == "email":
            url = f"{HIBP_API_BASE}/breachedaccount/{requests.utils.quote(query)}"
            params = {"truncateResponse": "false"}
            response = requests.get(url, headers=headers, params=params, timeout=20)

            if response.status_code == 404:
                return {
                    "success": True,
                    "query": query,
                    "type": "email",
                    "breached": False,
                    "total_breaches": 0,
                    "breaches": [],
                    "pastes_found": 0,
                    "risk_level": "NONE",
                }

            response.raise_for_status()
            breaches_raw = response.json() or []
            breaches = [_normalize_breach(b) for b in breaches_raw]
            total = len(breaches)

            pastes_found = 0
            try:
                paste_url = f"{HIBP_API_BASE}/pasteaccount/{requests.utils.quote(query)}"
                paste_resp = requests.get(paste_url, headers=headers, timeout=20)
                if paste_resp.status_code == 200:
                    pastes = paste_resp.json() or []
                    pastes_found = len(pastes)
                elif paste_resp.status_code not in (404, 401, 403):
                    paste_resp.raise_for_status()
            except requests.RequestException:
                # Paste lookup is supplemental; breach data remains useful alone.
                pastes_found = 0

            return {
                "success": True,
                "query": query,
                "type": "email",
                "breached": total > 0,
                "total_breaches": total,
                "breaches": breaches,
                "pastes_found": pastes_found,
                "risk_level": _risk_level(total),
            }

        # domain mode
        url = f"{HIBP_API_BASE}/breaches"
        params = {"domain": query}
        response = requests.get(url, headers=headers, params=params, timeout=20)
        response.raise_for_status()
        breaches_raw = response.json() or []
        breaches = [_normalize_breach(b) for b in breaches_raw]
        total = len(breaches)
        risk = _risk_level(total)
        result = {
            "success": True,
            "query": query,
            "type": "domain",
            "breached": total > 0,
            "total_breaches": total,
            "breaches": breaches,
            "risk_level": risk,
        }
        if total > 0:
            result["recommendation"] = (
                "Enforce password resets for all accounts on this domain"
            )
        return result

    except requests.exceptions.HTTPError as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status == 401:
            return {"success": False, "error": "HIBP API key is invalid or unauthorized"}
        if status == 429:
            return {
                "success": False,
                "error": "HIBP rate limit exceeded. Retry after a short delay.",
            }
        return {"success": False, "error": f"HIBP API request failed: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "HIBP API request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Could not connect to HIBP API: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
