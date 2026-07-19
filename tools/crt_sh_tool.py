from curl_cffi import requests
from curl_cffi.requests.errors import RequestsError
from typing import Any

from utils.helpers import is_valid_domain


def cert_transparency(domain: str) -> dict[str, Any]:
    """Search crt.sh Certificate Transparency logs only.

    This tool intentionally does not fall back to passive DNS sources.
    When crt.sh is unavailable, it returns a clear failure so callers do
    not confuse CT results with unrelated subdomain discovery data.
    """
    domain = domain.strip().lower()

    if not is_valid_domain(domain):
        return {
            "success": False,
            "error": "Invalid domain format",
        }

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    try:
        response = requests.get(url, headers=headers, timeout=50)
        response.raise_for_status()
        data = response.json()

        unique_subdomains = set()
        wildcards = set()
        certificates = []
        seen = set()

        for entry in data:
            issuer = entry.get("issuer_name", "Unknown")
            not_before = entry.get("not_before", "").split("T")[0]
            not_after = entry.get("not_after", "").split("T")[0]
            names = entry.get("name_value", "").split("\n")

            for name in names:
                name = name.strip().lower()

                if not name:
                    continue

                if name.startswith("*."):
                    wildcard_pattern = name[1:]  # "*.example.com" -> ".example.com"
                    if wildcard_pattern.endswith("." + domain) or wildcard_pattern == "." + domain:
                        wildcards.add(wildcard_pattern)
                    continue

                if not name.endswith(domain) or name == domain:
                    continue

                unique_subdomains.add(name)
                cert_key = (name, issuer, not_before, not_after)

                if cert_key in seen:
                    continue
                seen.add(cert_key)

                certificates.append(
                    {
                        "subdomain": name,
                        "issuer": issuer,
                        "not_before": not_before,
                        "not_after": not_after,
                    }
                )

        return {
            "success": True,
            "source": "crt.sh",
            "domain": domain,
            "total_certificates": len(certificates),
            "total_unique_subdomains": len(unique_subdomains),
            "unique_subdomains": sorted(unique_subdomains),
            "wildcards_found": sorted(wildcards),
            "returned_certificates": min(50, len(certificates)),
            "truncated": len(certificates) > 50,
            "certificates": certificates[:50],
        }

    except (RequestsError, ValueError, Exception):
        return {
            "success": False,
            "domain": domain,
            "error": "Certificate Transparency lookup failed.",
        }
