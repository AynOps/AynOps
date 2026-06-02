import re

def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None

def get_cvss_details(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    metric_groups = (
        metrics.get("cvssMetricV31")
        or metrics.get("cvssMetricV30")
        or metrics.get("cvssMetricV2")
        or []
    )

    if not metric_groups:
        return {"severity": "Unknown", "score": None}

    metric = metric_groups[0]
    cvss_data = metric.get("cvssData", {})

    return {
        "severity": metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "Unknown",
        "score": cvss_data.get("baseScore"),
    }

def get_english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])
    english = next((item for item in descriptions if item.get("lang") == "en"), None)
    return english.get("value", "") if english else ""