import requests
from utils.helpers import get_cvss_details, get_english_description
from packaging.version import Version, InvalidVersion


def _query_nvd(keyword: str) -> list:
    """Query the NVD CVE API by keyword and return the raw vulnerabilities list.

    The NVD API defaults to ``resultsPerPage=2000`` per response, which covers
    all but the most extreme cases (e.g. a bare product name with thousands of
    historical CVEs). We rely on that default page size here; introducing
    multi-page pagination without an API key would risk hitting NVD's public
    rate limit (5 requests / 30s).
    """
    response = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": keyword},
        timeout=60,
        headers={"User-Agent": "CyberSecurity-MCP-Server/1.0"},
    )
    response.raise_for_status()
    data = response.json()
    return data.get("vulnerabilities", [])


def _simplify_cve(item: dict) -> dict:
    """Convert a raw NVD vulnerability item into the simplified CVE dict."""
    cve = item.get("cve", {})
    cvss = get_cvss_details(cve)
    return {
        "cve_id": cve.get("id"),
        "severity": cvss["severity"],
        "score": cvss["score"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": get_english_description(cve),
    }


def _criteria_matches_software(criteria: str, software: str) -> bool:
    """Return whether a CPE criteria string refers to the requested software.

    CPE 2.3 (formatted string): ``cpe:2.3:<type>:<vendor>:<product>:<version>:...``
    CPE 2.2 (URI style):        ``cpe:/<type>:<vendor>:<product>:<version>:...``

    The match is case-insensitive on either the vendor or the product field
    (e.g. ``software="apache"`` matches ``cpe:2.3:a:apache:http_server:...``).
    A ``*`` wildcard in either field matches any software.
    """
    if not criteria or not software:
        return False
    parts = criteria.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor, product = parts[3], parts[4]
    elif len(parts) >= 4 and parts[0] == "cpe" and parts[1].startswith("/"):
        vendor, product = parts[2], parts[3]
    else:
        return False
    sw_lower = software.strip().lower()
    for field in (vendor, product):
        field_lower = field.strip().lower()
        if field_lower == "*" or field_lower == sw_lower:
            return True
    return False


def _version_in_range(target: Version, match: dict) -> bool:
    """Check whether the target version falls within the CPE match constraints.

    Returns ``False`` when none of the four boundary fields are present, since
    without explicit version constraints we cannot reliably determine whether
    the target version is affected. This avoids treating a constraint-less
    vulnerable CPE (e.g. an OS-level CPE attached to an application CVE) as
    affecting every version of the requested software.
    """
    try:
        start_including = match.get("versionStartIncluding")
        start_excluding = match.get("versionStartExcluding")
        end_including = match.get("versionEndIncluding")
        end_excluding = match.get("versionEndExcluding")
        if not (start_including or start_excluding or end_including or end_excluding):
            return False
        if start_including and target < Version(start_including):
            return False
        if start_excluding and target <= Version(start_excluding):
            return False
        if end_including and target > Version(end_including):
            return False
        if end_excluding and target >= Version(end_excluding):
            return False
        return True
    except InvalidVersion:
        # If any constraint version is unparseable, skip this match.
        return False


def _cve_affects_version(cve: dict, target: Version, software: str) -> bool:
    """Check whether a CVE's CPE version ranges include the target version.

    Returns ``True`` only when the CVE has at least one vulnerable cpeMatch
    entry whose:
      - ``criteria`` refers to the requested software (vendor/product match), AND
      - version constraints include the target version.

    Configuration nodes are traversed recursively so that nested ``children``
    nodes (used by NVD for AND/OR compositions) are handled correctly. CVEs
    without structured ``configurations``, or whose cpeMatch entries do not
    satisfy both conditions above, are excluded.
    """
    def _node_matches(node: dict) -> bool:
        for match in node.get("cpeMatch") or []:
            if not match.get("vulnerable", False):
                continue
            if not _criteria_matches_software(match.get("criteria", ""), software):
                continue
            if _version_in_range(target, match):
                return True
        for child in node.get("children") or []:
            if _node_matches(child):
                return True
        return False

    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            if _node_matches(node):
                return True
    return False


def cve_lookup(software: str, version: str) -> dict:
    """
    Look up known CVEs for a software name and version using the NVD API.

    Uses a 2-stage keyword search with version-based filtering applied to
    both stages:
      - Stage 1: keyword search with "<software> <version>".
      - Stage 2 (fallback when Stage 1 yields no version-matching CVEs):
        broader keyword search with just "<software>".

    In both stages, each CVE is kept only if it has a vulnerable cpeMatch
    entry whose CPE criteria refers to the requested software and whose
    version constraints include the supplied version. ``version_filtering_applied``
    is therefore ``True`` on every successful response.
    """
    software = software.strip()
    version = version.strip()

    if not software or not version:
        return {"success": False, "error": "Software and version are required"}

    try:
        target = Version(version)
    except InvalidVersion:
        return {
            "success": False,
            "error": (
                f"Invalid version format: '{version}'. "
                "Could not parse as a semantic version (PEP 440)."
            ),
        }

    try:
        # Stage 1: search with software + version, then filter.
        items = _query_nvd(f"{software} {version}")
        filtered = [
            item for item in items
            if _cve_affects_version(item.get("cve", {}), target, software)
        ]
        if filtered:
            return {
                "success": True,
                "software": software,
                "version": version,
                "total_results": len(filtered),
                "cves": [_simplify_cve(item) for item in filtered],
                "version_filtering_applied": True,
            }
        # Stage 2: broader query + version filtering.
        items = _query_nvd(software)
        filtered = [
            item for item in items
            if _cve_affects_version(item.get("cve", {}), target, software)
        ]
        return {
            "success": True,
            "software": software,
            "version": version,
            "total_results": len(filtered),
            "cves": [_simplify_cve(item) for item in filtered],
            "version_filtering_applied": True,
        }

    except requests.exceptions.HTTPError as e:
        return {"success": False, "error": f"NVD API request failed: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "NVD API request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Could not connect to NVD API: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
