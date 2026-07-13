def cve_extractor(result , signals):
    if result.get("success"):
        cve_list = result.get("cves") or result.get("data", {}).get("cves", [])
        for entry in cve_list:
            cve_id   = entry.get("id") or entry.get("cve_id", "")
            cvss     = entry.get("cvss") or entry.get("cvss_score", 0)
            summary  = entry.get("summary") or entry.get("description", "")
            if cve_id:
                signals["cves_found"].append({
                    "id":      cve_id,
                    "cvss":    cvss,
                    "summary": str(summary)[:120],
                })

        critical_cves = [c for c in signals["cves_found"] if float(c.get("cvss") or 0) >= 9.0]
        high_cves     = [c for c in signals["cves_found"] if 7.0 <= float(c.get("cvss") or 0) < 9.0]
        if critical_cves:
            ids = ", ".join(c["id"] for c in critical_cves[:3])
            signals["auto_warnings"].append(
                f"CRITICAL CVEs detected: {ids} (CVSS ≥ 9.0) — immediately exploitable"
            )
        elif high_cves:
            ids = ", ".join(c["id"] for c in high_cves[:3])
            signals["auto_warnings"].append(
                f"High-severity CVEs detected: {ids} (CVSS 7–9) — patch urgently"
            )
    else:
        return