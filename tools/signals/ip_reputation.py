def ip_reputation_extractor(result , signals):
    if result.get("success"):
        flagged    = result.get("is_malicious")
        rep_score  = result.get("abuse_confidence_score")
        signals["ip_reputation_flagged"] = flagged
        try:
            rep_score = int(rep_score)
        except (TypeError, ValueError):
            rep_score = 0
        if flagged:
            signals["auto_warnings"].append(
                f"IP flagged as MALICIOUS "
                f"— hosting may be blacklisted by mail servers and firewalls"
            )
        elif rep_score > 20:
            signals["auto_warnings"].append(
                f"IP reputation score {rep_score} — elevated risk, monitor closely"
            )
    else:
        return

def extract_ip(results: dict) -> str | None:
    """
    Extract IP address from results using multiple fallbacks.
    Priority: ASN result → DNS A record → None
    """
    asn = results.get("asn")
    if asn.get("success"):
        ip = asn.get("ip")
        if ip:
            return str(ip).strip()

    dns = results.get("dns", {})
    if dns.get("success"):
        a_records = dns.get("records", {}).get("A", [])
        if a_records:
            return str(a_records[0]).strip()

    return None