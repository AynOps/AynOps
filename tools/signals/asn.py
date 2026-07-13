def asn_extractor(result , signals):
    if result.get("success"):
        score = result.get("abuse_score") or result.get("data", {}).get("abuse_score", 0)
        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0
        signals["ip_abuse_score"] = score
        if score > 50:
            signals["auto_warnings"].append(
                f"ASN abuse score {score}/100 — HIGH malicious activity reported on this IP range"
            )
        elif score > 20:
            signals["auto_warnings"].append(
                f"ASN abuse score {score}/100 — elevated, investigate hosting provider"
            )

    else:
        return