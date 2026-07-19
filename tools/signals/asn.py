def asn_extractor(result , signals):
    # asn_tool returns {ip, asn, org, isp, country, region, city} — it does
    # NOT carry an abuse score. The abuse confidence score comes from the
    # AbuseIPDB-backed ip_reputation tool and is populated by
    # ip_reputation_extractor. The previous abuse_score lookup here was
    # dead code: it always fell through to the `0` default, which silently
    # zeroed out signals["ip_abuse_score"] (see PR #84 for the regression
    # and the follow-up PR that moved the assignment to ip_reputation).
    if not result.get("success"):
        return
