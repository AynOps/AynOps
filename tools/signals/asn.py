def asn_extractor(result, signals):
    """Populate ASN metadata signals from a successful asn_tool result.

    The asn_tool result does NOT carry an abuse score. Abuse confidence comes
    from the AbuseIPDB-backed ip_reputation tool and is populated by
    ip_reputation_extractor. This extractor only surfaces ASN ownership /
    network context for the threat-analysis prompt.
    """
    if not result.get("success"):
        return

    asn = result.get("asn")
    if asn:
        signals["asn_number"] = str(asn).strip()

    # Prefer modern Team Cymru field names; keep legacy org/isp aliases.
    org = result.get("organization") or result.get("org")
    if org:
        signals["asn_org"] = str(org).strip()

    ip = result.get("ip")
    if ip:
        signals["asn_ip"] = str(ip).strip()

    country = result.get("country")
    if country:
        signals["asn_country"] = str(country).strip()
