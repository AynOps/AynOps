def dns_extractor(result , signals):
    if result.get("success"):
        records = result.get("records", {})
        missing_dns = []

        # Check for core operational routing records
        if not records.get("A") and not records.get("AAAA"):
            missing_dns.append("A/AAAA")
            signals["auto_warnings"].append(
                "No A or AAAA records found — domain may not resolve to an active web server."
            )

        # Check if the domain is missing mail routing capabilities entirely
        if not records.get("MX"):
            missing_dns.append("MX")
            signals["auto_warnings"].append(
                "Missing MX records — this domain cannot natively receive email traffic safely."
            )

        # Log tracked structural gaps (excluding email security features handled by wave 1/3)
        signals["dns_missing_records"] = missing_dns

    else:
        return