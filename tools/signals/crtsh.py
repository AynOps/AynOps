def crt_extractor(result , signals):
    if result.get("success"):
        count = result.get("total_unique_subdomains")
        signals["subdomain_count"] = count
        if count > 50:
            signals["auto_warnings"].append(
                f"Very large attack surface: {count} subdomains in CT logs"
            )
        elif count > 20:
            signals["auto_warnings"].append(
                f"Expanded attack surface: {count} subdomains found in CT logs"
            )
    else:
        return