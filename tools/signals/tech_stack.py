def techstack_extractor(result, signals):
    if not result.get("success"):
        return

    technologies = result.get("technologies")

    if not isinstance(technologies, dict):
        return

    for tech in technologies.values():
        if tech and str(tech).strip() not in ("Unknown", "None", ""):
            signals["software_detected"].append(str(tech).strip())

    if not result.get("success"):
        return

    status_code = result.get("status_code")
    headers_data = result.get("security_headers")

    if status_code >= 400 or not headers_data:
        signals["missing_security_headers"] = []
        return

    missing = headers_data.get("missing")

    signals["missing_security_headers"] = missing

    if len(missing) >= 4:
        signals["auto_warnings"].append(
            f"{len(missing)} security headers missing ({', '.join(missing)}) — significant hardening gap"
        )
        
    elif len(missing) >= 2:
        signals["auto_warnings"].append(
            f"{len(missing)} security headers missing: {', '.join(missing)}"
        )
    