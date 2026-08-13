def headers_extractor(result, signals):
    """Populate the security-header signal from a headers_analyzer result.

    headers_analyzer reports every checked header as
    ``{"present": bool, "value": ..., "issue": ..., "severity": ...}``;
    the ones it marks absent are what `missing_security_headers` means.
    Information-disclosure headers (``server``, ``x_powered_by``, …) only
    appear when they ARE present, so they never enter the missing list.
    """
    if not result.get("success"):
        return

    headers = result.get("headers")

    if not isinstance(headers, dict):
        return

    missing = [
        name
        for name, analysis in headers.items()
        if isinstance(analysis, dict) and not analysis.get("present")
    ]

    signals["missing_security_headers"] = missing

    if len(missing) >= 4:
        signals["auto_warnings"].append(
            f"{len(missing)} security headers missing ({', '.join(missing)}) — significant hardening gap"
        )

    elif len(missing) >= 2:
        signals["auto_warnings"].append(
            f"{len(missing)} security headers missing: {', '.join(missing)}"
        )
