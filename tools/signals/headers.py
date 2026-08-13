def _final_hop_status(result):
    """The status code of the response headers_analyzer analysed, or None.

    headers_analyzer does not surface the status at the top level; the last
    entry of ``redirect_chain`` is the hop whose headers became the
    analysis.
    """
    chain = result.get("redirect_chain")

    if not isinstance(chain, list) or not chain:
        return None

    final_hop = chain[-1]

    if not isinstance(final_hop, dict):
        return None

    status = final_hop.get("status_code")

    if isinstance(status, bool) or not isinstance(status, int):
        return None

    return status


def headers_extractor(result, signals):
    """Populate the security-header signal from a headers_analyzer result.

    headers_analyzer reports every checked header as
    ``{"present": bool, "value": ..., "issue": ..., "severity": ...}``;
    the ones it marks absent are what `missing_security_headers` means.
    Information-disclosure headers (``server``, ``x_powered_by``, …) only
    appear when they ARE present, so they never enter the missing list.

    A result that did not reach real page content is insufficient data, not
    a hardening finding: headers_analyzer happily analyses whatever the
    final hop returned, and an error, maintenance or bot-block page carries
    its own (usually bare) headers, which say nothing about the site. Unless
    the analysed hop answered 2xx, the signal is left at its default so the
    prompt's "Insufficient data" rule applies instead.
    """
    if not result.get("success"):
        return

    status = _final_hop_status(result)

    if status is None or not 200 <= status < 300:
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
