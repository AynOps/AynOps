def ssl_extractor(result, signals):
    if not result.get("success"):
        return

    expiry = result.get("certificate", {}).get("days_until_expiry")
    if expiry is None:
        return

    signals["ssl_days_remaining"] = expiry

    if expiry < 0:
        signals["auto_warnings"].append(
            f"SSL certificate expired {abs(expiry)} days ago — all HTTPS traffic at risk"
        )
    elif expiry < 14:
        signals["auto_warnings"].append(
            f"SSL certificate expires in {expiry} days — CRITICAL, renew immediately"
        )
    elif expiry < 30:
        signals["auto_warnings"].append(
            f"SSL certificate expires in {expiry} days — HIGH priority renewal"
        )