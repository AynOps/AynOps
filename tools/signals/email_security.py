def email_security_extractor(result , signals):
    if result.get("success"):
        spf   = result.get("spf")
        dkim  = result.get("dkim")
        dmarc = result.get("dmarc")

        spf_found   = spf.get("found", False)
        dkim_found  = dkim.get("found", False)
        dmarc_found = dmarc.get("found", False)

        spf_policy  = spf.get("policy", "none")
        dmarc_policy = dmarc.get("policy", "none")

        signals["email_security"] = {
            "security_score": result.get("security_score"),
            "rating":         result.get("rating"),
            "spf_found":      spf_found,
            "spf_policy":     spf_policy,
            "dkim_found":     dkim_found,
            "dmarc_found":    dmarc_found,
            "dmarc_policy":   dmarc_policy,
            "recommendations": result.get("recommendations", []),
        }

        if not spf_found and not dmarc_found:
            signals["auto_warnings"].append(
                "No SPF and no DMARC configured — trivial email spoofing, any attacker can "
                "send mail appearing to come from this domain"
            )

        elif not spf_found:
            signals["auto_warnings"].append(
                "SPF missing — senders cannot be validated, enables phishing from this domain"
            )
            
        elif spf_policy in ("neutral", "pass", "+all"):
            signals["auto_warnings"].append(
                f"SPF policy is '{spf_policy}' — provides no real protection; use '-all'"
            )

        if not dkim_found:
            signals["auto_warnings"].append(
                "DKIM not detected on any common selector — email integrity cannot be verified"
            )

        if not dmarc_found:
            signals["auto_warnings"].append(
                "DMARC missing — receiving mail servers have no policy for handling spoofed mail"
            )
        elif dmarc_policy == "none":
            signals["auto_warnings"].append(
                "DMARC policy is 'none' — monitoring only, spoofed mail is still delivered"
            )

    else:
        return