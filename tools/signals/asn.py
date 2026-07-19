def asn_extractor(result, signals):
    if not result.get("success"):
        return

    signals["asn_number"] = result.get("asn")
    signals["asn_isp"] = result.get("isp")
