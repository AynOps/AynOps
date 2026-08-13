def techstack_extractor(result, signals):
    if not result.get("success"):
        return

    technologies = result.get("technologies")

    if not isinstance(technologies, dict):
        return

    for tech in technologies.values():
        if isinstance(tech, list):
            for item in tech:
                if item and str(item).strip() not in ("Unknown", "None", ""):
                    signals["software_detected"].append(str(item).strip())
        elif tech and str(tech).strip() not in ("Unknown", "None", ""):
            signals["software_detected"].append(str(tech).strip())
