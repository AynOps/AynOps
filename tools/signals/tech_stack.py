"""tech_stack signal extractor.

Reads the structured technologies dict produced by tech_stack_detect
(issue #130 schema: each category value is a list of
``{"name": ..., "confidence": ..., "evidence": [...]}`` dicts) and
populates the shared signals dict.

All detections are forwarded to ``software_detected`` regardless of
confidence score — the confidence data is already visible to downstream
consumers via the raw ``technologies`` field in the tool output.
"""

from __future__ import annotations


def techstack_extractor(result: dict, signals: dict) -> None:
    """Populate ``software_detected`` from a tech_stack_detect result."""
    if not result.get("success"):
        return

    technologies = result.get("technologies")
    if not isinstance(technologies, dict):
        return

    for category_detections in technologies.values():
        if not isinstance(category_detections, list):
            continue
        for det in category_detections:
            # new schema: each element is a dict with a "name" key
            if isinstance(det, dict):
                name = det.get("name", "")
            else:
                # defensive fallback for unexpected shapes
                name = str(det)

            name = str(name).strip()
            if name and name not in ("Unknown", "None", ""):
                signals["software_detected"].append(name)
