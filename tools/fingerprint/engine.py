"""Technology fingerprinting engine.

Pure and I/O-free: it is handed an already-fetched response's headers,
cookie names, and body text; it returns the technologies it recognises in
the structured confidence/evidence schema agreed in issue #130.

Detection is organised as four independent layers:

1. ``headers_layer``  — HTTP response headers  (names and values)
2. ``cookies_layer``  — Set-Cookie cookie names
3. ``meta_layer``     — ``<meta name="generator">`` tag in the HTML body
4. ``html_layer``     — arbitrary HTML substrings and asset paths

Adding a new layer means: adding a table to signatures.py, a layer function
here, and one line in ``fingerprint()``.

Output schema
-------------
``fingerprint()`` returns two dicts:

*technologies* — grouped by category, each value a list of detection dicts::

    {
        "web_servers": [
            {"name": "nginx", "confidence": 95,
             "evidence": ["Server header: nginx/1.18"]}
        ],
        "cms": [
            {"name": "WordPress", "confidence": 95,
             "evidence": ["wp-content path", "wp-json path"]}
        ],
        ...
    }

  Categories that have no detections are omitted.

*fingerprints* — raw artefacts extracted during detection::

    {
        "headers":   {"server": "nginx/1.18", ...},
        "cookies":   ["phpsessid"],
        "meta_tags": {"generator": "WordPress 6.4"}
    }
"""

from __future__ import annotations

import re
from typing import TypedDict

from tools.fingerprint.signatures import (
    ANALYTICS_SIGNATURES,
    CDN_SIGNATURES,
    CMS_SIGNATURES,
    JS_FRAMEWORK_SIGNATURES,
    LANGUAGE_SIGNATURES,
    WEB_SERVER_SIGNATURES,
)

# ------------------------------------------------------------------
# Internal types
# ------------------------------------------------------------------

class _Detection(TypedDict):
    name: str
    confidence: int
    evidence: list[str]


# Map from signature-dict → category key in the output schema
_SIGNATURE_CATEGORIES: list[tuple[dict, str]] = [
    (WEB_SERVER_SIGNATURES,   "web_servers"),
    (LANGUAGE_SIGNATURES,     "programming_languages"),
    (CMS_SIGNATURES,          "cms"),
    (JS_FRAMEWORK_SIGNATURES, "frameworks"),
    (CDN_SIGNATURES,          "hosting_providers"),
    (ANALYTICS_SIGNATURES,    "analytics"),
]

_META_GENERATOR_RE = re.compile(
    r'<meta\s[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_META_GENERATOR_ALT_RE = re.compile(
    r'<meta\s[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']',
    re.IGNORECASE,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _extract_meta_tags(raw_html: str) -> dict[str, str]:
    """Return a dict of notable meta tag values found in the HTML."""
    meta: dict[str, str] = {}
    m = _META_GENERATOR_RE.search(raw_html) or _META_GENERATOR_ALT_RE.search(raw_html)
    if m:
        meta["generator"] = m.group(1).strip()
    return meta


def _match_signatures(
    sig_table: dict[str, list[tuple[str, str, int]]],
    *,
    headers: dict[str, str],
    header_raw: dict[str, str],
    cookies: list[str],
    meta_tags: dict[str, str],
    html: str,
) -> list[_Detection]:
    """Run one signature table against all four input sources.

    Returns a list of detections, one per matched technology.
    """
    detections: list[_Detection] = []

    for tech_name, markers in sig_table.items():
        best_confidence = 0
        evidence: list[str] = []

        for marker_type, marker_value, confidence in markers:
            mv_lower = marker_value.lower()

            if marker_type == "header_name":
                if mv_lower in headers:
                    best_confidence = max(best_confidence, confidence)
                    evidence.append(f"{marker_value} header present")

            elif marker_type == "header_value":
                # check every header value for the substring
                for hname, hval in headers.items():
                    if mv_lower in hval.lower():
                        best_confidence = max(best_confidence, confidence)
                        # report the raw header name + value for clarity
                        raw_val = header_raw.get(hname, hval)
                        evidence.append(f"{hname}: {raw_val}")
                        break

            elif marker_type == "cookie_name":
                for cookie in cookies:
                    if cookie.lower().startswith(mv_lower):
                        best_confidence = max(best_confidence, confidence)
                        evidence.append(f"cookie: {cookie}")
                        break

            elif marker_type == "meta_generator":
                generator = meta_tags.get("generator", "").lower()
                if generator and mv_lower in generator:
                    best_confidence = max(best_confidence, confidence)
                    evidence.append(f"<meta generator>: {meta_tags['generator']}")

            elif marker_type == "html_substring":
                if mv_lower in html:
                    best_confidence = max(best_confidence, confidence)
                    evidence.append(marker_value)

        if best_confidence > 0:
            # deduplicate evidence strings while preserving order
            seen: set[str] = set()
            unique_evidence: list[str] = []
            for e in evidence:
                if e not in seen:
                    seen.add(e)
                    unique_evidence.append(e)
            detections.append(
                _Detection(
                    name=tech_name,
                    confidence=best_confidence,
                    evidence=unique_evidence,
                )
            )

    return detections


# ------------------------------------------------------------------
# Layer functions (each is independently testable)
# ------------------------------------------------------------------

def headers_layer(
    raw_headers: dict[str, str],
) -> dict[str, list[_Detection]]:
    """Detect technologies from HTTP response headers alone.

    ``raw_headers`` is any mapping of header name → value.
    Names are compared case-insensitively; values are passed through unchanged.
    """
    headers_lower = {k.lower(): v for k, v in raw_headers.items()}
    result: dict[str, list[_Detection]] = {}
    for sig_table, category in _SIGNATURE_CATEGORIES:
        detections = _match_signatures(
            sig_table,
            headers=headers_lower,
            header_raw=raw_headers,
            cookies=[],
            meta_tags={},
            html="",
        )
        if detections:
            result[category] = detections
    return result


def cookies_layer(
    cookie_names: list[str],
) -> dict[str, list[_Detection]]:
    """Detect technologies from cookie names alone."""
    result: dict[str, list[_Detection]] = {}
    for sig_table, category in _SIGNATURE_CATEGORIES:
        detections = _match_signatures(
            sig_table,
            headers={},
            header_raw={},
            cookies=cookie_names,
            meta_tags={},
            html="",
        )
        if detections:
            result[category] = detections
    return result


def meta_layer(raw_html: str) -> dict[str, list[_Detection]]:
    """Detect technologies from HTML meta tags alone."""
    meta_tags = _extract_meta_tags(raw_html)
    result: dict[str, list[_Detection]] = {}
    for sig_table, category in _SIGNATURE_CATEGORIES:
        detections = _match_signatures(
            sig_table,
            headers={},
            header_raw={},
            cookies=[],
            meta_tags=meta_tags,
            html="",
        )
        if detections:
            result[category] = detections
    return result


def html_layer(raw_html: str) -> dict[str, list[_Detection]]:
    """Detect technologies from HTML body substrings and asset paths."""
    html_lower = raw_html.lower()
    result: dict[str, list[_Detection]] = {}
    for sig_table, category in _SIGNATURE_CATEGORIES:
        detections = _match_signatures(
            sig_table,
            headers={},
            header_raw={},
            cookies=[],
            meta_tags={},
            html=html_lower,
        )
        if detections:
            result[category] = detections
    return result


# ------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------

def fingerprint(
    raw_headers: dict[str, str],
    raw_text: str,
    *,
    cookie_names: list[str] | None = None,
) -> tuple[dict[str, list[_Detection]], dict]:
    """Identify the technologies behind one HTTP response.

    Parameters
    ----------
    raw_headers:
        The response headers mapping (any case).
    raw_text:
        The response body (may be truncated by the caller).
    cookie_names:
        Names of cookies set by the response (from Set-Cookie headers).
        Optional; defaults to an empty list.

    Returns
    -------
    technologies:
        Dict grouped by category.  Each value is a list of detection dicts
        ``{"name": ..., "confidence": ..., "evidence": [...]}``.
        Categories with no detections are omitted.
    fingerprints:
        Raw artefacts extracted during detection:
        ``{"headers": {...}, "cookies": [...], "meta_tags": {...}}``.
    """
    if cookie_names is None:
        cookie_names = []

    headers_lower = {k.lower(): v for k, v in raw_headers.items()}
    meta_tags = _extract_meta_tags(raw_text)
    html_lower = raw_text.lower()

    # ── artefacts ────────────────────────────────────────────────────────────
    fp_artefacts: dict = {
        "headers":   headers_lower,
        "cookies":   cookie_names,
        "meta_tags": meta_tags,
    }

    # ── run all four layers, accumulate per-category ──────────────────────
    # We gather detections for every (category, tech_name) pair across layers
    # and merge them: evidence lists are unioned, confidence is the max.
    accumulated: dict[str, dict[str, _Detection]] = {}

    for sig_table, category in _SIGNATURE_CATEGORIES:
        layer_detections = _match_signatures(
            sig_table,
            headers=headers_lower,
            header_raw=raw_headers,
            cookies=cookie_names,
            meta_tags=meta_tags,
            html=html_lower,
        )
        if not layer_detections:
            continue

        cat_bucket = accumulated.setdefault(category, {})
        for det in layer_detections:
            name = det["name"]
            if name not in cat_bucket:
                cat_bucket[name] = _Detection(
                    name=name,
                    confidence=det["confidence"],
                    evidence=list(det["evidence"]),
                )
            else:
                existing = cat_bucket[name]
                existing["confidence"] = max(existing["confidence"], det["confidence"])
                seen = set(existing["evidence"])
                for ev in det["evidence"]:
                    if ev not in seen:
                        existing["evidence"].append(ev)
                        seen.add(ev)

    # ── build final output, preserving category order ─────────────────────
    technologies: dict[str, list[_Detection]] = {}
    for _, category in _SIGNATURE_CATEGORIES:
        if category in accumulated:
            technologies[category] = list(accumulated[category].values())

    return technologies, fp_artefacts
