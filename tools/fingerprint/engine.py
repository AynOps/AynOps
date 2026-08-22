"""Technology fingerprinting engine.

Pure and I/O-free: it is handed an already-fetched response's headers and body
and returns the technologies it recognises. Fetching, error handling and
response assembly stay with the calling tool.

Detection is organised as independent layers, each contributing its own keys to
one shared result map. Adding a layer (cookies, <meta name="generator">, asset
URLs) means adding a table to signatures.py, a layer function here, and one
line in fingerprint().
"""

from tools.fingerprint.signatures import (
    ANALYTICS_SIGNATURES,
    CDN_SIGNATURES,
    CMS_SIGNATURES,
    JS_SIGNATURES,
)


def _matching(signatures: dict, predicate) -> list:
    """Names from a signature table whose markers satisfy ``predicate``.

    Table order is preserved, which is what makes the tool's output order
    stable.
    """
    return [
        name for name, markers in signatures.items()
        if any(predicate(marker) for marker in markers)
    ]


def headers_layer(raw_headers) -> dict:
    """Technologies identifiable from response headers alone.

    ``raw_headers`` is any mapping of header name to value; names are compared
    case-insensitively, values are passed through unchanged.
    """
    headers = {k.lower(): v for k, v in raw_headers.items()}
    found = {}

    if "server" in headers:
        found["web_server"] = headers["server"]

    if "x-powered-by" in headers:
        found["powered_by"] = headers["x-powered-by"]

    cdns = _matching(CDN_SIGNATURES, lambda header: header in headers)
    if cdns:
        found["cdn"] = cdns

    return found


def html_layer(raw_text: str) -> dict:
    """Technologies identifiable from the response body alone.

    Markers are matched as plain substrings against a lowercased copy of the
    body, so the body may be passed in as received.
    """
    html = raw_text.lower()
    found = {}

    cms = _matching(CMS_SIGNATURES, lambda sig: sig in html)
    if cms:
        found["cms"] = cms

    frameworks = _matching(JS_SIGNATURES, lambda sig: sig in html)
    if frameworks:
        found["javascript_frameworks"] = frameworks

    analytics = _matching(ANALYTICS_SIGNATURES, lambda sig: sig in html)
    if analytics:
        found["analytics"] = analytics

    return found


def fingerprint(raw_headers, raw_text: str) -> dict:
    """Identify the technologies behind one HTTP response.

    Takes the raw headers mapping and raw body text; each layer normalises what
    it needs. Categories that match nothing are omitted rather than reported
    empty, so an unrecognised page yields ``{}``.
    """
    technologies = headers_layer(raw_headers)
    technologies.update(html_layer(raw_text))
    return technologies
