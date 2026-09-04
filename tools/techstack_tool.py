"""tech_stack_detect tool.

Fetches one HTTP response (with HTTPS → HTTP fallback) and delegates all
technology detection to the fingerprinting engine.  This module owns:

* network I/O and error handling
* HTTPS → HTTP fallback
* response-body size cap (``MAX_BODY_BYTES``)
* cookie-name extraction from Set-Cookie headers
* assembling the final result dict

Everything else — what counts as a technology, how confidence is scored —
lives in ``tools/fingerprint/``.
"""

from __future__ import annotations

import re

import requests

from tools.fingerprint import fingerprint
from utils.helpers import is_valid_domain, normalize_domain

# Maximum bytes of response body fed to the fingerprint engine.
# Avoids wasting time on huge pages; most fingerprint signals appear
# in the first few kilobytes anyway.
MAX_BODY_BYTES: int = 512_000  # 500 KB

_SET_COOKIE_NAME_RE = re.compile(r'^([^=;,\s]+)')

_REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
}


def _extract_cookie_names(response: requests.Response) -> list[str]:
    """Return a list of cookie names set by the response."""
    names: list[str] = []
    for raw in response.raw.headers.getlist("Set-Cookie"):
        m = _SET_COOKIE_NAME_RE.match(raw.strip())
        if m:
            names.append(m.group(1))
    return names


def _fetch(url: str) -> requests.Response:
    """Perform a GET request and return the response object."""
    return requests.get(
        url,
        timeout=10,
        allow_redirects=True,
        headers=_REQUEST_HEADERS,
        stream=True,          # stream=True so we can cap the body size
    )


def _read_body(response: requests.Response) -> str:
    """Read at most ``MAX_BODY_BYTES`` of the response body."""
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        remaining = MAX_BODY_BYTES - total
        if len(chunk) >= remaining:
            chunks.append(chunk[:remaining])
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def tech_stack_detect(domain: str) -> dict:
    """Detect the technology stack of a website.

    Tries HTTPS first; falls back to HTTP if the HTTPS connection fails
    with an SSL or connection error.

    Returns
    -------
    On success::

        {
            "success":      True,
            "domain":       "example.com",
            "url":          "https://example.com",
            "status_code":  200,
            "technologies": {
                "web_servers": [{"name": "nginx", "confidence": 95,
                                 "evidence": ["Server header: nginx/1.18"]}],
                ...
            },
            "fingerprints": {
                "headers":   {"server": "nginx/1.18", ...},
                "cookies":   ["phpsessid"],
                "meta_tags": {"generator": "WordPress 6.4"},
            },
        }

    On failure::

        {"success": False, "error": "<reason>"}
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    resp = None
    last_error: str | None = None

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = _fetch(url)
            last_error = None
            break  # success — stop trying
        except requests.exceptions.SSLError as exc:
            last_error = f"SSL error: {exc}"
            # fall through to try http://
        except requests.exceptions.ConnectionError:
            last_error = "Could not connect to the domain"
            # fall through to try http://
        except requests.exceptions.Timeout:
            return {"success": False, "error": "Request timed out"}
        except requests.exceptions.TooManyRedirects:
            return {"success": False, "error": "Too many redirects"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": str(exc)}

    if resp is None:
        return {"success": False, "error": last_error or "Could not connect to the domain"}

    try:
        body = _read_body(resp)
        cookie_names = _extract_cookie_names(resp)
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}
    finally:
        resp.close()

    technologies, fp_artefacts = fingerprint(
        dict(resp.headers),
        body,
        cookie_names=cookie_names,
    )

    return {
        "success":      True,
        "domain":       domain,
        "url":          resp.url,
        "status_code":  resp.status_code,
        "technologies": technologies,
        "fingerprints": fp_artefacts,
    }
