# `tech_stack_detect`

## Overview

`tech_stack_detect` fetches a website and identifies technologies from HTTP
headers, names of cookies set by the response, HTML generator metadata, and
HTML/asset-path signatures. It returns grouped detections with confidence and
evidence, plus the observed fingerprint artefacts. No API key is required.

## Purpose and common use cases

Use it to inventory externally visible web technologies, identify CMS and
framework hints, and collect evidence for defensive attack-surface reviews.
It also runs in wave 2 of `full_recon`; its signal extractor forwards detected
names to `software_detected` without a confidence threshold.

## Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | Yes | Domain name, for example `example.com`. Supply a domain rather than a URL, path, or host with a port. |

The shared normalizer trims surrounding whitespace, lowercases the value, and
removes trailing dots before domain validation. Invalid domains are rejected
before any HTTP request.

## Optional parameters

None. Scheme selection, timeout, redirects, user agent, and body limit are
implementation settings, not tool arguments.

## Example MCP request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "tech_stack_detect",
    "arguments": {"domain": "example.com"}
  }
}
```

## Example successful response

This is an illustrative tool-result payload, not the JSON-RPC/MCP response
envelope or a claim about the live technologies at `example.com`. It represents
a response with `Server: nginx/1.18`, no cookies, and no matching HTML markers.

```json
{
  "success": true,
  "domain": "example.com",
  "url": "https://example.com/",
  "status_code": 200,
  "technologies": {
    "web_servers": [
      {"name": "nginx", "confidence": 95, "evidence": ["server: nginx/1.18"]}
    ]
  },
  "fingerprints": {
    "headers": {"server": "nginx/1.18"},
    "cookies": [],
    "meta_tags": {}
  }
}
```

## Response field descriptions

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` when fetching, reading, and fingerprinting complete; does not certify an HTTP 2xx response or an accurate/complete inventory. |
| `domain` | string | Normalized input domain. |
| `url` | string | Final response URL after redirects; may differ from the input domain or use HTTP. |
| `status_code` | integer | Final HTTP status, including non-2xx statuses. |
| `technologies` | object | Detected technologies grouped into the categories below. Categories with no matches are omitted; no matches produces `{}`. |
| `fingerprints` | object | Observed response headers, cookie names, and generator metadata. |

### Technology categories

| Key | Examples |
|---|---|
| `web_servers` | nginx, Apache, IIS, Caddy |
| `programming_languages` | PHP, Python, Ruby, Java, ASP.NET |
| `cms` | WordPress, Drupal, Joomla, Shopify |
| `frameworks` | React, Vue.js, Angular, Next.js |
| `hosting_providers` | Cloudflare, Fastly, Vercel, Netlify |
| `analytics` | Google Analytics, Google Tag Manager, Hotjar |

Each category contains an array of objects:

| Field | Type | Description |
|---|---|---|
| `name` | string | Technology name from the signature tables. |
| `confidence` | integer | Signature-assigned score on a 0–100 scale. The maximum matching score is used, not the sum; this is a heuristic, not a calibrated probability. |
| `evidence` | array of strings | Matching header observations, cookie names, generator values, or HTML markers. Duplicate evidence strings are removed while preserving order. |

Matching is case-insensitive. Header-value markers search across response
header values, cookie markers match name prefixes, and HTML markers use
substring matching. Technology and category order follow the signature tables.

### Fingerprint artefacts

| Field | Type | Description |
|---|---|---|
| `headers` | object | Final response headers with lowercased keys and original values. These are not restricted to headers that matched signatures. |
| `cookies` | array of strings | Cookie names extracted from the final response's `Set-Cookie` headers; preserves case and does not contain cookie values. |
| `meta_tags` | object | Contains `generator` when a supported quoted HTML generator tag is found, otherwise `{}`. |

Although `cookies` contains names only, `headers` can include `set-cookie` and
other response values. Review these raw artefacts before sharing reports.

## Errors and timeouts

Failures return `{"success": false, "error": "<reason>"}` without the success
payload's other fields.

| Situation | Error / behavior |
|---|---|
| Invalid domain | `Invalid domain format`; no request. |
| SSL or connection error while fetching HTTPS (including `ConnectTimeout`) | Retries using HTTP. `ConnectTimeout` also inherits from `Timeout`, but the earlier `ConnectionError` handler takes precedence. |
| Both schemes fail | Last error: `SSL error: <details>` or `Could not connect to the domain`. |
| Fetch raises `ReadTimeout` or another `Timeout` that is not a `ConnectionError` | `Request timed out`; no HTTP retry for this exception handler. |
| Excessive redirects | `Too many redirects`; no HTTP retry. |
| Other fetch exception or failure while reading the body/cookie names | Exception message in `error`; no HTTP fallback for body-reading failures. |
| Fingerprint engine raises | `Fingerprinting error: <details>`. |
| HTTP 4xx/5xx response | Still fingerprinted; can return `success: true` with that status code. |

Requests use `timeout=10`, `allow_redirects=True`, streaming, and
`User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)`. The timeout is a
Requests connection/read timeout, not a ten-second deadline for the entire
operation: redirects, fallback, and continued body reads can extend elapsed
time. Body-read exceptions use the generic exception-message path. The response
is closed after the body/cookie-reading stage, including when that stage fails.

## Notes and limitations

- HTTPS is tried first. An SSL or connection failure can downgrade the scan to
  unencrypted HTTP; inspect `url` before interpreting the evidence.
- Redirects are followed, but only the final response is fingerprinted. A
  redirect may lead to a different host; the original input stays in `domain`.
- At most **512,000 bytes (500 KiB)** from `iter_content` are passed to the
  engine, decoded as UTF-8 with replacement for invalid sequences. This caps
  the body processed for detection, not all network traffic; markers beyond
  the cap are missed. Truncation is not reported in the result.
- No browser executes JavaScript, no linked assets are fetched for analysis,
  and the tool does not crawl other pages. Dynamic or hidden technologies may
  go undetected.
- Matches are signature-based hints. Spoofed banners, substring collisions,
  proxies, and WAF/block/error pages can cause misleading or missing matches.
- An empty `technologies` object does not establish that a site has no stack.
  An HTTP error page may still expose signatures.
- Generator parsing recognizes specific quoted meta-tag patterns rather than
  using a full HTML parser. Version text can appear in evidence/artefacts, but
  there is no structured version field or vulnerability lookup in this tool.
- Security-header assessment belongs to `headers_analyzer`; this tool does not
  produce a security score, rating, or missing-header assessment.
- Network access to the target and any redirect destinations is required.

## API key requirements

None required.

## Related tools

`headers_analyzer` evaluates HTTP security headers, `trace_redirects` inspects
redirect chains, `cve_lookup` searches known vulnerabilities for separately
identified software/version inputs, and `full_recon` combines reconnaissance
signals. See the [tools index](README.md) for documentation availability.
