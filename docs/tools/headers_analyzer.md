# `headers_analyzer`

## Overview

`headers_analyzer` fetches a domain over HTTPS, follows redirects manually,
and evaluates HTTP security-header values with per-header severity ratings.
It returns the final response's analysis and each visited response's raw
headers and analysis. No API key is required.

## Purpose and common use cases

Use this tool to review missing or misconfigured web security headers,
identify technology-disclosure headers, and compare header configuration
between redirect responses and the final destination.

## Parameters

The MCP tool exposes one required input:

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | Yes | A fully qualified domain name, for example `example.com`. URLs, paths, ports, IP addresses, `localhost`, and bare labels are rejected. |

Before validation, the shared normalizer strips surrounding whitespace,
lowercases the value, and removes trailing dots. Validation requires at least
one dot, labels of at most 63 characters, a total length of at most 253
characters, and a final label of at least two ASCII letters. Other labels
may contain letters, digits, and internal hyphens, but cannot start or end
with a hyphen.

## Optional parameters

None. The starting scheme, timeout, redirect limit, and browser impersonation
are fixed implementation settings, not tool arguments.

## Example MCP request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "headers_analyzer",
    "arguments": {"domain": "example.com"}
  }
}
```

## Example successful response

This is an illustrative tool-result payload, not the JSON-RPC/MCP response
envelope or a live observation of `example.com`. It represents one response
with the seven raw headers shown below and no redirects.

```json
{
  "success": true,
  "domain": "example.com",
  "requested_url": "https://example.com",
  "final_url": "https://example.com",
  "redirected": false,
  "redirect_chain": [
    {
      "url": "https://example.com",
      "status_code": 200,
      "headers": {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=()",
        "server": "nginx"
      },
      "analysis": {
        "strict-transport-security": {"present": true, "value": "max-age=31536000; includeSubDomains", "issue": "None", "severity": "low"},
        "content-security-policy": {"present": true, "value": "default-src 'self'", "issue": "None", "severity": "low"},
        "x-frame-options": {"present": true, "value": "DENY", "issue": "None", "severity": "low"},
        "x-content-type-options": {"present": true, "value": "nosniff", "issue": "None", "severity": "low"},
        "referrer-policy": {"present": true, "value": "strict-origin-when-cross-origin", "issue": "None", "severity": "low"},
        "permissions-policy": {"present": true, "value": "camera=(), microphone=()", "issue": "None", "severity": "low"},
        "server": {"present": true, "value": "nginx", "issue": "server header exposes technology information", "severity": "low"}
      }
    }
  ],
  "headers": {
    "strict-transport-security": {"present": true, "value": "max-age=31536000; includeSubDomains", "issue": "None", "severity": "low"},
    "content-security-policy": {"present": true, "value": "default-src 'self'", "issue": "None", "severity": "low"},
    "x-frame-options": {"present": true, "value": "DENY", "issue": "None", "severity": "low"},
    "x-content-type-options": {"present": true, "value": "nosniff", "issue": "None", "severity": "low"},
    "referrer-policy": {"present": true, "value": "strict-origin-when-cross-origin", "issue": "None", "severity": "low"},
    "permissions-policy": {"present": true, "value": "camera=(), microphone=()", "issue": "None", "severity": "low"},
    "server": {"present": true, "value": "nginx", "issue": "server header exposes technology information", "severity": "low"}
  }
}
```

## Response field descriptions

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` when fetching and analysis complete; does not mean the site is secure or the HTTP status is 2xx. |
| `domain` | string | Authority component of the final URL, obtained by splitting the URL at `/`. It may differ from the input domain and can include a port after a redirect. |
| `requested_url` | string | Starting URL: `https://` followed by the normalized input domain. |
| `final_url` | string | Last URL visited by the manual redirect walker. |
| `redirected` | boolean | Whether more than one response was captured. |
| `redirect_chain` | array of objects | Every captured response, including the final response. A non-redirected success still contains one entry. |
| `headers` | object | Final response's header analysis; identical to the last `redirect_chain` entry's `analysis`. |

Each `redirect_chain` entry contains:

| Field | Type | Description |
|---|---|---|
| `url` | string | URL requested for this hop. |
| `status_code` | integer | HTTP response status for this hop. |
| `headers` | object | Raw response header values with lowercased names, including headers outside the analysis rules. Duplicate names are combined into comma-joined values by the HTTP client. |
| `analysis` | object | The same header checks used for the final response, applied to this hop. Response bodies are not included. |

Both the top-level `headers` and each hop's `analysis` map lowercased header
names to objects with these fields:

| Field | Type | Description |
|---|---|---|
| `present` | boolean | Whether the check found a non-empty value. For `x-content-type-options`, only a value matching `nosniff` after trimming and lowercasing produces `true`; another non-empty value produces `false`. |
| `value` | string | Observed value or `""` when absent. CSP values longer than 200 characters and Permissions-Policy values longer than 100 characters are shortened to those lengths plus `...`; checks use the full values. Raw hop headers retain the full values. |
| `issue` | string | Finding text, with multiple findings joined by `; `. The string `"None"` means no issue was flagged; it is not JSON `null`. |
| `severity` | string | `low`, `medium`, or `high` according to the rules below. There is no aggregate score or overall rating. |

### Header checks

The six security-header entries are always included, even when absent.

| Header | Implemented checks |
|---|---|
| `strict-transport-security` | Missing header, missing `max-age=`, or a non-positive parsed max-age: `high`. A positive max-age below 31,536,000 seconds, an unparseable max-age, or missing `includeSubDomains`: at least `medium`. Otherwise `low`. |
| `content-security-policy` | Missing header: `high`. Falls back to `content-security-policy-report-only` when enforcing CSP is empty or absent, storing that value under `content-security-policy`. Quoted `unsafe-inline` or `unsafe-eval`, or a standalone `*` source token in `default-src` or `script-src`: `high`. Lacking both literal substrings `default-src 'self'` and `default-src 'none'`, or report-only mode: at least `medium`. Otherwise `low`. |
| `x-frame-options` | Trimmed, case-insensitive `DENY` or `SAMEORIGIN`: `low`. Missing or any other value: `medium`. |
| `x-content-type-options` | Trimmed, case-insensitive `nosniff`: `low`. Missing or any other value: `medium`. |
| `referrer-policy` | Uses the last recognized policy in a comma-separated list, or the last token when none is recognized. `no-referrer`, `strict-origin-when-cross-origin`, `same-origin`, and `strict-origin`: `low`. Other non-empty values: `medium`. Missing: `low` with an issue message. |
| `permissions-policy` | Case-insensitive literal matches for `camera=*`, `microphone=*`, `geolocation=*`, `payment=*`, or `usb=*`: `medium`. Other present values: `low`. Missing: `low` with an issue message. |

`server`, `x-powered-by`, `x-aspnet-version`, and `x-generator` are included
only when non-empty, each with `present: true`, its observed value, a
technology-disclosure issue, and `severity: "low"`.

## Errors and timeouts

Handled failures return `{"success": false, "error": "<reason>"}` without the
successful response fields:

| Situation | Error / behavior |
|---|---|
| Invalid domain | `Invalid domain format`; no request. |
| Redirect walker returns no responses | `No response received`. |
| Last captured status is 301, 302, 303, 307, or 308 | Error beginning `Could not reach final page content -- redirect chain did not resolve`, including the captured hop count, final status, and 8-hop limit. Applies to loops, the cap, and redirects without a `Location` header; the message names only loops or exceeding the limit as possible causes. |
| Final response matches a supported WAF challenge/block signature | Error beginning `Received a bot-detection challenge/block page instead of the real site`, naming Cloudflare, Imperva, or Akamai. No analysis is returned. |
| `curl_cffi` `RequestsError` during fetching, including request timeouts | `Connection failed: <exception message>`. There is no separate timeout-specific response. |
| Other exception inside the fetching/WAF-check block | The exception message. Normalization, validation, and subsequent header analysis are outside this block. |
| Other HTTP 4xx/5xx responses | Analyzed normally when they do not match a block signature; can return `success: true`. |

Each GET uses `timeout=10`, `impersonate="chrome"`, and
`allow_redirects=False`. Redirects cause additional GETs with the same timeout;
the tool has no separate overall deadline. HTTPS failures do not trigger an
HTTP fallback or retry.

## Notes and limitations

- Redirects follow only 301, 302, 303, 307, and 308 with a `Location` header.
  Relative locations are resolved against the current URL. Revisited URLs
  stop the walk, and at most eight responses are captured, including the
  initial response. A redirect at the cap returns a failure.
- Redirects can change the host, port, or scheme, including to HTTP. Only the
  initial input is domain-validated; inspect `final_url` and `redirect_chain`
  when interpreting the result.
- Every hop uses the same rules. Missing content-related headers on a bare
  redirect response are findings about that response, not necessarily the
  final page's configuration.
- WAF detection examines only the final response. It matches
  `cf-mitigated: challenge` case-insensitively, or, on statuses of at least
  400, `_incapsula_resource` in the body (Imperva) or both `access denied`
  and `reference #` (Akamai). Body matching is case-insensitive and
  signature-based; it cannot identify every block page.
- GET responses include bodies for WAF detection, with no explicit body-size
  cap in this tool. Bodies are omitted from the public result. Raw hop
  headers can contain `set-cookie` or other sensitive response values;
  review them before sharing results.
- These are fixed string and token checks, not a full policy parser or
  browser enforcement test. For example, Permissions-Policy wildcard
  matching requires the literal `feature=*` spelling. A `low` severity or
  `issue: "None"` does not establish that a policy is secure.
- Cross-Origin-Opener-Policy (COOP), Cross-Origin-Embedder-Policy (COEP), and
  Cross-Origin-Resource-Policy (CORP) are not evaluated. They can still appear
  in a hop's raw headers.
- Network access to the target and redirect destinations is required.

## API key requirements

None required.

## Related tools

`tech_stack_detect` identifies web technologies, `ssl_inspect` inspects TLS
and certificates, and `trace_redirects` provides a dedicated redirect-chain
view. `full_recon` includes header analysis with other reconnaissance tools.
See the [tools index](README.md) for documentation availability.
