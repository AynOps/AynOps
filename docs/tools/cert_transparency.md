# `cert_transparency`

## Overview

`cert_transparency` queries crt.sh for Certificate Transparency data and returns
certificate entries, discovered names, wildcard patterns, and summary counts.
It is registered as a public MCP tool and does not require an API key.

The callable is:

```python
cert_transparency(domain: str)
```

The implementation normalizes and validates `domain` before requesting
`https://crt.sh/?q=%.{domain}&output=json`.

## Purpose and common use cases

Use this tool to discover names recorded in certificates, review certificate
issuers and validity dates, and identify wildcard patterns returned by crt.sh.
The lookup queries crt.sh rather than scanning the target hosts.

## Parameters

The MCP tool has one required parameter:

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `domain` | string | Yes | — | Domain to query, such as `example.com`. Surrounding whitespace and trailing dots are removed, and the value is lowercased before domain-format validation. |

## Optional parameters

There are no optional parameters. The request timeout and certificate return
limit are fixed by the implementation and cannot be configured through this
callable.

## Example MCP request

The public MCP registration uses the callable name and parameter name shown
in the signature:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "cert_transparency",
    "arguments": {
      "domain": "example.com"
    }
  }
}
```

This is a request shape example only; it does not perform a lookup here.

## Example successful response

The following is an illustrative response using the shape returned by the
focused mocked test suite. Values are examples, not the result of a live
query:

```json
{
  "success": true,
  "source": "crt.sh",
  "domain": "example.com",
  "total_certificates": 3,
  "total_unique_subdomains": 3,
  "unique_subdomains": [
    "api.example.com",
    "dev.example.com",
    "www.example.com"
  ],
  "wildcards_found": [".example.com"],
  "returned_certificates": 3,
  "truncated": false,
  "certificates": [
    {
      "subdomain": "api.example.com",
      "issuer": "Let's Encrypt",
      "not_before": "2026-01-01",
      "not_after": "2026-04-01"
    },
    {
      "subdomain": "dev.example.com",
      "issuer": "Let's Encrypt",
      "not_before": "2026-01-01",
      "not_after": "2026-04-01"
    },
    {
      "subdomain": "www.example.com",
      "issuer": "Let's Encrypt",
      "not_before": "2026-02-01",
      "not_after": "2026-05-01"
    }
  ]
}
```

## Response field descriptions

On success, the response contains `success: true` and these fields:

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` when the response was processed and the result was assembled. |
| `source` | string | Always `"crt.sh"` on success. |
| `domain` | string | The normalized domain used for the query. |
| `total_certificates` | integer | Number of deduplicated certificate entries before the return limit. Entries are unique by name, issuer, and the extracted validity dates; this is not a count of distinct certificates in the upstream logs. |
| `total_unique_subdomains` | integer | Number of distinct retained non-wildcard names before the certificate return limit. |
| `unique_subdomains` | array of strings | Sorted, deduplicated retained non-wildcard names. Names are stripped and lowercased; the queried domain itself is excluded. |
| `wildcards_found` | array of strings | Sorted, deduplicated matching wildcard patterns with the leading `*` removed, such as `.example.com` or `.api.example.com`. |
| `returned_certificates` | integer | Number of entries in `certificates`: the smaller of 50 and `total_certificates`. |
| `truncated` | boolean | `true` when `total_certificates` exceeds 50. |
| `certificates` | array of objects | The first 50 deduplicated certificate entries in upstream encounter order, or all entries when fewer are available. Can be empty. |

Each object in `certificates` contains:

| Field | Type | Description |
|---|---|---|
| `subdomain` | string | Retained non-wildcard name, stripped and lowercased. |
| `issuer` | string | Upstream `issuer_name`; defaults to `"Unknown"` when that key is absent. |
| `not_before` | string | Upstream `not_before` text before the first `T`, typically `YYYY-MM-DD`; defaults to an empty string when the key is absent. |
| `not_after` | string | Upstream `not_after` text before the first `T`, typically `YYYY-MM-DD`; defaults to an empty string when the key is absent. |

## Errors and timeouts

Failure responses contain `success: false` and an `error` string. The normal
failure shapes are:

| Situation | Response |
|---|---|
| Invalid domain format | `{"success": false, "error": "Invalid domain format"}` |
| `RequestsError`, including a request timeout | `{"success": false, "domain": "example.com", "error": "Network error: <message>"}` |
| `ValueError`, including invalid JSON | `{"success": false, "domain": "example.com", "error": "Invalid response data: <message>"}` |
| Any other unexpected exception during the lookup or response processing | `{"success": false, "domain": "example.com", "error": "Certificate Transparency lookup failed. Unexpected error: <type>: <message>"}` |

The invalid-domain response returns before any request and has no `domain`
key. The exception responses include the normalized `domain`.

The HTTP request uses a fixed timeout of 50 seconds. A timeout follows the
`Network error: ...` path; there is no separate timeout-specific response.
Non-2xx HTTP responses raise through `raise_for_status()` and follow the
`RequestsError` or unexpected-exception path according to the exception type.

## Notes and limitations

- Names are split on newlines, stripped, and lowercased. Empty names are skipped.
- Non-wildcard names are retained when they end with the normalized domain and
  differ from it. This is a string-suffix check without a dot-boundary check.
- Wildcard names are recorded separately when the pattern without its leading
  `*` equals `.` plus the domain or ends with `.` plus the domain. They are not
  added to `unique_subdomains` or `certificates`.
- Deduplication uses the name, issuer, and extracted validity dates. One
  upstream entry containing several names can produce several certificate
  entries, and one name can have several entries with different metadata.
- Only `certificates` is capped at 50. Counts and the sorted subdomain and
  wildcard lists are computed from the entire returned data before truncation.
- The tool returns crt.sh data without checking DNS resolution, host
  reachability, or whether a certificate is currently valid.
- No live crt.sh query is part of this documentation page or its verification.

## API key requirements

None required. The tool has no API-key parameter and sends its request to
crt.sh without an API key.

## Related tools

`dns_enumeration`, `ssl_inspect`, and `full_recon` are also registered MCP tools.
See the [tools index](README.md) for their documentation status and reference
pages.
