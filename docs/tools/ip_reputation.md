# `ip_reputation`

## Overview

`ip_reputation` queries AbuseIPDB for reports about an IP address and returns
abuse-report metadata with a reputation classification. It requires the
`ABUSEIPDB_API_KEY` environment variable.

## Purpose and common use cases

Use this tool to inspect an address's abuse confidence score, report counts,
whitelist and Tor status, and associated network metadata. The reputation and
`is_malicious` fields summarize these signals for investigation and triage.

## Parameters

The MCP tool exposes one required input:

| Name | Type | Required | Description |
|---|---|---|---|
| `ip_address` | string | Yes | An IPv4 or IPv6 address to query. Surrounding whitespace is stripped and the address is normalized using Python's `ipaddress` library. |

Validation uses `str(ipaddress.ip_address(ip_address.strip()))`. Malformed
addresses are rejected before the API key is checked. Private and reserved
addresses are accepted locally; any parseable address is sent to AbuseIPDB
when an API key is configured.

## Optional parameters

None.

## Example MCP request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "ip_reputation",
    "arguments": {
      "ip_address": "192.0.2.1"
    }
  }
}
```

## Example successful response

The values below are illustrative; AbuseIPDB supplies the report data and
network metadata, and some fields may be unavailable.

```json
{
  "success": true,
  "ip": "192.0.2.1",
  "ip_version": 4,
  "is_malicious": true,
  "is_whitelisted": false,
  "is_public": true,
  "is_tor": false,
  "reputation": "high-risk",
  "num_distinct_users": 0,
  "abuse_confidence_score": 95,
  "total_reports": 342,
  "country": "CN",
  "isp": "Example ISP",
  "domain": "example.net",
  "hostnames": null,
  "usage_type": "Data Center/Web Hosting/Transit",
  "last_reported_at": "2026-05-01T00:00:00+00:00"
}
```

## Response field descriptions

On success, the response contains `success: true` and the following fields:

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` for a completed AbuseIPDB lookup. |
| `ip` | string | Normalized input address, rather than the API's `ipAddress` value. |
| `ip_version` | integer or null | The API's `ipVersion` value, when supplied. |
| `is_malicious` | boolean | `true` exactly when `reputation` is `high-risk` or `suspicious`. |
| `is_whitelisted` | boolean | Boolean conversion of the API's `isWhitelisted` value; absent or null values become `false`. |
| `is_public` | boolean | Boolean conversion of the API's `isPublic` value; absent or null values become `false`. |
| `is_tor` | boolean | Boolean conversion of the API's `isTor` value; absent or null values become `false`. |
| `reputation` | string | `trusted`, `high-risk`, `suspicious`, `low-risk`, or `clean`, using the rules below. |
| `num_distinct_users` | integer | The API's `numDistinctUsers` value; absent or null values become `0`. |
| `abuse_confidence_score` | integer or null | The API's `abuseConfidenceScore` value; defaults to `0` when absent. An explicit null is not replaced. |
| `total_reports` | integer or null | The API's `totalReports` value; defaults to `0` when absent. An explicit null is not replaced. |
| `country` | string or null | Country code from the API's `countryCode` value. |
| `isp` | string or null | ISP returned by AbuseIPDB. |
| `domain` | string or null | Domain returned by AbuseIPDB. |
| `hostnames` | list of strings or null | Hostnames returned by AbuseIPDB. |
| `usage_type` | string or null | Usage classification from the API's `usageType` value. |
| `last_reported_at` | string or null | Last report timestamp from the API's `lastReportedAt` value, returned without reformatting. |

Classification evaluates these rules in order and uses the first match:

1. Whitelisted: `trusted`, regardless of score or Tor status.
2. Abuse confidence score at least 75: `high-risk`, including Tor addresses.
3. Tor address: `suspicious`.
4. Abuse confidence score at least 25: `suspicious`.
5. Abuse confidence score greater than 0: `low-risk`.
6. Otherwise: `clean`.

A non-whitelisted Tor exit node therefore reports `is_malicious: true` even
at score 0. A whitelisted IP is never marked malicious.

## Errors and timeouts

Failure responses contain `success: false` and an `error` string instead of
the successful fields:

| Situation | Response |
|---|---|
| Input fails IP address validation | `{"success": false, "error": "Invalid IP address format"}` |
| Valid address but no API key configured | `{"success": false, "error": "ABUSEIPDB_API_KEY environment variable is required"}` |
| The API request raises `HTTPError` | `{"success": false, "error": "AbuseIPDB API request failed: <exception message>"}` |
| The API request raises `requests.Timeout` | `{"success": false, "error": "AbuseIPDB API request timed out"}` |
| Any other `RequestException` | `{"success": false, "error": "Could not connect to AbuseIPDB API: <exception message>"}` |
| Any other exception during the API request or response processing | `{"success": false, "error": "<exception message>"}` |

The tool sends a GET request to `https://api.abuseipdb.com/api/v2/check`
with the normalized `ipAddress`, a fixed `maxAgeInDays=90`, and a 15-second
request timeout. The report window and timeout are not configurable inputs.

## Notes and limitations

- IPv4 and IPv6 are accepted. Normalization strips surrounding whitespace
  and uses `ipaddress`'s string representation, including compressed,
  lowercase IPv6 notation.
- The lookup needs network access to AbuseIPDB and sends the normalized
  address to that service, including private or reserved addresses.
- Reputation reflects AbuseIPDB data and the classification rules above.
  The score check for `high-risk` runs before the Tor check; whitelisting
  takes priority over both.
- API-sourced metadata can be `null`. Boolean flags are converted to
  booleans, and the numeric defaults are applied as described above.
- An explicit null abuse confidence score can cause an error during
  classification for a non-whitelisted address.

## API key requirements

`ABUSEIPDB_API_KEY` is required. Obtain a free API key from
[abuseipdb.com](https://www.abuseipdb.com) and set it in the server's
environment. The key is checked after IP address validation.

## Related tools

`asn_lookup`, `dns_enumeration`, and `full_recon` provide related
network-ownership, DNS, and combined-reconnaissance views. See the [tools index](README.md)
for the current registration inventory and documentation status.
