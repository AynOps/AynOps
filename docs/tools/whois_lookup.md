# `whois_lookup`

## Overview

`whois_lookup` queries domain-registration data through the WHOIS service and
returns the fields that the upstream WHOIS response provides. It does not
require an API key.

## Purpose and common use cases

Use this tool to inspect registration metadata such as the registrar, registry
dates, name servers, registration status, and the organization associated with
a domain. WHOIS responses vary by registry, so some fields may be unavailable.

## Parameters

The MCP tool exposes one required input:

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | Yes | A fully qualified domain name to query. IP addresses, `localhost`, bare labels, and malformed domain names are rejected. |

Validation requires at least one dot, labels of at most 63 characters, a total
length of at most 253 characters, and a final label consisting entirely of at
least two ASCII letters. Each non-final label may contain letters, digits, and
internal hyphens, but may not start or end with a hyphen.

## Optional parameters

None.

## Example MCP request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "whois_lookup",
    "arguments": {
      "domain": "example.com"
    }
  }
}
```

## Example successful response

The values below are illustrative; registries and registrars can omit fields
or return more than one value for a field.

```json
{
  "success": true,
  "domain": "example.com",
  "registrar": "Example Registrar LLC",
  "registrar_url": "https://registrar.example",
  "whois_server": "whois.example",
  "creation_date": "2010-01-01 00:00:00",
  "expiration_date": "2030-01-01 00:00:00",
  "updated_date": "2023-06-15 00:00:00",
  "name_servers": [
    "ns1.example.com",
    "ns2.example.com"
  ],
  "status": "clientTransferProhibited",
  "emails": "admin@example.com",
  "dnssec": "unsigned",
  "country": "US",
  "org": "Example Organization"
}
```

## Response field descriptions

On success, the response contains `success: true` and the following fields:

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` for a completed WHOIS lookup. |
| `domain` | string, list of strings, or null | The `domain_name` value returned by the WHOIS library. A single parsed value remains a string; multiple values are returned as a list. |
| `registrar` | string or null | Registrar returned by the WHOIS response. |
| `registrar_url` | string, list of strings, or null | Registrar URL, when supplied. A single parsed value is a string; repeated upstream values are returned as a list. |
| `whois_server` | string or null | WHOIS server returned by the response. |
| `creation_date` | string, list of strings, or null | Creation date. Date objects are converted to strings; multiple values are returned as a list. |
| `expiration_date` | string, list of strings, or null | Expiration date, with the same conversion and list behavior as `creation_date`. |
| `updated_date` | string, list of strings, or null | Last-updated date, with the same conversion and list behavior as `creation_date`. |
| `name_servers` | string, list of strings, or null | Name-server values. A single value is a string; multiple values are a list. |
| `status` | string, list of strings, or null | Registration status values. A single value is a string; multiple values are a list. |
| `emails` | string, list of strings, or null | Contact email values. A single value is a string; multiple values are a list. |
| `dnssec` | string, list of strings, or null | DNSSEC status, when supplied. A single parsed value is a string; repeated values are a list. |
| `country` | string, list of strings, or null | Registrant country, when supplied. A single parsed value is a string; repeated values are a list. |
| `org` | string, list of strings, or null | Registrant organization, when supplied. A single parsed value is a string; repeated values are a list. |

The successful `domain` field comes from the WHOIS response and is not a copy
of the normalized input. The date fields are stringified for JSON output; the
exact date text and format depend on the registry response.

## Errors and timeouts

Failure responses contain `success: false` and an `error` string instead of
the successful fields:

| Situation | Response |
|---|---|
| Input fails normalization or validation | `{"success": false, "error": "Invalid domain format"}` |
| The WHOIS request raises a socket timeout or `TimeoutError` | `{"success": false, "error": "WHOIS lookup timed out after 10 seconds"}` |
| Any other exception | `{"success": false, "error": "<exception message>"}` |

The WHOIS request is made with a 10-second timeout. Other service or parser
failures are returned using the underlying exception message.

## Notes and limitations

- Before validation, the server strips surrounding whitespace, converts the
  value to lowercase, and removes trailing dots.
- The lookup needs network access to the relevant WHOIS service.
- Field availability and formatting vary between registries and registrars;
  missing values are returned as `null`.
- A field with one parsed value is a scalar string, while repeated values are
  returned as a list of strings.
- The validator accepts domain names only; IP address lookups are not part of
  this tool's input contract.

## API key requirements

None required.

## Related tools

`dns_enumeration`, `asn_lookup`, and `full_recon` provide related DNS,
network-ownership, and combined-reconnaissance views. See the [tools index](README.md)
for the current registration inventory and documentation status.
