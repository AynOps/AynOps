# `whois_lookup`

Domain registration data lookup via the public WHOIS protocol (python-whois).

## Purpose and common use cases

- Identify the registrant organization and registrar for a domain
- Check creation / expiration / update dates
- Enumerate name servers and registration status
- Support triage during reconnaissance (asset ownership, domain age, potential takeover targets)

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | string | Yes | Domain to look up, e.g. `example.com` |

No optional parameters.

## Example MCP request

```json
{
  "tool": "whois_lookup",
  "arguments": {
    "domain": "example.com"
  }
}
```

## Example successful response

```json
{
  "success": true,
  "domain": "EXAMPLE.COM",
  "registrar": "Example Registrar, Inc.",
  "registrar_url": "http://www.example-registrar.com",
  "whois_server": "whois.example-registrar.com",
  "creation_date": "1995-08-14 04:00:00",
  "expiration_date": "2030-08-13 04:00:00",
  "updated_date": "2024-01-01 12:00:00",
  "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
  "status": ["clientDeleteProhibited", "clientTransferProhibited"],
  "emails": ["abuse@example-registrar.com"],
  "dnssec": "signedDelegation",
  "country": "US",
  "org": "Example Organization"
}
```

## Response field descriptions

| Field | Description |
|-------|-------------|
| `success` | Whether the lookup completed |
| `domain` | Normalized domain name |
| `registrar` / `registrar_url` | Registrar identity and homepage |
| `whois_server` | WHOIS server that served the record |
| `creation_date` / `expiration_date` / `updated_date` | Registration lifecycle dates (strings, may be lists) |
| `name_servers` | List of authoritative name servers |
| `status` | Registration status codes (e.g. clientTransferProhibited) |
| `emails` | Registrar/abuse contact emails |
| `dnssec` | DNSSEC delegation status if published |
| `country` / `org` | Registrant country and organization |

## Errors and timeouts

- Invalid domain format → `{"success": false, "error": "Invalid domain format"}`
- WHOIS server timeout (10s) → `{"success": false, "error": "WHOIS lookup timed out ..."}`
- Unregistered / unavailable domains may return partial or null fields

## Notes and limitations

- Results depend on the upstream WHOIS server; some registries redact registrant data (GDPR)
- `creation_date` / `expiration_date` may be lists when multiple records exist; they are serialized to strings
- Lookup is public — no API key required

## API key requirements

None.

## Related tools

- `dns_enumeration` — DNS records for the same domain
- `asn_lookup` — network ownership for the domain's IPs
- `cert_transparency` — certificate subdomain discovery
