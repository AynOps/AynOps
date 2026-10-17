# `asn_lookup`

## Overview

`asn_lookup` asks Team Cymru's IP-to-ASN mapping service which Autonomous
System a domain or IP address belongs to, and returns the BGP prefix, the
registry that allocated the block, and the AS organization name. The query is a
plain WHOIS request over TCP port 43; it is not an HTTP API and it needs no
credentials.

## Purpose and common use cases

Use this tool to answer "who actually hosts this?" during the attribution half
of a recon pass:

- Map a resolved IP to its hosting provider or ISP (`AS13335` → Cloudflare).
- Group several hosts under one network owner without resolving every one of
  them.
- Record the BGP prefix and the allocation date, so a finding can be quoted
  with the responsible network rather than a bare address.
- Compare with `whois_lookup`, which returns registration data for a *domain*;
  this tool works for the *address* the domain points at, and accepts IPv6.

## Parameters

The MCP tool exposes one required input:

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | string | Yes | A domain name, an IPv4 address, an IPv6 address, or a URL. |

Input handling, in order:

1. Surrounding whitespace is stripped.
2. If the value contains `://`, the host is taken from the URL (`netloc`, falling
   back to the path when there is no netloc).
3. If the value contains exactly one colon and does not start with `[`, the part
   after the last colon is dropped when it is all digits — so `example.com:443`
   queries `example.com`. IPv6 addresses are left intact.
4. If the value parses as an IP address it is used directly; otherwise it is
   resolved with `socket.getaddrinfo`, and the **first** returned address is
   queried.

There is no separate host/port parameter and no validation of the domain shape:
an unresolvable name fails at resolution rather than at validation.

## Optional parameters

None.

## Example MCP request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "asn_lookup",
    "arguments": {
      "target": "8.8.8.8"
    }
  }
}
```

## Example successful response

Captured from a live call; `asn_lookup("8.8.8.8")`:

```json
{
  "success": true,
  "ip": "8.8.8.8",
  "asn": "AS15169",
  "bgp_prefix": "8.8.8.0/24",
  "country": "US",
  "registry": "arin",
  "allocated": "2023-12-28",
  "organization": "GOOGLE - Google LLC, US"
}
```

A URL input is accepted too; `asn_lookup("https://example.com:443")` resolves
the host and returns the address it resolved to:

```json
{
  "success": true,
  "ip": "2606:4700:10::6814:179a",
  "asn": "AS13335",
  "bgp_prefix": "2606:4700:10::/44",
  "country": "US",
  "registry": "arin",
  "allocated": "2011-11-01",
  "organization": "CLOUDFLARENET - Cloudflare, Inc., US"
}
```

## Response field descriptions

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` when a data line was parsed out of the WHOIS reply. |
| `ip` | string | The address that was actually queried: the input when it was an IP, otherwise the first address `getaddrinfo` returned. |
| `asn` | string | Autonomous System number with the `AS` prefix, e.g. `AS15169`. Team Cymru returns the bare number and the tool normalizes it. |
| `bgp_prefix` | string | The BGP prefix the address is announced in, e.g. `8.8.8.0/24`. |
| `country` | string | Two-letter country code of the registering organization. |
| `registry` | string | Registry that allocated the block (`arin`, `ripencc`, `apnic`, `lacnic`, `afrinic`, …), as reported upstream. |
| `allocated` | string | Allocation date as `YYYY-MM-DD`. |
| `organization` | string | AS name, e.g. `GOOGLE - Google LLC, US`. Non-ASCII characters are replaced rather than raising a decode error. |

The response is the verbose Team Cymru form, whose reply begins with a header
line (`AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name`). The tool
skips the header and every blank line, then takes the **first** row whose first
field is numeric.

## Errors and timeouts

Failures return `success: false` plus an `error` string:

| Situation | Response |
|---|---|
| The hostname cannot be resolved (`socket.gaierror`) | `{"success": false, "error": "Failed to resolve domain"}` |
| The WHOIS socket times out | `{"success": false, "error": "Team Cymru WHOIS request timed out"}` |
| Connection refused or closed (`ConnectionError`, `OSError`) | `{"success": false, "error": "Could not connect to Team Cymru WHOIS service: <detail>"}` |
| Empty reply, header-only reply, or no numeric AS field | `{"success": false, "error": "Unexpected or malformed response from Team Cymru WHOIS"}` |
| Anything else | `{"success": false, "error": "<exception message>"}` |

The socket is opened with a 15-second timeout, which covers connecting and every
subsequent read. There are no retries, and no second DNS answer is tried when the
first one fails: `getaddrinfo` returns a list and only its first entry is used.

## Notes and limitations

- The tool needs outbound TCP port 43. Networks that only allow HTTP(S) egress
  will see the "Could not connect" error rather than a result.
- Private and reserved addresses are answered by Team Cymru with `NA` in the AS
  field, which fails the numeric check, so `asn_lookup("10.0.0.1")` reports the
  malformed-response error rather than "no ASN". Verified against
  `10.0.0.1` and `192.168.1.1`.
- The answer describes the AS that announces the address, not the owner of the
  domain, the hosting plan, or the data center. A CDN in front of a site means
  the ASN belongs to the CDN.
- The `allocated` date and the `bgp_prefix` describe the block, so two addresses
  in the same block return the same values.
- Because a domain is resolved locally first, this tool discloses the query to
  the local resolver and to Team Cymru; it is not a passive lookup in the way
  `whois_lookup` is.

## API key requirements

None required.

## Related tools

`ip_reputation` scores the address that this tool attributes to a network, and
`whois_lookup` returns registration data for the domain that resolved to it.
`full_recon` calls `asn_lookup` as one of its stages. See the
[tools index](README.md) for the current registration inventory and
documentation status.
