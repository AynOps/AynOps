# `dns_enumeration`

## Overview

`dns_enumeration` queries DNS records for a domain through the configured
public resolvers and returns the records, per-lookup errors, common service
records, common subdomains, and resolver metadata. It does not require an API
key.

## Purpose and common use cases

Use this tool to inspect a domain's core DNS configuration, including address,
mail, delegation, text, alias, authority, and certificate-authority records.
It also checks a fixed set of common enterprise SRV names and tries a built-in
list of common subdomain labels. This can help with reconnaissance, routing
and mail configuration checks, and identifying hosts that may need further
investigation.

## Parameters

The MCP tool exposes one required input:

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | Yes | A fully qualified domain name to query. IP addresses, `localhost`, bare labels, and malformed domain names are rejected. |

Before validation, the input is converted to a string, surrounding whitespace
is stripped, letters are lowercased, and a trailing dot is removed. Validation
requires at least one dot, labels of at most 63 characters, a total length of
at most 253 characters, and a final label consisting entirely of at least two
ASCII letters. Other labels may contain letters, digits, and internal hyphens,
but may not start or end with a hyphen.

## Optional parameters

None.

## Example MCP request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "dns_enumeration",
    "arguments": {
      "domain": "example.com"
    }
  }
}
```

## Example successful response

The values below are illustrative and use the response shape exercised by the
focused test suite. Empty lists mean that no record was returned for that
entry; an entry in an error map identifies a lookup that could not be
completed.

```json
{
  "success": true,
  "domain": "example.com",
  "errors": {
    "AAAA": "NoAnswer",
    "MX": "NoAnswer",
    "NS": "NoAnswer",
    "TXT": "NoAnswer",
    "CNAME": "NoAnswer",
    "SOA": "NoAnswer",
    "CAA": "NoAnswer"
  },
  "records": {
    "A": ["192.0.2.10"],
    "AAAA": [],
    "MX": [],
    "NS": [],
    "TXT": [],
    "CNAME": [],
    "SOA": [],
    "CAA": []
  },
  "srv_records": {
    "_sip._tcp": [
      {
        "priority": 10,
        "weight": 20,
        "port": 5060,
        "target": "sip.example.com"
      }
    ],
    "_ldap._tcp": [],
    "_xmpp-client._tcp": [],
    "_kerberos._tcp": [],
    "_autodiscover._tcp": []
  },
  "srv_errors": {},
  "subdomains_found": ["www.example.com"],
  "subdomain_errors": {},
  "ttl": {
    "A": 60
  },
  "resolver": {
    "nameservers": ["1.1.1.1", "8.8.8.8"],
    "timeout": 2.0,
    "lifetime": 5
  }
}
```

## Response field descriptions

On success, the response contains `success: true` and the following fields:

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` when the domain passed validation and enumeration completed, even if individual lookups recorded errors. |
| `domain` | string | The normalized input domain: surrounding whitespace removed, lowercased, and any trailing dot removed. |
| `errors` | object | Maps a target record type such as `A` or `TXT` to an error name. Anticipated lookup failures use the exception name; unexpected lookup failures are prefixed with `unexpected: `. |
| `records` | object | Contains `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, and `CAA` results. Missing record answers are represented by empty lists, while each successful record type uses the shape described below. |
| `srv_records` | object | Maps `_sip._tcp`, `_ldap._tcp`, `_xmpp-client._tcp`, `_kerberos._tcp`, and `_autodiscover._tcp` to SRV record lists. Each record has integer `priority`, `weight`, and `port` fields plus a cleaned `target`; an unpublished service has an empty list. |
| `srv_errors` | object | Maps a service name to its lookup error when an SRV lookup fails with an anticipated or unexpected error. `NoAnswer` and `NXDOMAIN` are treated as an unpublished service and are not added here. |
| `subdomains_found` | array of strings | Common `label.domain` names for which an `A`, `AAAA`, or `CNAME` lookup resolved. Each candidate is added at most once. |
| `subdomain_errors` | object | Maps a candidate hostname to a record-type map for unexpected subdomain lookup errors. Expected negative lookup results are ignored, and a later successful record lookup removes the candidate's error entry. |
| `ttl` | object | Maps a successfully parsed target record type to its TTL when the resolver answer provides one. Types without an available TTL are omitted. |
| `resolver` | object | Reports the resolver configuration used: public `nameservers`, a `timeout` of 2.0 seconds, and a `lifetime` of 5 seconds. |

The `records` object uses these per-type shapes:

| Record type | Value shape and description |
|---|---|
| `A`, `AAAA` | Array of strings containing the record values. |
| `MX` | Array of objects with integer `preference` and cleaned string `exchange` fields. |
| `NS`, `CNAME` | Array of names with trailing dots removed. |
| `TXT` | Array of strings formed by concatenating each record's text chunks. UTF-8 decoding failures leave the list empty and record `UnicodeDecodeError` in `errors`. |
| `SOA` | An object with cleaned `mname` and `rname` strings plus integer `serial`, `refresh`, `retry`, `expire`, and `minimum` fields. |
| `CAA` | Array of objects with `flags`, `tag`, and `value` fields. When a CAA object does not expose `tag` or `value`, the formatter returns a `raw` string instead. |

## Errors and timeouts

Failure responses contain `success: false` and an `error` string instead of
the successful fields:

| Situation | Response |
|---|---|
| Input fails normalization or validation | `{"success": false, "error": "Invalid domain format"}` |
| The target-domain lookup raises `NXDOMAIN` | `{"success": false, "error": "Domain <normalized-domain> does not exist"}` |
| A target record lookup raises `NoAnswer`, `NoNameservers`, `YXDOMAIN`, or a resolver timeout | The record list is empty and `errors[record_type]` contains the raised exception's class name. |
| A target record lookup raises another exception | The record list is empty and `errors[record_type]` is `unexpected: <exception class name>`. |
| A common subdomain lookup raises an anticipated negative/error exception | The candidate is skipped; it is not added to `subdomains_found` or `subdomain_errors`. |
| A common subdomain lookup raises another exception | `subdomain_errors[hostname][record_type]` records `unexpected: <exception class name>`, unless another record type later resolves the hostname. |
| An SRV lookup raises `NoAnswer` or `NXDOMAIN` | The service entry is an empty list and is not added to `srv_errors`. |
| An SRV lookup raises another anticipated or unexpected exception | The service entry is an empty list and its error name is stored in `srv_errors`. |

Target-domain and SRV resolver calls use a 5-second lifetime; common
subdomain calls use a 3-second lifetime. The resolver's per-attempt timeout is
2.0 seconds. The tool does not expose a separate overall timeout response.
Other errors raised while parsing a returned record are not converted into a
standard failure object, except for `UnicodeDecodeError` while formatting TXT
or CAA data, which is recorded for that record type and leaves the enumeration
successful.

## Notes and limitations

- The resolver is configured with the public DNS servers `1.1.1.1` and
  `8.8.8.8`; the lookup needs network access to those servers.
- The record pass is limited to `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`,
  and `CAA` at the target domain.
- SRV checks cover only SIP, LDAP, XMPP client, Kerberos, and Autodiscover
  service names from the fixed list in the implementation.
- Subdomain discovery tries only the implementation's fixed list of common
  labels and does not provide exhaustive subdomain enumeration.
- A target `NXDOMAIN` stops the enumeration with `success: false`; an
  `NXDOMAIN` result for a candidate subdomain or SRV service is treated as an
  ordinary absent name.
- The tool does not query IP addresses, bare labels, or `localhost`.

## API key requirements

None required. The tool uses DNS resolvers directly and has no API-key input.

## Related tools

`whois_lookup` provides complementary domain-registration data, while
`subdomain_takeover` reuses the discovered subdomains for takeover checks and
`full_recon` combines DNS enumeration with the server's other core tools. See
the [tools index](README.md) for the current registration inventory and
documentation status.
