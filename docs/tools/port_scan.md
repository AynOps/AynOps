# `port_scan`

## Overview

`port_scan` runs Nmap against a target domain or IP address and returns the
hosts Nmap found, their protocol and port data, and (for OS scans) operating
system matches. It is registered as a public MCP tool and does not require an
API key.

The callable is:

```python
port_scan(target, scan_type="basic", timeout=None)
```

The implementation passes `target` directly to Nmap. It does not normalize the
target or perform domain, IP-address, ownership, or authorization validation.

## Purpose and common use cases

Use this tool to identify reachable hosts, open ports, and the service data
that Nmap reports for an authorized target. Choose a service scan when service
and version information is useful, an OS scan when operating-system detection
is needed, a full scan when all ports must be considered, or a vulnerability
scan when the Nmap `vuln` script set is appropriate for the engagement.

## Parameters

The MCP tool has one required parameter and two optional parameters:

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `target` | string | Yes | — | Domain name or IP address passed directly to Nmap. The tool does not validate its format. |
| `scan_type` | string | No | `"basic"` | One of exactly `basic`, `service`, `os`, `full`, or `vuln`. |
| `timeout` | integer or null | No | Derived | Optional positive application-level timeout in seconds. `null` uses the mode's derived default. |

## Optional parameters

`scan_type` selects one of the five fixed Nmap configurations. `timeout`, when
provided, must be positive and replaces the derived application-level timeout
passed to `scanner.scan`; it does not change the mode's Nmap argument string.

The derived default is the mode's Nmap `--host-timeout` multiplied by the
application's 20% margin and converted to an integer number of seconds:

| Mode | Nmap arguments | Nmap semantics | Derived application timeout |
|---|---|---|---:|
| `basic` | `-F --host-timeout 30s` | Fast scan of the top 100 ports. | 36 seconds |
| `service` | `-sV -F --host-timeout 120s` | Service and version detection over the fast port set. | 144 seconds |
| `os` | `-O -F --host-timeout 60s` | Operating-system detection over the fast port set. | 72 seconds |
| `full` | `-p- --host-timeout 15m` | Scan all 65,535 ports. | 1,080 seconds |
| `vuln` | `--script vuln -F --host-timeout 15m --script-timeout 5m` | Run Nmap's `vuln` scripts over the fast port set, with a five-minute script timeout. | 1,080 seconds |

The derived values are application timeouts; the `--host-timeout` and, for
`vuln`, `--script-timeout` values remain part of the Nmap arguments shown above.

## Example MCP request

The public MCP registration uses the callable name and parameter names shown
in the signature:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "port_scan",
    "arguments": {
      "target": "scanme.nmap.org",
      "scan_type": "service",
      "timeout": 300
    }
  }
}
```

This is a request shape example only; it does not perform a scan here.

## Example successful response

The following is an illustrative response using the shape returned by the
focused mocked test suite. Values are examples, not the result of a live
scan:

```json
{
  "success": true,
  "target": "scanme.nmap.org",
  "scan_type": "service",
  "hosts_found": 1,
  "duration_seconds": 1.23,
  "results": [
    {
      "host": "93.184.216.34",
      "hostname": "example.com",
      "state": "up",
      "protocols": {
        "tcp": [
          {
            "port": 80,
            "state": "open",
            "service": "http",
            "product": "nginx",
            "version": "1.18",
            "scripts": {
              "http-title": "Example Domain"
            }
          }
        ]
      }
    }
  ],
  "host_timeout_status": {
    "93.184.216.34": false
  }
}
```

For an `os` scan, a host result can additionally contain the OS matches that
Nmap returned:

```json
{
  "os_matches": [
    {
      "name": "Linux 4.19 - 5.15",
      "accuracy": "98"
    }
  ]
}
```

The `os_matches` key is omitted for non-OS scans and when Nmap returns an empty
`osmatch` list for an OS scan. If Nmap returns source entries without a
non-empty `name` or `accuracy`, the key is present with an empty list.

## Response field descriptions

On success, the response contains `success: true` and these fields:

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` when Nmap completed and the result was assembled. |
| `target` | string | The exact target value passed to the callable and Nmap; it is not normalized. |
| `scan_type` | string | The selected mode: `basic`, `service`, `os`, `full`, or `vuln`. |
| `hosts_found` | integer | Number of host entries in `results`; it can be zero. |
| `duration_seconds` | number or null | Nmap's elapsed scan time parsed as a floating-point number. It is `null` when scan statistics are unavailable or cannot be read. |
| `results` | array of objects | One entry for each host returned by Nmap. An empty scan returns an empty array. |
| `host_timeout_status` | object or null | A map from IPv4 (preferred) or IPv6 host address to a boolean parsed from Nmap XML. `true` means the host has `timedout="true"`; `false` means the host element does not have that value. It is `null` when XML is unavailable, invalid, or contains no usable host address. |

Each object in `results` contains:

| Field | Type | Description |
|---|---|---|
| `host` | string | Host address/key returned by Nmap. |
| `hostname` | string | Hostname returned by Nmap's host record. |
| `state` | string | Nmap host state, such as `up`. |
| `protocols` | object | Maps each protocol reported by Nmap, such as `tcp`, to an array of port entries. |
| `os_matches` | array of objects, OS scans only | Included only when `scan_type` is `os` and Nmap's `osmatch` list is non-empty. Each retained item contains any non-empty `name` and/or `accuracy` fields from Nmap; the output list can therefore be empty if every source match lacks those fields. |

Each port entry inside a protocol array contains:

| Field | Type | Description |
|---|---|---|
| `port` | integer | Port number reported by Nmap. |
| `state` | string | Port state, such as `open`. |
| `service` | string | Nmap's service name (`name` in the underlying record). |
| `product` | string, optional | Product name when Nmap reports one. |
| `version` | string, optional | Product version when Nmap reports one. |
| `scripts` | object, optional | Nmap script output (`script` in the underlying record), included when script data is present. |

## Errors and timeouts

Failure responses contain `success: false` and an `error` string. The normal
failure shapes are:

| Situation | Response |
|---|---|
| Invalid scan type | `{"success": false, "error": "Invalid scan_type 'invalid'. Valid options are: basic, service, os, full, vuln", "valid_scan_types": ["basic", "service", "os", "full", "vuln"]}` |
| Invalid timeout (`timeout < 1`) | `{"success": false, "error": "Invalid timeout '0'. Must be a positive number of seconds."}` |
| Application or Nmap timeout | `{"success": false, "error": "Port scan timed out"}` |
| Nmap is missing or raises `nmap.PortScannerError` | `{"success": false, "error": "Nmap not found or not installed: <message>"}` |
| Any other unexpected exception | `{"success": false, "error": "<exception message>"}` |

The invalid scan-type response includes the complete valid-mode list. A target
that Nmap cannot process is not rejected by a separate target-validation layer;
its resulting Nmap error follows the Nmap or unexpected-error shapes above.

## Notes and limitations

- Nmap must be installed and available to the Python `nmap` binding. Install
  Nmap separately as a system prerequisite, or use the repository's Docker
  image, which includes Nmap.
- OS detection (`-O`) may require administrator/root privileges. Without the
  necessary privilege, Nmap may fail or return no OS matches.
- `full` and `vuln` scans can take substantially longer than the fast modes;
  their application defaults are derived from a 15-minute Nmap host timeout.
- Only scan domains and IP addresses that you own or are explicitly authorized
  to test. The repository rule permits `scanme.nmap.org` as its sole public
  live-test target; do not use other public hosts for live tests.
- No live Nmap scan is part of this documentation page or its verification.

## API key requirements

None required. The tool invokes the local Nmap executable and has no API-key
parameter.

## Related tools

`dns_enumeration` provides DNS records and common-subdomain results, while
`whois_lookup` provides registration data. `full_recon` combines the core
reconnaissance tools, and `ssl_inspect` provides complementary certificate and
TLS details. See the [tools index](README.md) for the registration inventory
and documentation status.
