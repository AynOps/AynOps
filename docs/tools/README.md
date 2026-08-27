# AynOps Tools Documentation

This index covers the MCP tools provided by AynOps for reconnaissance. Each tool has a dedicated page describing its purpose, parameters, example request/response, errors, and limitations.

## Included in `full_recon`

| Tool | Description | Docs |
|------|-------------|------|
| `whois_lookup` | Domain registration data — registrant, registrar, dates, name servers | [whois_lookup.md](whois_lookup.md) |
| `dns_enumeration` | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV + subdomain brute-forcing | — |
| `port_scan` | Nmap-powered scanner with service/version detection | — |
| `ssl_inspect` | SSL/TLS certificate — issuer, expiry, SANs, TLS version | — |
| `email_security_check` | SPF, DKIM, DMARC checks with security_score and recommendations | — |
| `tech_stack_detect` | Web server, CMS, JS frameworks, CDN, analytics detection | — |
| `cert_transparency` | crt.sh Certificate Transparency log queries | — |
| `asn_lookup` | ASN and network ownership via Team Cymru WHOIS | — |
| `ip_reputation` | IP abuse check via AbuseIPDB (API key required) | — |
| `full_recon` | Aggregate full reconnaissance in one call | — |

## Standalone tools

| Tool | Description | Docs |
|------|-------------|------|
| `headers_analyzer` | HTTP security header analysis | — |
| `cve_lookup` | CVE / vulnerability lookup | — |
| `cloud_exposure_check` | Cloud bucket / storage exposure checks | — |
| `trace_redirects` | HTTP redirect chain tracing | — |
| `robots_txt_inspect` | robots.txt inspection | — |
| `hibp_check` | Have I Been Pwned breach check (API key required) | — |

> This index is intentionally maintained as documentation pages are added. PRs documenting a subset of tools are welcome — reference `#143` in the PR description.
