# AynOps tools

This index lists the tools currently registered by the MCP server. Dedicated
pages are being added incrementally; `whois_lookup` is documented in this
slice, and the remaining pages are planned follow-ups.

## Included in `full_recon`

| Tool | Description | Documentation |
|---|---|---|
| [`whois_lookup`](whois_lookup.md) | Domain registration data — registrant organization, registrar, creation date, expiry, and name servers | Available |
| `dns_enumeration` | Enumerates DNS records and common subdomains | Pending |
| `port_scan` | Nmap-powered port scanner with service and version detection | Pending |
| `ssl_inspect` | Inspects SSL/TLS certificates, cipher strength, SANs, and TLS version | Pending |
| `email_security_check` | Checks SPF, DKIM, and DMARC configuration | Pending |
| `tech_stack_detect` | Detects web servers, CMSs, JavaScript frameworks, CDNs, and analytics | Pending |
| `cert_transparency` | Queries Certificate Transparency logs and extracts certificate and subdomain information | Pending |
| `asn_lookup` | Looks up ASN and network ownership information through Team Cymru WHOIS | Pending |
| `ip_reputation` | Checks whether an IP is flagged as malicious through AbuseIPDB | Pending |
| `headers_analyzer` | Analyzes HTTP security headers and reports misconfigurations | Pending |
| `full_recon` | Combines results from the core reconnaissance tools into a single report | Pending |

## Standalone tools

| Tool | Description | Documentation |
|---|---|---|
| `cve_lookup` | Searches the NVD for known CVEs by software and version | Pending |
| `cloud_exposure_check` | Checks for publicly accessible cloud storage buckets | Pending |
| `trace_redirects` | Traces an HTTP redirect chain and flags suspicious hops | Pending |
| `robots_txt_inspect` | Fetches and parses `robots.txt` for hidden directories and sitemaps | Pending |
| `subdomain_takeover` | Checks discovered subdomains for takeover indicators | Pending |
| `hibp_check` | Checks whether an email or domain appears in Have I Been Pwned breach data | Pending |
