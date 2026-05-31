from fastmcp import FastMCP
import whois
import re
import nmap
import dns.resolver
import ipaddress
import os
import ssl
import socket
import requests
from datetime import datetime
import concurrent.futures
from urllib.parse import urlparse

mcp = FastMCP("CyberSecurity-MCP-Server")

# HELPERS

def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None

def get_cvss_details(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    metric_groups = (
        metrics.get("cvssMetricV31")
        or metrics.get("cvssMetricV30")
        or metrics.get("cvssMetricV2")
        or []
    )

    if not metric_groups:
        return {"severity": "Unknown", "score": None}

    metric = metric_groups[0]
    cvss_data = metric.get("cvssData", {})

    return {
        "severity": metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "Unknown",
        "score": cvss_data.get("baseScore"),
    }

def get_english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])
    english = next((item for item in descriptions if item.get("lang") == "en"), None)
    return english.get("value", "") if english else ""

# TOOL 1 — WHOIS LOOKUP
@mcp.tool()
def whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup for a domain."""
    try:
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        result = whois.whois(domain)

        def safe_date(d):
            return str(d[0] if isinstance(d, list) else d)

        return {
            "success": True,
            "domain": domain,
            "registrar": result.registrar,
            "whois_server": result.whois_server,
            "creation_date": safe_date(result.creation_date),
            "expiration_date": safe_date(result.expiration_date),
            "updated_date": safe_date(result.updated_date),
            "name_servers": result.name_servers,
            "status": result.status,
            "emails": result.emails,
            "dnssec": result.dnssec,
            "country": result.country,
            "org": result.org
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# TOOL 2 — DNS ENUMERATION
@mcp.tool()
def dns_enumeration(domain: str) -> dict:
    """
    Enumerate DNS records for a domain.
    Returns A, AAAA, MX, NS, TXT, CNAME, SOA records.
    """
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    records = {}

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            if rtype == "MX":
                records[rtype] = [
                    {"preference": r.preference, "exchange": str(r.exchange)}
                    for r in answers
                ]
            elif rtype == "SOA":
                r = answers[0]
                records[rtype] = {
                    "mname": str(r.mname),
                    "rname": str(r.rname),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum
                }
            else:
                records[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            return {"success": False, "error": f"Domain {domain} does not exist"}
        except Exception:
            records[rtype] = []

    # Subdomain brute-force (common subdomains)
    common_subdomains = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "remote", "portal"]
    found_subdomains = []

    for sub in common_subdomains:
        try:
            full = f"{sub}.{domain}"
            dns.resolver.resolve(full, "A", lifetime=3)
            found_subdomains.append(full)
        except Exception:
            pass

    return {
        "success": True,
        "domain": domain,
        "records": records,
        "subdomains_found": found_subdomains
    }

# TOOL 3 — PORT SCANNING (NMAP)
@mcp.tool()
def port_scan(target: str, scan_type: str = "basic") -> dict:
    """
    Perform Nmap port scan on a target IP or domain.

    scan_type options:
    - "basic"   : Top 100 ports, fast (-F)
    - "service" : Service & version detection (-sV -F)
    - "os"      : OS detection, needs admin (-O -F)
    - "full"    : All 65535 ports, slow (-p-)
    - "vuln"    : Basic vulnerability scripts (--script vuln -F)
    """
    try:
        scanner = nmap.PortScanner()

        scan_args = {
            "basic":   "-F",
            "service": "-sV -F",
            "os":      "-O -F",
            "full":    "-p-",
            "vuln":    "--script vuln -F"
        }

        args = scan_args.get(scan_type, "-F")
        scanner.scan(hosts=target, arguments=args)

        results = []
        for host in scanner.all_hosts():
            host_data = {
                "host": host,
                "hostname": scanner[host].hostname(),
                "state": scanner[host].state(),
                "protocols": {}
            }

            for proto in scanner[host].all_protocols():
                ports = []
                for port, data in scanner[host][proto].items():
                    port_info = {
                        "port": port,
                        "state": data["state"],
                        "service": data["name"],
                    }
                    if data.get("product"):
                        port_info["product"] = data["product"]
                    if data.get("version"):
                        port_info["version"] = data["version"]
                    if data.get("script"):
                        port_info["scripts"] = data["script"]
                    ports.append(port_info)

                host_data["protocols"][proto] = ports

            results.append(host_data)

        return {
            "success": True,
            "target": target,
            "scan_type": scan_type,
            "hosts_found": len(results),
            "results": results
        }

    except nmap.PortScannerError as e:
        return {"success": False, "error": f"Nmap not found or not installed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# TOOL 4 — SSL INSPECTION
@mcp.tool()
def ssl_inspect(domain: str, port: int = 443) -> dict:
    """
    Inspect SSL/TLS certificate details for a domain.
    Returns cert validity, issuer, SANs, expiry, and cipher info.
    """
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = context.wrap_socket(
            socket.create_connection((domain, port), timeout=10),
            server_hostname=domain
        )
        cert = conn.getpeercert()
        cipher = conn.cipher()
        tls_version = conn.version()
        conn.close()

        # Parse dates
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
        days_left  = (not_after - datetime.utcnow()).days

        # Subject Alternative Names
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        # Issuer / Subject as flat dicts
        def rdn(rdns):
            return {k: v for rdn in rdns for k, v in rdn}

        return {
            "success": True,
            "domain": domain,
            "port": port,
            "tls_version": tls_version,
            "cipher": {
                "name": cipher[0],
                "protocol": cipher[1],
                "bits": cipher[2]
            },
            "certificate": {
                "subject": rdn(cert.get("subject", [])),
                "issuer": rdn(cert.get("issuer", [])),
                "serial_number": cert.get("serialNumber"),
                "not_before": str(not_before),
                "not_after": str(not_after),
                "days_until_expiry": days_left,
                "expired": days_left < 0,
                "expiring_soon": 0 <= days_left <= 30,
                "subject_alt_names": sans,
                "version": cert.get("version")
            }
        }

    except ssl.SSLCertVerificationError as e:
        return {"success": False, "error": f"SSL verification failed: {str(e)}"}
    except socket.timeout:
        return {"success": False, "error": "Connection timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# TOOL 5 — TECHNOLOGY STACK DETECTION
@mcp.tool()
def tech_stack_detect(domain: str) -> dict:
    """
    Detect technology stack of a website.
    Identifies web server, frameworks, CMS, CDN, analytics, and security headers.
    """
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    try:
        url = f"https://{domain}"
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"})

        headers = {k.lower(): v for k, v in resp.headers.items()}
        html    = resp.text.lower()
        tech    = {}

        # ── Web Server ──
        if "server" in headers:
            tech["web_server"] = headers["server"]

        # ── Powered By ──
        if "x-powered-by" in headers:
            tech["powered_by"] = headers["x-powered-by"]

        # ── CDN Detection ──
        cdn_signatures = {
            "Cloudflare":   ["cf-ray", "cf-cache-status"],
            "Fastly":       ["x-fastly-request-id"],
            "Akamai":       ["x-akamai-transformed"],
            "AWS CloudFront": ["x-amz-cf-id"],
            "Vercel":       ["x-vercel-id"],
            "Netlify":      ["x-nf-request-id"],
        }
        cdns = [name for name, hdrs in cdn_signatures.items() if any(h in headers for h in hdrs)]
        if cdns:
            tech["cdn"] = cdns

        # ── CMS Detection ──
        cms_signatures = {
            "WordPress":  ["wp-content", "wp-includes", "wordpress"],
            "Drupal":     ["drupal.js", "drupal.min.js", "/sites/default/files"],
            "Joomla":     ["/media/jui/", "joomla"],
            "Shopify":    ["cdn.shopify.com", "shopify.com/s/files"],
            "Wix":        ["wix.com", "wixstatic.com"],
            "Squarespace":["squarespace.com", "static.squarespace.com"],
            "Ghost":      ["ghost.io", "content/themes/ghost"],
        }
        cms_found = [name for name, sigs in cms_signatures.items() if any(s in html for s in sigs)]
        if cms_found:
            tech["cms"] = cms_found

        # ── JavaScript Frameworks ──
        js_signatures = {
            "React":      ["react.js", "react.min.js", "_react", "__react"],
            "Vue.js":     ["vue.js", "vue.min.js", "__vue__"],
            "Angular":    ["angular.js", "ng-version", "angular/core"],
            "Next.js":    ["_next/static", "__next"],
            "Nuxt.js":    ["_nuxt/", "__nuxt"],
            "jQuery":     ["jquery.js", "jquery.min.js"],
            "Bootstrap":  ["bootstrap.css", "bootstrap.min.css", "bootstrap.js"],
            "Tailwind":   ["tailwindcss", "tailwind.css"],
        }
        js_found = [name for name, sigs in js_signatures.items() if any(s in html for s in sigs)]
        if js_found:
            tech["javascript_frameworks"] = js_found

        # ── Analytics ──
        analytics_signatures = {
            "Google Analytics":   ["google-analytics.com", "gtag(", "ga("],
            "Google Tag Manager": ["googletagmanager.com"],
            "Hotjar":             ["hotjar.com"],
            "Mixpanel":           ["mixpanel.com"],
            "Segment":            ["segment.com", "analytics.js"],
            "Facebook Pixel":     ["connect.facebook.net/en_us/fbevents"],
        }
        analytics_found = [name for name, sigs in analytics_signatures.items() if any(s in html for s in sigs)]
        if analytics_found:
            tech["analytics"] = analytics_found

        # ── Security Headers ──
        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "x-xss-protection"
        ]
        present = [h for h in security_headers if h in headers]
        missing = [h for h in security_headers if h not in headers]

        security_score = int((len(present) / len(security_headers)) * 100)

        return {
            "success": True,
            "domain": domain,
            "url": resp.url,
            "status_code": resp.status_code,
            "technologies": tech,
            "security_headers": {
                "present": present,
                "missing": missing,
                "score": f"{security_score}%",
                "rating": (
                    "Excellent" if security_score >= 85 else
                    "Good"      if security_score >= 60 else
                    "Fair"      if security_score >= 40 else
                    "Poor"
                )
            }
        }

    except requests.exceptions.SSLError as e:
        return {"success": False, "error": f"SSL error: {str(e)}"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Could not connect to the domain"}
    except Exception as e:
        return {"success": False, "error": str(e)}
    
# Tool 6 - ASN Lookup
@mcp.tool()
def asn_lookup(target: str) -> dict:
    """
    Find the Autonomous System Number (ASN) and 
    organization for a domain or IP. Useful for 
    identifying hosting provider and network ownership.

    API Key: https://ipapi.com

    Args:
        target (str): Domain or IP address

    Returns:
        dict: Geolocation and ASN details matching the expected signature
    """
    try:
        target = target.strip()
        api_key = os.getenv("IP_API_KEY")
        
        if not api_key:
            return {
                "success": False,
                "error": "Environment variable 'IP_API_KEY' is missing or not set."
            }

        if "://" in target:
            parsed = urlparse(target)
            target = parsed.netloc if parsed.netloc else parsed.path

        if target.count(":") == 1 and not target.startswith("["):
            host, possible_port = target.rsplit(":", 1)
            if possible_port.isdigit():
                target = host

        try:
            ipaddress.ip_address(target)
            ip = target
        except ValueError:
            ip = socket.getaddrinfo(target, None)[0][4][0]


        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json"
        }
        response = requests.get(
            f"https://api.ipapi.com/api/{ip}?access_key={api_key}",
            timeout=15,
            headers=headers
        )

        if response.status_code != 200:
            return {
                "success": False,
                "error": f"API request failed with status {response.status_code}"
            }

        data = response.json()

        if data.get("success") is False:
            error_info = data.get("error", {})
            return {
                "success": False,
                "error": error_info.get("info", "API returned an error state")
            }

        connection = data.get("connection", {})
        
        asn_val = connection.get("asn")
        if asn_val and not str(asn_val).startswith("AS"):
            asn_string = f"AS{asn_val}"
        else:
            asn_string = str(asn_val) if asn_val else None

        return {
            "success": True,
            "ip": ip,
            "asn": asn_string,
            "org": connection.get("org"),
            "isp": connection.get("isp"), 
            "country": data.get("country_name"),
            "region": data.get("region_name"),
            "city": data.get("city")
        }

    except socket.gaierror:
        return {"success": False, "error": "Failed to resolve domain"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}
    
# TOOL 7 — FULL RECON (runs all 6 tools)
@mcp.tool()
def full_recon(domain: str) -> dict:
    """
    Run all recon tools on a domain in parallel:
    WHOIS, DNS enumeration, port scan, SSL inspection,
    and technology stack detection.

    Returns combined raw results. The MCP client (Claude)
    should generate summaries for each section.
    """
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    results = {}

    def run(name, fn, *args, **kwargs):
        try:
            results[name] = fn(*args, **kwargs)
        except Exception as e:
            results[name] = {"success": False, "error": str(e)}

    # Run all tools in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = [
            ex.submit(run, "whois",    whois_lookup,       domain),
            ex.submit(run, "dns",      dns_enumeration,    domain),
            ex.submit(run, "ports",    port_scan,          domain, "service"),
            ex.submit(run, "ssl",      ssl_inspect,        domain),
            ex.submit(run, "techstack",tech_stack_detect,  domain),
            ex.submit(run, "asn" , asn_lookup, domain)
        ]
        concurrent.futures.wait(futures)

    return {
        "success": True,
        "domain": domain,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "results": results,
        "instructions": (
            "Generate a 2-3 sentence summary for each tool's output "
            "(whois_summary, dns_summary, ports_summary, ssl_summary, techstack_summary , asn_summary) "
            "and a final overall_summary of 4-5 sentences covering the full security posture. "
        )
    }

# TOOL 8 — CVE LOOKUP
@mcp.tool()
def cve_lookup(software: str, version: str) -> dict:
    """
    Look up known CVEs for a software name and version using the NVD API.
    """
    software = software.strip()
    version = version.strip()

    if not software or not version:
        return {"success": False, "error": "Software and version are required"}

    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": f"{software} {version}"},
            timeout=60,
            headers={"User-Agent": "CyberSecurity-MCP-Server/1.0"},
        )
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cvss = get_cvss_details(cve)
            cves.append({
                "cve_id": cve.get("id"),
                "severity": cvss["severity"],
                "score": cvss["score"],
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "description": get_english_description(cve),
            })

        return {
            "success": True,
            "software": software,
            "version": version,
            "total_results": data.get("totalResults", len(cves)),
            "cves": cves,
        }

    except requests.exceptions.HTTPError as e:
        return {"success": False, "error": f"NVD API request failed: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "NVD API request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Could not connect to NVD API: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# TOOL 9 — IP REPUTATION CHECK
@mcp.tool()
def ip_reputation(ip_address: str) -> dict:
    """
    Check whether an IP address is reported as malicious using AbuseIPDB.
    Requires ABUSEIPDB_API_KEY in the environment.
    """
    try:
        ip = str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        return {"success": False, "error": "Invalid IP address format"}

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "ABUSEIPDB_API_KEY environment variable is required",
        }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json().get("data", {})

        abuse_score = data.get("abuseConfidenceScore", 0)
        return {
            "success": True,
            "ip": ip,
            "is_malicious": abuse_score >= 25,
            "abuse_confidence_score": abuse_score,
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "last_reported_at": data.get("lastReportedAt"),
        }

    except requests.exceptions.HTTPError as e:
        return {"success": False, "error": f"AbuseIPDB API request failed: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "AbuseIPDB API request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Could not connect to AbuseIPDB API: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    mcp.run()