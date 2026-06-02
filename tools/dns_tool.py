import dns.resolver
from utils.helpers import is_valid_domain

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