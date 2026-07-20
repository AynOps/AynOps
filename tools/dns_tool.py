import dns.resolver
from utils.helpers import is_valid_domain, normalize_domain

# Public resolvers used for every lookup.
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# Central resolver timing configuration (seconds).
RESOLVER_TIMEOUT = 2.0
RESOLVER_LIFETIME = 5
SUBDOMAIN_LIFETIME = 3

# Record types enumerated for the target domain.
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

# Common subdomains tried during brute-force discovery; adjust to taste.
COMMON_SUBDOMAINS = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "remote", "portal"]

# A subdomain counts as found if any of these record types resolves for it.
SUBDOMAIN_RECORD_TYPES = ("A", "AAAA", "CNAME")


def _clean_name(value) -> str:
    return str(value).rstrip(".")


def _format_txt_record(record) -> str:
    chunks = getattr(record, "strings", None)
    if chunks:
        return "".join(
            chunk.decode("utf-8") if isinstance(chunk, bytes) else str(chunk)
            for chunk in chunks
        )
    return str(record)


def _format_caa_record(record) -> dict:
    tag = getattr(record, "tag", None)
    value = getattr(record, "value", None)
    if tag is None or value is None:
        return {"raw": str(record)}
    return {
        "flags": getattr(record, "flags", 0),
        "tag": tag.decode("utf-8") if isinstance(tag, bytes) else str(tag),
        "value": value.decode("utf-8") if isinstance(value, bytes) else str(value),
    }


def _record_ttl(answers):
    rrset = getattr(answers, "rrset", None)
    return getattr(rrset, "ttl", None)


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_RESOLVERS
    resolver.timeout = RESOLVER_TIMEOUT
    resolver.lifetime = RESOLVER_LIFETIME
    return resolver


def _resolver_metadata(resolver) -> dict:
    return {
        "nameservers": [str(ns) for ns in resolver.nameservers],
        "timeout": resolver.timeout,
        "lifetime": resolver.lifetime,
    }


def dns_enumeration(domain: str) -> dict:
    """
    Enumerate DNS records for a domain.
    Returns A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records (CAA surfaces
    certificate authority restrictions), TTL per record type when available,
    common subdomains discovered via A/AAAA/CNAME lookups, and metadata about
    the resolver used.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    records = {}
    ttls = {}
    resolver = _make_resolver()

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=RESOLVER_LIFETIME, tcp=True)
            ttl = _record_ttl(answers)
            if ttl is not None:
                ttls[rtype] = ttl
            if rtype == "MX":
                records[rtype] = [
                    {"preference": r.preference, "exchange": _clean_name(r.exchange)}
                    for r in answers
                ]
            elif rtype == "SOA":
                r = answers[0]
                records[rtype] = {
                    "mname": _clean_name(r.mname),
                    "rname": _clean_name(r.rname),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum
                }
            elif rtype == "TXT":
                records[rtype] = [_format_txt_record(r) for r in answers]
            elif rtype == "CAA":
                records[rtype] = [_format_caa_record(r) for r in answers]
            elif rtype in {"NS", "CNAME"}:
                records[rtype] = [_clean_name(r) for r in answers]
            else:
                records[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            return {"success": False, "error": f"Domain {domain} does not exist"}
        except Exception:
            records[rtype] = []

    # Subdomain brute-force (common subdomains); a subdomain counts as found
    # when any of A/AAAA/CNAME resolves, so IPv6-only and aliased hosts are
    # not missed.
    found_subdomains = []

    for sub in COMMON_SUBDOMAINS:
        full = f"{sub}.{domain}"
        for rtype in SUBDOMAIN_RECORD_TYPES:
            try:
                resolver.resolve(full, rtype, lifetime=SUBDOMAIN_LIFETIME, tcp=True)
                found_subdomains.append(full)
                break
            except Exception:
                continue

    return {
        "success": True,
        "domain": domain,
        "records": records,
        "subdomains_found": found_subdomains,
        "ttl": ttls,
        "resolver": _resolver_metadata(resolver)
    }
