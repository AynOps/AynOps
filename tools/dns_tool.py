from concurrent.futures import ThreadPoolExecutor
from itertools import zip_longest
import base64

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename
from utils.helpers import is_valid_domain, normalize_domain


class _DnsExecutor(ThreadPoolExecutor):
    def cancel_pending(self):
        self._cancel_pending = True

    def __exit__(self, exc_type, exc_value, traceback):
        cancel_pending = getattr(self, "_cancel_pending", False)
        self.shutdown(wait=not cancel_pending, cancel_futures=cancel_pending)
        return False

# Public resolvers used for every lookup.
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# Central resolver timing configuration (seconds).
RESOLVER_TIMEOUT = 2.0
RESOLVER_LIFETIME = 5
SUBDOMAIN_LIFETIME = 3
MAX_CONCURRENT_LOOKUPS = 10
MAX_CNAME_DEPTH = 5

# Record types enumerated for the target domain.
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

# DNSSEC record types enumerated for the target domain (issue #144, item 4).
DNSSEC_RECORD_TYPES = ["DNSKEY", "DS", "RRSIG", "NSEC"]

# Common subdomains tried during brute-force discovery; adjust to taste.
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "remote", "portal",
    "webmail", "smtp", "pop", "imap", "autodiscover", "autoconfig", "mx", "ns1", "ns2", "cpanel","whm", 
    "blog", "store", "app", "shop", "mobile", "test", "demo", "beta", "testing","sandbox","local",
    "cdn", "edge", "static", "proxy", "origin", "media", "assets", "images", "docs", "help","support","status",
    "git", "jenkins", "jira", "wiki","pipeline","sso", "auth", "login", "gateway","secure", "files", "upload", "backup",
    "db", "monitor", "dashboard","cloud", "chat", "forum", "cluster", "aws"
]

# A subdomain counts as found if any of these record types resolves for it.
SUBDOMAIN_RECORD_TYPES = ("A", "AAAA", "CNAME")

# SRV services probed for the target domain (issue #144, item 6: SIP, LDAP,
# XMPP, Kerberos and Autodiscover), as the owner-name prefixes queried with
# the SRV record type.
SRV_SERVICES = [
    "_sip._tcp",
    "_ldap._tcp",
    "_xmpp-client._tcp",
    "_kerberos._tcp",
    "_autodiscover._tcp",
]

# Lookup failures dnspython documents for Resolver.resolve(): the name has no
# RRset of the requested type, no nameserver could answer, the resolution
# lifetime expired, or the name is too long after DNAME substitution. NXDOMAIN
# is documented too but handled separately, because a target domain that does
# not exist ends the whole enumeration. Anything outside this set is recorded
# as an unexpected lookup error so the rest of the scan can continue.
LOOKUP_ERRORS = (
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.resolver.YXDOMAIN,
    # dns.resolver.Timeout is dns.resolver.LifetimeTimeout, a subclass of this.
    dns.exception.Timeout,
)

# On the brute-force path NXDOMAIN is the ordinary result for a name that does
# not exist, and a candidate built by prefixing a label to a long target can
# exceed the 255-octet limit; both mean "no such subdomain", not a failed scan.
SUBDOMAIN_LOOKUP_ERRORS = LOOKUP_ERRORS + (dns.resolver.NXDOMAIN, dns.name.NameTooLong)

# An SRV owner name is built by prefixing a service label to the target, so a
# target near the length limit pushes the queried name past 255 octets; like
# the brute-force path, that means "no such service name", not a failed scan.
SRV_LOOKUP_ERRORS = LOOKUP_ERRORS + (dns.name.NameTooLong,)


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


def _format_dnskey_record(record) -> dict:
    key = getattr(record, "key", None)
    if isinstance(key, bytes):
        key_str = base64.b64encode(key).decode("ascii")
    else:
        key_str = str(key) if key is not None else ""
    return {
        "flags": getattr(record, "flags", None),
        "protocol": getattr(record, "protocol", None),
        "algorithm": getattr(record, "algorithm", None),
        "key": key_str,
    }


def _format_ds_record(record) -> dict:
    digest = getattr(record, "digest", None)
    if isinstance(digest, bytes):
        digest_hex = digest.hex()
    else:
        digest_hex = str(digest) if digest is not None else ""
    return {
        "key_tag": getattr(record, "key_tag", None),
        "algorithm": getattr(record, "algorithm", None),
        "digest_type": getattr(record, "digest_type", None),
        "digest": digest_hex,
    }


def _format_rrsig_record(record) -> dict:
    type_covered = getattr(record, "type_covered", None)
    try:
        type_covered_name = (
            dns.rdatatype.to_text(type_covered) if type_covered is not None else None
        )
    except Exception:
        type_covered_name = str(type_covered)
    return {
        "type_covered": type_covered_name,
        "algorithm": getattr(record, "algorithm", None),
        "labels": getattr(record, "labels", None),
        "original_ttl": getattr(record, "original_ttl", None),
        "expiration": getattr(record, "expiration", None),
        "inception": getattr(record, "inception", None),
        "key_tag": getattr(record, "key_tag", None),
        "signer": _clean_name(getattr(record, "signer", "")),
    }


def _format_nsec_record(record) -> dict:
    next_name = getattr(record, "next", None)
    return {
        "next": _clean_name(next_name) if next_name else str(record),
    }


def _resolve_cname_chain(resolver, domain: str, initial_cnames: list) -> list:
    """Follow CNAME targets iteratively up to MAX_CNAME_DEPTH with cycle detection."""
    if not initial_cnames:
        return []
    chain = []
    seen = {domain.lower().rstrip(".")}
    current = str(initial_cnames[0]).rstrip(".")
    chain.append(current)
    seen.add(current.lower())

    for _ in range(MAX_CNAME_DEPTH):
        try:
            answers = resolver.resolve(current, "CNAME", lifetime=RESOLVER_LIFETIME)
            next_target = _clean_name(answers[0])
            if next_target.lower() in seen:
                break
            chain.append(next_target)
            seen.add(next_target.lower())
            current = next_target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            break
        except Exception:
            break
    return chain


def _resolve_ptr_records(resolver, ip_addresses: list) -> tuple[dict, dict]:
    """Perform reverse DNS (PTR) lookups for resolved IP addresses."""
    ptr_records = {}
    ptr_errors = {}
    for ip in ip_addresses:
        try:
            rev_name = dns.reversename.from_address(str(ip))
            answers = resolver.resolve(rev_name, "PTR", lifetime=RESOLVER_LIFETIME)
            ptr_records[str(ip)] = [_clean_name(r.target) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            ptr_records[str(ip)] = []
        except LOOKUP_ERRORS as exc:
            ptr_records[str(ip)] = []
            ptr_errors[str(ip)] = type(exc).__name__
        except Exception as exc:
            ptr_records[str(ip)] = []
            ptr_errors[str(ip)] = f"unexpected: {type(exc).__name__}"
    return ptr_records, ptr_errors


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


def _lookup_subdomain(resolver, full: str) -> tuple[bool, dict]:
    errors = {}
    for rtype in SUBDOMAIN_RECORD_TYPES:
        try:
            resolver.resolve(full, rtype, lifetime=SUBDOMAIN_LIFETIME)
            return True, {}
        except SUBDOMAIN_LOOKUP_ERRORS:
            continue
        except Exception as exc:
            errors[rtype] = f"unexpected: {type(exc).__name__}"
    return False, errors


def dns_enumeration(domain: str) -> dict:
    """
    Enumerate DNS records for a domain.
    Returns A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records (CAA surfaces
    certificate authority restrictions), per-record-type errors, TTL per record
    type when available, SRV records for common enterprise services, common
    subdomains discovered via A/AAAA/CNAME
    lookups, unexpected subdomain lookup errors, and metadata about the
    resolver used.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    records = {}
    errors = {}
    ttls = {}
    resolver = _make_resolver()

    first_record_answers = None
    first_record_error = None
    if RECORD_TYPES:
        try:
            first_record_answers = resolver.resolve(
                domain, RECORD_TYPES[0], lifetime=RESOLVER_LIFETIME
            )
        except dns.resolver.NXDOMAIN:
            return {"success": False, "error": f"Domain {domain} does not exist"}
        except Exception as exc:
            first_record_error = exc

    lookup_count = (
        len(RECORD_TYPES)
        + len(SRV_SERVICES)
        + len(COMMON_SUBDOMAINS)
        + len(DNSSEC_RECORD_TYPES)
    )
    max_workers = max(1, min(MAX_CONCURRENT_LOOKUPS, lookup_count))
    with _DnsExecutor(max_workers=max_workers) as executor:
        record_futures = []
        srv_futures = []
        subdomain_futures = []
        dnssec_futures = []
        for rtype, service, sub, dnssec_type in zip_longest(
            RECORD_TYPES[1:], SRV_SERVICES, COMMON_SUBDOMAINS, DNSSEC_RECORD_TYPES
        ):
            if rtype is not None:
                record_futures.append(
                    executor.submit(
                        resolver.resolve,
                        domain,
                        rtype,
                        lifetime=RESOLVER_LIFETIME,
                    )
                )
            if service is not None:
                srv_futures.append(
                    executor.submit(
                        resolver.resolve,
                        f"{service}.{domain}",
                        "SRV",
                        lifetime=RESOLVER_LIFETIME,
                    )
                )
            if sub is not None:
                subdomain_futures.append(
                    executor.submit(_lookup_subdomain, resolver, f"{sub}.{domain}")
                )
            if dnssec_type is not None:
                dnssec_futures.append(
                    executor.submit(
                        resolver.resolve,
                        domain,
                        dnssec_type,
                        lifetime=RESOLVER_LIFETIME,
                    )
                )

        for index, rtype in enumerate(RECORD_TYPES):
            try:
                if index == 0:
                    if first_record_error is not None:
                        raise first_record_error
                    answers = first_record_answers
                else:
                    answers = record_futures[index - 1].result()
            except dns.resolver.NXDOMAIN:
                executor.cancel_pending()
                return {"success": False, "error": f"Domain {domain} does not exist"}
            except LOOKUP_ERRORS as exc:
                records[rtype] = []
                errors[rtype] = type(exc).__name__
            except Exception as exc:
                records[rtype] = []
                errors[rtype] = f"unexpected: {type(exc).__name__}"
            else:
                ttl = _record_ttl(answers)
                if ttl is not None:
                    ttls[rtype] = ttl
                try:
                    if rtype == "MX":
                        records[rtype] = [
                            {
                                "preference": r.preference,
                                "exchange": _clean_name(r.exchange),
                            }
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
                            "minimum": r.minimum,
                        }
                    elif rtype == "TXT":
                        records[rtype] = [_format_txt_record(r) for r in answers]
                    elif rtype == "CAA":
                        records[rtype] = [_format_caa_record(r) for r in answers]
                    elif rtype in {"NS", "CNAME"}:
                        records[rtype] = [_clean_name(r) for r in answers]
                    else:
                        records[rtype] = [str(r) for r in answers]
                except UnicodeDecodeError as exc:
                    # TXT chunks and CAA values are arbitrary remote octets,
                    # not guaranteed UTF-8. Keep this record type's failure
                    # visible without swallowing defects in our formatting.
                    records[rtype] = []
                    errors[rtype] = type(exc).__name__
                    ttls.pop(rtype, None)

        # SRV enumeration for common enterprise services. Unlike the target
        # domain itself, an absent SRV owner or RRset is an ordinary negative.
        srv_records = {}
        srv_errors = {}
        for service, future in zip(SRV_SERVICES, srv_futures):
            try:
                answers = future.result()
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                srv_records[service] = []
            except SRV_LOOKUP_ERRORS as exc:
                srv_records[service] = []
                srv_errors[service] = type(exc).__name__
            except Exception as exc:
                srv_records[service] = []
                srv_errors[service] = f"unexpected: {type(exc).__name__}"
            else:
                srv_records[service] = [
                    {
                        "priority": r.priority,
                        "weight": r.weight,
                        "port": r.port,
                        "target": _clean_name(r.target),
                    }
                    for r in answers
                ]

        # DNSSEC enumeration (DNSKEY, DS, RRSIG, NSEC)
        dnssec_records = {}
        dnssec_errors = {}
        for dnssec_type, future in zip(DNSSEC_RECORD_TYPES, dnssec_futures):
            try:
                answers = future.result()
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                dnssec_records[dnssec_type] = []
            except LOOKUP_ERRORS as exc:
                dnssec_records[dnssec_type] = []
                dnssec_errors[dnssec_type] = type(exc).__name__
            except Exception as exc:
                dnssec_records[dnssec_type] = []
                dnssec_errors[dnssec_type] = f"unexpected: {type(exc).__name__}"
            else:
                try:
                    if dnssec_type == "DNSKEY":
                        dnssec_records[dnssec_type] = [
                            _format_dnskey_record(r) for r in answers
                        ]
                    elif dnssec_type == "DS":
                        dnssec_records[dnssec_type] = [
                            _format_ds_record(r) for r in answers
                        ]
                    elif dnssec_type == "RRSIG":
                        dnssec_records[dnssec_type] = [
                            _format_rrsig_record(r) for r in answers
                        ]
                    elif dnssec_type == "NSEC":
                        dnssec_records[dnssec_type] = [
                            _format_nsec_record(r) for r in answers
                        ]
                    else:
                        dnssec_records[dnssec_type] = [str(r) for r in answers]
                except Exception as exc:
                    dnssec_records[dnssec_type] = []
                    dnssec_errors[dnssec_type] = type(exc).__name__

        # Aggregate completed subdomain work in configured order so execution
        # timing cannot alter the public result.
        found_subdomains = []
        subdomain_errors = {}
        for sub, future in zip(COMMON_SUBDOMAINS, subdomain_futures):
            full = f"{sub}.{domain}"
            found, lookup_errors = future.result()
            if found:
                found_subdomains.append(full)
            elif lookup_errors:
                subdomain_errors[full] = lookup_errors

        # Complete CNAME alias chain resolution (Issue #144, item 8)
        cname_chain = _resolve_cname_chain(resolver, domain, records.get("CNAME", []))

        # Reverse DNS (PTR) lookups for discovered A and AAAA IPs (Issue #144, item 7)
        ip_addresses = []
        for ip in records.get("A", []) + records.get("AAAA", []):
            if ip not in ip_addresses:
                ip_addresses.append(ip)
        ptr_records, ptr_errors = _resolve_ptr_records(resolver, ip_addresses)

    return {
        "success": True,
        "domain": domain,
        "errors": errors,
        "records": records,
        "cname_chain": cname_chain,
        "dnssec_records": dnssec_records,
        "dnssec_errors": dnssec_errors,
        "ptr_records": ptr_records,
        "ptr_errors": ptr_errors,
        "srv_records": srv_records,
        "srv_errors": srv_errors,
        "subdomains_found": found_subdomains,
        "subdomain_errors": subdomain_errors,
        "ttl": ttls,
        "resolver": _resolver_metadata(resolver),
    }
