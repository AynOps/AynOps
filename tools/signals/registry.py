from tools import (
    asn_lookup,
    cert_transparency,
    dns_enumeration,
    email_security_check,
    headers_analyzer,
    ip_reputation,
    port_scan,
    ssl_inspect,
    tech_stack_detect,
    whois_lookup,
)
from tools.signals import (
    asn_extractor,
    crt_extractor,
    dns_extractor,
    email_security_extractor,
    extract_ip,
    headers_extractor,
    ip_reputation_extractor,
    portscan_extractor,
    ssl_extractor,
    techstack_extractor,
    whois_extractor,
)

TOOL_REGISTRY = [
    # ---------------- Wave 1 ---------------- #
    {
        "name": "whois",
        "fn": whois_lookup,
        "wave": 1,
        "args": lambda domain, results: (domain,),
        "extractor": whois_extractor,
    },
    {
        "name": "dns",
        "fn": dns_enumeration,
        "wave": 1,
        "args": lambda domain, results: (domain,),
        "extractor": dns_extractor,
    },
    {
        "name": "ssl",
        "fn": ssl_inspect,
        "wave": 1,
        "args": lambda domain, results: (domain,),
        "extractor": ssl_extractor,
    },
    {
        "name": "email_security",
        "fn": email_security_check,
        "wave": 1,
        "args": lambda domain, results: (domain,),
        "extractor": email_security_extractor,
    },
    {
        "name": "asn",
        "fn": asn_lookup,
        "wave": 1,
        "args": lambda domain, results: (domain,),
        "extractor": asn_extractor,
    },
    # ---------------- Wave 2 ---------------- #
    {
        "name": "ports",
        "fn": port_scan,
        "wave": 2,
        "args": lambda domain, results: (domain, "service"),
        "extractor": portscan_extractor,
    },
    {
        "name": "techstack",
        "fn": tech_stack_detect,
        "wave": 2,
        "args": lambda domain, results: (domain,),
        "extractor": techstack_extractor,
    },
    {
        "name": "headers",
        "fn": headers_analyzer,
        "wave": 2,
        "args": lambda domain, results: (domain,),
        "extractor": headers_extractor,
    },
    {
        "name": "ct_logs",
        "fn": cert_transparency,
        "wave": 2,
        "args": lambda domain, results: (domain,),
        "extractor": crt_extractor,
    },
    # ---------------- Wave 3 ---------------- #
    {
        "name": "ip_reputation",
        "fn": ip_reputation,
        "wave": 3,
        "args": lambda domain, results: (extract_ip(results),),
        "should_run": lambda domain, results: extract_ip(results) is not None,
        "skip_reason": "No IP address found — ip_reputation skipped",
        "extractor": ip_reputation_extractor,
    },
]
