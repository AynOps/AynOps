from tools.whois_tool import whois_lookup
from tools.dns_tool import dns_enumeration
from tools.portscan_tool import port_scan
from tools.ssl_tool import ssl_inspect
from tools.techstack_tool import tech_stack_detect
from tools.asn_tool import asn_lookup
from tools.crt_sh_tool import cert_transparency
from tools.iprep_tool import ip_reputation
from tools.email_security_tool import email_security_check

from tools.signals.whois import whois_extractor
from tools.signals.dns import dns_extractor
from tools.signals.ports_scan import portscan_extractor
from tools.signals.ssl import ssl_extractor
from tools.signals.tech_stack import techstack_extractor
from tools.signals.asn import asn_extractor
from tools.signals.crtsh import crt_extractor
from tools.signals.ip_reputation import ip_reputation_extractor
from tools.signals.email_security import email_security_extractor
from tools.signals.ip_reputation import extract_ip

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
    } ,
]