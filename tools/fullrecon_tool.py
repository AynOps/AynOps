from tools.whois_tool import whois_lookup
from tools.dns_tool import dns_enumeration
from tools.portscan_tool import port_scan
from tools.ssl_tool import ssl_inspect
from tools.techstack_tool import tech_stack_detect
from tools.asn_tool import asn_lookup
from utils.helpers import is_valid_domain
import concurrent.futures
from datetime import datetime , timezone

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
        "scanned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "results": results,
        "instructions": (
            "Generate a 2-3 sentence summary for each tool's output "
            "(whois_summary, dns_summary, ports_summary, ssl_summary, techstack_summary , asn_summary) "
            "and a final overall_summary of 4-5 sentences covering the full security posture. "
        )
    }