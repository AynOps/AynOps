from fastmcp import FastMCP
from fastmcp.prompts import PromptResult

from tools import (
    asn_lookup,
    cert_transparency,
    cloud_exposure_check,
    cve_lookup,
    dns_enumeration,
    email_security_check,
    full_recon,
    headers_analyzer,
    hibp_check,
    ip_reputation,
    port_scan,
    robots_txt_inspect,
    ssl_inspect,
    subdomain_takeover,
    tech_stack_detect,
    trace_redirects,
    whois_lookup,
)
from tools.prompts import THREAT_ANALYSIS_PROMPT

mcp = FastMCP("AynOps")

mcp.tool()(whois_lookup)
mcp.tool()(dns_enumeration)
mcp.tool()(port_scan)
mcp.tool()(ssl_inspect)
mcp.tool()(tech_stack_detect)
mcp.tool()(asn_lookup)
mcp.tool()(full_recon)
mcp.tool()(cve_lookup)
mcp.tool()(ip_reputation)
mcp.tool()(cert_transparency)
mcp.tool()(headers_analyzer)
mcp.tool()(email_security_check)
mcp.tool()(trace_redirects)
mcp.tool()(cloud_exposure_check)
mcp.tool()(robots_txt_inspect)
mcp.tool()(subdomain_takeover)
mcp.tool()(hibp_check)


@mcp.prompt(
    name="threat_analysis",
    description="Generate a structured cybersecurity threat analysis from AynOps full reconnaissance results.",
    tags={"security", "analysis", "full_recon", "threat_intelligence"},
    meta={
        "tool": "full_recon",
        "category": "security_analysis",
    },
)
def threat_analysis() -> PromptResult:
    """
    Generate a threat analysis prompt for the `full_recon` tool.
    """
    return PromptResult(
        messages=THREAT_ANALYSIS_PROMPT,
        description="Threat analysis prompt for AynOps full reconnaissance results.",
        meta={
            "tool": "full_recon",
        },
    )


if __name__ == "__main__":
    mcp.run()
