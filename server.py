from fastmcp import FastMCP
from tools.whois_tool import whois_lookup
from tools.dns_tool import dns_enumeration
from tools.portscan_tool import port_scan
from tools.ssl_tool import ssl_inspect
from tools.techstack_tool import tech_stack_detect
from tools.asn_tool import asn_lookup
from tools.fullrecon_tool import full_recon
from tools.cve_tool import cve_lookup
from tools.iprep_tool import ip_reputation

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

if __name__ == "__main__":
    mcp.run()