import re
import xml.etree.ElementTree as ET
import nmap

SCAN_CONFIG = {
    "basic": {"args": "-F --host-timeout 30s"},
    "service": {"args": "-sV -F --host-timeout 120s"},
    "os": {"args": "-O -F --host-timeout 60s"},
    "full": {"args": "-p- --host-timeout 15m"},
    "vuln": {"args": "--script vuln -F --host-timeout 15m --script-timeout 5m"},
}

TIMEOUT_MARGIN = 0.2

PORT_SCAN_TIMEOUT_ERRORS = (TimeoutError, getattr(nmap, "PortScannerTimeout", TimeoutError))

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600}


def _host_timeout_seconds(args: str) -> int:
    match = re.search(r"--host-timeout\s*[=]?\s*(\d+)\s*([smh])?", args)
    if not match:
        return 0
    value = int(match.group(1))
    unit = match.group(2) or "s"
    return value * _DURATION_UNITS[unit]


def _default_timeout(args: str) -> int:
    host_timeout = _host_timeout_seconds(args)
    if host_timeout <= 0:
        raise ValueError(f"No parseable --host-timeout in args: {args!r}")
    return int(host_timeout * (1 + TIMEOUT_MARGIN))


def _extract_host_timeout_status(nmap_output: bytes) -> dict:
    """
    Parse raw nmap XML to extract timedout status per host.
    Returns {host_ip: True/False} for each <host> element.
    Returns empty dict on parse failure.

    Hosts are keyed by IPv4 address when present, falling back to
    IPv6 — matching how python-nmap keys entries in all_hosts().
    """
    try:
        dom = ET.fromstring(nmap_output)
    except ET.ParseError:
        return {}
    result = {}
    for host_el in dom.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is not None:
            addr = addr_el.get("addr")
            if addr:
                result[addr] = host_el.get("timedout") == "true"
    return result


def port_scan(target: str, scan_type: str = "basic", timeout: int | None = None) -> dict:
    """
    Perform Nmap port scan on a target IP or domain.

    scan_type options:
    - "basic"   : Top 100 ports, fast (-F)
    - "service" : Service & version detection (-sV -F)
    - "os"      : OS detection, needs admin (-O -F)
    - "full"    : All 65535 ports, slow (-p-)
    - "vuln"    : Basic vulnerability scripts (--script vuln -F)

    timeout overrides the application-level timeout in seconds. When omitted,
    it defaults to the scan's --host-timeout plus a margin (TIMEOUT_MARGIN).
    """
    if scan_type not in SCAN_CONFIG:
        return {
            "success": False,
            "error": (
                f"Invalid scan_type '{scan_type}'. Valid options are: "
                f"{', '.join(SCAN_CONFIG.keys())}"
            ),
            "valid_scan_types": list(SCAN_CONFIG.keys()),
        }

    if timeout is not None and timeout < 1:
        return {
            "success": False,
            "error": f"Invalid timeout '{timeout}'. Must be a positive number of seconds.",
        }

    try:
        scanner = nmap.PortScanner()

        config = SCAN_CONFIG[scan_type]
        effective_timeout = timeout if timeout is not None else _default_timeout(config["args"])
        scanner.scan(
            hosts=target,
            arguments=config["args"],
            timeout=effective_timeout,
        )

        results = []
        for host in scanner.all_hosts():
            host_data = {
                "host": host,
                "hostname": scanner[host].hostname(),
                "state": scanner[host].state(),
                "protocols": {}
            }

            os_matches = scanner[host].get("osmatch", [])
            if scan_type == "os" and os_matches:
                host_data["os_matches"] = [
                    {k: m.get(k) for k in ("name", "accuracy") if m.get(k)}
                    for m in os_matches
                    if m.get("name") or m.get("accuracy")
                ]

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

        duration = None
        try:
            raw = scanner.scanstats().get("elapsed")
            if raw is not None:
                duration = float(raw)
        except Exception:
            pass

        host_timeout_status = {}
        try:
            raw_xml = scanner.get_nmap_last_output()
            if raw_xml:
                host_timeout_status = _extract_host_timeout_status(raw_xml)
        except Exception:
            pass

        return {
            "success": True,
            "target": target,
            "scan_type": scan_type,
            "hosts_found": len(results),
            "duration_seconds": duration,
            "results": results,
            "host_timeout_status": host_timeout_status or None,
        }

    except PORT_SCAN_TIMEOUT_ERRORS:
        return {"success": False, "error": "Port scan timed out"}
    except nmap.PortScannerError as e:
        return {"success": False, "error": f"Nmap not found or not installed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
