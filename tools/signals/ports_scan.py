def portscan_extractor(result , signals):
    if result.get("success"):
        open_port_nums = []
        for host in result.get("results", []):
            for proto, port_list in host.get("protocols", {}).items():
                for p in port_list:
                    if p.get("state") == "open":
                        signals["open_ports"].append(
                            f"{p['port']}/tcp ({p.get('service', '?')})"
                        )
                        open_port_nums.append(p.get("port"))

        dangerous = {21: "FTP", 23: "Telnet", 3389: "RDP", 445: "SMB",
                     3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
        for port_num, service in dangerous.items():
            if port_num in open_port_nums:
                signals["auto_warnings"].append(
                    f"Dangerous port open: {port_num} ({service}) — high-value attack target"
                )
    else:
        return