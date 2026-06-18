import os
from urllib.parse import urlparse
import ipaddress
import requests
import socket

def asn_lookup(target: str) -> dict:
    """
    Find the Autonomous System Number (ASN) and 
    organization for a domain or IP. Useful for 
    identifying hosting provider and network ownership.

    API Key: https://ipapi.com

    Args:
        target (str): Domain or IP address

    Returns:
        dict: Geolocation and ASN details matching the expected signature
    """
    try:
        target = target.strip()
        api_key = os.getenv("IP_API_KEY")
        
        if not api_key:
            return {
                "success": False,
                "error": (
                    "IP_API_KEY environment variable is not set. "
                    "Get a free key at https://ipapi.com and add it to "
                    "your Claude Desktop config under 'IP_API_KEY'."
                )
            }

        if "://" in target:
            parsed = urlparse(target)
            target = parsed.netloc if parsed.netloc else parsed.path

        if target.count(":") == 1 and not target.startswith("["):
            host, possible_port = target.rsplit(":", 1)
            if possible_port.isdigit():
                target = host

        try:
            ipaddress.ip_address(target)
            ip = target
        except ValueError:
            ip = socket.getaddrinfo(target, None)[0][4][0]


        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json"
        }
        response = requests.get(
            f"https://api.ipapi.com/api/{ip}?access_key={api_key}",
            timeout=15,
            headers=headers
        )

        if response.status_code != 200:
            return {
                "success": False,
                "error": f"API request failed with status {response.status_code}"
            }

        data = response.json()

        if data.get("success") is False:
            error_info = data.get("error", {})
            return {
                "success": False,
                "error": error_info.get("info", "API returned an error state")
            }

        connection = data.get("connection", {})
        
        asn_val = connection.get("asn")
        if asn_val and not str(asn_val).startswith("AS"):
            asn_string = f"AS{asn_val}"
        else:
            asn_string = str(asn_val) if asn_val else None

        return {
            "success": True,
            "ip": ip,
            "asn": asn_string,
            "org": connection.get("org"),
            "isp": connection.get("isp"), 
            "country": data.get("country_name"),
            "region": data.get("region_name"),
            "city": data.get("city")
        }

    except socket.gaierror:
        return {"success": False, "error": "Failed to resolve domain"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}