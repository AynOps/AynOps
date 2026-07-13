from datetime import datetime, timezone
from utils.helpers import safe_parse_datetime

def whois_extractor(result , signals):
    if result.get("success"):
        expiry = result.get("expiration_date")
        exp_dt = safe_parse_datetime(expiry)
        if exp_dt:
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            days = (exp_dt - datetime.now(timezone.utc)).days
            signals["domain_expiry_days"] = days
            if days < 0:
                signals["auto_warnings"].append(f"Domain EXPIRED {abs(days)} days ago — domain may be hijackable")
            elif days < 14:
                signals["auto_warnings"].append(f"Domain expires in {days} days — CRITICAL renewal required")
            elif days < 30:
                signals["auto_warnings"].append(f"Domain expires in {days} days — HIGH priority renewal")
    else:
        return