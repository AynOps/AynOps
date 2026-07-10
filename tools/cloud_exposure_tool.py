from utils.helpers import is_valid_domain
import tldextract
import requests
from concurrent.futures import ThreadPoolExecutor , as_completed

COMMON_SUFFIXES = [
    "",
    "assets",
    "backup",
    "backups",
    "dev",
    "prod",
    "production",
    "staging",
    "stage",
    "test",
    "media",
    "static",
    "files",
    "uploads",
    "images",
    "cdn",
    "storage",
    "data",
]

SUBDOMAIN_PREFIXES = [
    "assets",
    "backup",
    "media",
    "static",
    "cdn",
    "files",
]

def generate_bucket_names(company_name: str) -> list:
    """Generate bucket names for the given company names and return list"""
    bucket_names = []

    for i in COMMON_SUFFIXES:
        if i == "":
            bucket_names.append(company_name)
        else:
            x = company_name + "-" + i
            bucket_names.append(x)

    for i in SUBDOMAIN_PREFIXES:
        bucket_names.append(i + "." + company_name + ".com")

    bucket_names = list(dict.fromkeys(bucket_names))
    return bucket_names

def url_response(url: str) -> dict:
    """Check bucket urls and return the response results"""
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "AynOps Recon"})
    except Exception as e:
        return {
            "url": url,
            "status": "ERROR",
            "severity": "INFO",
            "note": str(e)
        }

    if response.status_code == 200:
        return {
                "url": url ,
                "status":"PUBLIC" , 
                "severity":"CRITICAL" , 
                "note": "Bucket is publicly listable — files are exposed"
            }
    elif response.status_code == 403:
        return {
                "url": url ,
                "status": "EXISTS_PRIVATE" , 
                "severity":"INFO" ,
                "note": "Bucket exists but is not publicly accessible"
            }
    
    elif response.status_code == 404:
        return {
            "url": url,
            "status": "NOT_FOUND" ,
            "severity": "INFO" ,
            "note":"Bucket does not exist"
        }
    
    else:
        return {
            "url":url,
            "status":"NOT_FOUND",
            "severity":"INFO",
            "note": f"URL Respond with status code {response.status_code}"
        }
    
def check_provider(bucket, provider):
    """Build url with bucket names and cloud provider , then send url for checking to url_response"""
    if provider == "AWS S3":
        url = "https://" + bucket + ".s3.amazonaws.com/"
    elif provider == "GCP":
        url = "https://storage.googleapis.com/" + bucket + "/"
    elif provider == "AZURE":
        url = "https://" + bucket + ".blob.core.windows.net/" + bucket + "?restype=container&comp=list"
    else:
        raise ValueError(f"Unknown provider: {provider}")

    result = url_response(url)
    return {
        "bucket_name": bucket ,
        "provider":provider,
        **result
    }

def cloud_exposure_check(domain: str) -> dict:
    """Takes domain as input and return complete metrics and results for cloud urls exposed or not for a company"""
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}
    
    company_name = tldextract.extract(domain).domain
    bucket_names = generate_bucket_names(company_name)
    providers = ["AWS S3" , "GCP" , "AZURE"]

    findings = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_provider, bucket, provider) for bucket in bucket_names for provider in providers]
        for future in as_completed(futures):
            try:
                findings.append(future.result())
            except Exception as e:
                findings.append({
                    "status": "ERROR",
                    "note": str(e)
                })
        
    total_exposed = len([item for item in findings if item.get("status") == "PUBLIC"])
    total_private = len([item for item in findings if item.get("status") == "EXISTS_PRIVATE"])
    total_not_found = len([item for item in findings if item.get("status") == "NOT_FOUND"])

    return {
        "success": True,
        "domain": domain ,
        "buckets_checked": len(bucket_names) * 3 ,
        "findings": findings ,
        "total_exposed": total_exposed,
        "total_private": total_private,
        "total_not_found": total_not_found
    }