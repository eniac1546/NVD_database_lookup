import requests
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import time

load_dotenv()
API_KEY = os.getenv("NVD_API_KEY")

#helper functio to gather total cve count to process the pagination 

# At module level:
_total_count_cache = {}
_CACHE_TTL = 120  # seconds

def get_total_cve_count(keyword=None, severity=None):
    global _total_count_cache

    cache_key = (keyword or "", severity or "")
    now = time.time()
    # Check cache first
    if cache_key in _total_count_cache:
        value, timestamp = _total_count_cache[cache_key]
        if now - timestamp < _CACHE_TTL:
            return value

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY}
    params = {"resultsPerPage": 1}
    if keyword:
        params["keywordSearch"] = keyword
    if severity:
        params["cvssV3Severity"] = severity.upper()
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        total = data.get("totalResults", 0)
        # Store in cache
        _total_count_cache[cache_key] = (total, now)
        return total
    except Exception as e:
        print(f"[!] Failed to get total CVE count: {e}")
        # If cache exists, fallback to old value to avoid 0 on error
        if cache_key in _total_count_cache:
            value, timestamp = _total_count_cache[cache_key]
            return value
        return 0



def get_cve_data(limit=10, page=1, keyword=None, severity=None):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY}
    total_results = get_total_cve_count(keyword, severity)
    total_pages = (total_results + limit - 1) // limit

    # --- Backward pagination (latest first) ---
    start_index = total_results - (page * limit)
    if start_index < 0:
        limit = limit + start_index  # start_index is negative, so reduce limit
        start_index = 0

    params = {
        "resultsPerPage": limit,
        "startIndex": start_index
    }
    if keyword:
        params["keywordSearch"] = keyword

    # Only send param for valid severities (NOT for "UNKNOWN" or blank)
    valid_sevs = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    if severity and severity.upper() in valid_sevs:
        params["cvssV3Severity"] = severity.upper()
    # If severity is "UNKNOWN" or blank or "All", don't add to params

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            results.append({
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
                "severity": cve_severity,
                "published_date": cve.get("published", "").split("T")[0]
            })

        # --- Strict post-filtering for all severities ---
        if severity and severity.upper() != "ALL":
            if severity.upper() == "UNKNOWN":
                results = [c for c in results if c["severity"].upper() in ("", "UNKNOWN")]
                # Sort by published_date descending (latest first)
                results.sort(key=lambda c: c["published_date"] or "1900-01-01", reverse=True)
            else:
                results = [c for c in results if c["severity"].upper() == severity.upper()]

        has_next = page < total_pages
        return results, has_next, total_pages

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            print("NVD rate limit exceeded. Please wait a minute and try again. ")
            return "RATE_LIMIT", False, total_pages
        print(f"[!] Failed to fetch CVE by ID: {e}")
        return None, False, total_pages
    except Exception as e:
        print(f"[!] Other error: {e}")
        return None, False, total_pages




def get_cve_by_id(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY}
    params = {"cveId": cve_id}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        items = data.get("vulnerabilities", [])
        if not items:
            return None
        cve = items[0].get("cve", {})
        return {
            "id": cve.get("id"),
            "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
            "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
            "published_date": cve.get("published", "").split("T")[0]
        }
    except Exception as e:
        print(f"[!] Failed to fetch CVE by ID: {e}")
        return None