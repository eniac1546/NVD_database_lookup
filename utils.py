import requests
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()
API_KEY = os.getenv("NVD_API_KEY")

#helper functio to gather total cve count to process the pagination 

def get_total_cve_count(keyword=None, severity=None):
    """
    Fetches the total number of CVEs from the NVD API (with optional keyword/severity).
    """
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
        return data.get("totalResults", 0)
    except Exception as e:
        print(f"[!] Failed to get total CVE count: {e}")
        return 0


def get_cve_data(limit=50, page=1, keyword=None, severity=None):
    """
    Fetches CVE data from the NVD API, with reverse paging to show latest first.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY}
    # --------- REVERSE PAGINATION LOGIC ---------
    total_results = get_total_cve_count(keyword, severity)
    # Calculate reverse paging start index:
    start_index = max(total_results - page * limit, 0)
    params = {
        "resultsPerPage": limit + 1,
        "startIndex": start_index
    }
    if keyword:
        params["keywordSearch"] = keyword
    if severity:
        params["cvssV3Severity"] = severity.upper()  # Use API's filter param

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            # No local filter needed; API handles it
            results.append({
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
                "severity": cve_severity,
                "published_date": cve.get("published", "").split("T")[0]
            })
        has_next = start_index > 0  # If there are earlier pages
        if len(results) > limit:
            results = results[:limit]
        return results, has_next

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            print("[!] Rate limit exceeded. Please wait and try again.")
            return "RATE_LIMIT", False
        print(f"[!] Failed to fetch CVE by ID: {e}")
        return None, False
    except Exception as e:
        print(f"[!] Other error: {e}")
        return None, False




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