import requests
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()
API_KEY = os.getenv("NVD_API_KEY")

def get_cve_data(limit=10, page=1, keyword=None, severity=None):  # <--- Added severity argument
    """
    Fetches CVE data from the NVD API.
    Supports pagination and optional keyword-based and severity-based search.

    Args:
        limit (int): Number of results per page.
        page (int): Page number (1-based).
        keyword (str): Optional keyword to search (partial match).
        severity (str): Optional severity filter ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

    Returns:
        List of CVE dictionaries with key details.
    """
    today = datetime.utcnow()
    thirty_days_ago = today - timedelta(days=30)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY}

    # --------- Pagination logic ---------
    start_index = (page - 1) * limit

    # --------- Add 'keywordSearch' param if keyword provided ---------
    params = {
        "resultsPerPage": limit,
        "startIndex": start_index,
        "pubStartDate": thirty_days_ago.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": today.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }
    if keyword:
        params["keywordSearch"] = keyword

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            
            # --------- NEW: Filter by severity if specified ---------
            if keyword:
                params["keywordSearch"] = keyword
            
            if severity:
                if cve_severity.upper() != severity.upper():
                    continue

            results.append({
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
                "severity": cve_severity,
                "published_date": cve.get("published", "").split("T")[0]
            })

        return results

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            print("[!] Rate limit exceeded. Please wait and try again.")
            return "RATE_LIMIT"
        print(f"[!] Failed to fetch CVE by ID: {e}")
        return None
    except Exception as e:
        print(f"[!] Other error: {e}")
        return None



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