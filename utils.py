import requests
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()
API_KEY = os.getenv("NVD_API_KEY")

def get_cve_data(limit=10):
    today = datetime.utcnow()
    thirty_days_ago = today - timedelta(days=30)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        "apiKey": API_KEY
    }

    params = {
        "resultsPerPage": limit,
        "startIndex": 0,
        "pubStartDate": thirty_days_ago.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": today.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        # Parse CVEs into simplified format
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            results.append({
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
                "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
                "published_date": cve.get("published", "").split("T")[0]
            })

        return results
    except Exception as e:
        print(f"[!] Failed to fetch CVE data: {e}")
        return []
