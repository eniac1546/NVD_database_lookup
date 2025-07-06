import requests
import os
from dotenv import load_dotenv
import time

load_dotenv()
API_KEY = os.getenv("NVD_API_KEY")
print("ENV NVD_API_KEY:", os.environ.get("NVD_API_KEY"))
print("Loaded API_KEY:", API_KEY)

BATCH_SIZE = 2000
CACHE_TTL = 1800  # 30 min
_total_count_cache = {}
cve_superbatch_cache = {}
cve_superbatch_cache_ts = {}

# --- New: cache total count to avoid hitting the API repeatedly ---
TOTAL_CVE_COUNT = None
TOTAL_CVE_COUNT_TS = 0
COUNT_TTL = 1800  # 30 min

_total_cve_count = None
_total_cve_count_ts = 0

def get_total_cve_count():
    global _total_cve_count, _total_cve_count_ts
    if _total_cve_count and time.time() - _total_cve_count_ts < 3600:
        return _total_cve_count
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY} if API_KEY else {}
    resp = requests.get(url, headers=headers, params={"resultsPerPage": 1})
    resp.raise_for_status()
    data = resp.json()
    _total_cve_count = int(data.get("totalResults", 0))
    _total_cve_count_ts = time.time()
    return _total_cve_count

def get_total_cve_count_filtered(keyword=None, severity=None):
    """Get total count for filtered search results"""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY} if API_KEY else {}
    params = {"resultsPerPage": 1}
    
    if keyword:
        params["keywordSearch"] = keyword
    if severity and severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        params["cvssV3Severity"] = severity.upper()
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        return int(data.get("totalResults", 0))
    except Exception as e:
        print(f"Failed to fetch total count: {e}")
        return 0

def fetch_superbatch(super_batch_start):
    """
    Fetch BATCH_SIZE CVEs in reverse order (latest-first).
    super_batch_start is 0 for latest, 2000 for next 2000 older, etc.
    """
    batch_results = []
    headers = {"apiKey": API_KEY} if API_KEY else {}
    now = time.time()

    total_cves = get_total_cve_count()
    # Calculate the true startIndex for NVD API, which expects 0=oldest
    api_start_index = max(total_cves - super_batch_start - BATCH_SIZE, 0)
    results_per_page = min(BATCH_SIZE, total_cves - super_batch_start) if (total_cves - super_batch_start) < BATCH_SIZE else BATCH_SIZE

    params = {"resultsPerPage": results_per_page, "startIndex": api_start_index}
    resp = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        headers=headers, params=params
    )
    resp.raise_for_status()
    data = resp.json()
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        batch_results.append({
            "id": cve.get("id"),
            "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
            "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
            "published_date": cve.get("published", "").split("T")[0]
        })
    # API returns oldest-first, so reverse here to always get latest first
    batch_results.reverse()
    cve_superbatch_cache[super_batch_start] = batch_results
    cve_superbatch_cache_ts[super_batch_start] = now
    return batch_results

def get_superbatch_for_index(index):
    """
    Reverse paging: index 0 is latest. Batches are counted from latest.
    """
    total_cves = get_total_cve_count()
    # Figure out the batch offset from latest
    # Page 1: index 0 (latest), so batch_start = 0
    # Page 2: index limit (e.g. 10), batch_start = (10 // 2000) * 2000 = 0
    batch_start = (index // BATCH_SIZE) * BATCH_SIZE
    now = time.time()
    if (batch_start not in cve_superbatch_cache or
        now - cve_superbatch_cache_ts.get(batch_start, 0) > CACHE_TTL):
        fetch_superbatch(batch_start)
    return cve_superbatch_cache[batch_start]


# Add this debug function to your utils.py to help troubleshoot
def debug_severity_filter(cve_list, severity):
    """Debug helper to see what's happening with severity filtering"""
    print(f"Debug: Filtering {len(cve_list)} CVEs with severity '{severity}'")
    
    if not severity or severity.upper() == "ALL":
        print("Debug: No severity filter applied")
        return cve_list
    
    filtered = []
    for cve in cve_list:
        cve_severity = cve.get("severity", "UNKNOWN").upper()
        if severity.upper() == "UNKNOWN":
            if cve_severity in ("", "UNKNOWN"):
                filtered.append(cve)
        else:
            if cve_severity == severity.upper():
                filtered.append(cve)
    
    print(f"Debug: After filtering, {len(filtered)} CVEs remain")
    return filtered


# Update your filter_cve_data function to use proper severity filtering
def filter_cve_data(severity=None, keyword=None, page=1, limit=10):
    total_cves = get_total_cve_count()
    
    print(f"Debug filter_cve_data: severity='{severity}', keyword='{keyword}', page={page}, limit={limit}")
    
    # If we have keyword search, we need to use search_cve_data instead
    if keyword:
        return search_cve_data(keyword=keyword, severity=severity, page=page, limit=limit)
    
    # Calculate the indexes for the current page, latest first
    start_index = (page - 1) * limit
    end_index = min(start_index + limit, total_cves)

    batch = get_superbatch_for_index(start_index)
    # If end_index crosses into next batch, fetch that batch too and combine
    if (end_index - 1) // BATCH_SIZE != start_index // BATCH_SIZE:
        next_batch = get_superbatch_for_index(end_index)
        batch += next_batch

    # Apply severity filter FIRST, before slicing
    all_data = batch
    if severity and severity.upper() not in ("", "ALL"):
        print(f"Debug: Applying severity filter '{severity}'")
        if severity.upper() == "UNKNOWN":
            all_data = [c for c in all_data if c.get("severity", "UNKNOWN").upper() in ("", "UNKNOWN")]
        else:
            all_data = [c for c in all_data if c.get("severity", "UNKNOWN").upper() == severity.upper()]
        print(f"Debug: After severity filter, {len(all_data)} CVEs remain")

    # Apply keyword filter if provided
    if keyword:
        print(f"Debug: Applying keyword filter '{keyword}'")
        all_data = [c for c in all_data if keyword.lower() in (c.get("id", "").lower() + c.get("description", "").lower())]
        print(f"Debug: After keyword filter, {len(all_data)} CVEs remain")

    # Now slice to only show correct page items
    # Note: When filtering, we need to recalculate pagination based on filtered results
    if severity and severity.upper() not in ("", "ALL"):
        # For filtered results, we need to handle pagination differently
        total_filtered = len(all_data)
        total_pages = (total_filtered + limit - 1) // limit if total_filtered > 0 else 1
        
        # Slice the filtered results for this page
        page_start = (page - 1) * limit
        page_end = page_start + limit
        results = all_data[page_start:page_end]
        
        has_next = page < total_pages
        return results, has_next, total_pages
    else:
        # For unfiltered results, use original pagination logic
        results = all_data[start_index % BATCH_SIZE : (start_index % BATCH_SIZE) + limit]
        total_pages = (total_cves + limit - 1) // limit
        has_next = page < total_pages
        return results, has_next, total_pages




# Make sure your search_cve_data function properly handles empty severity
def search_cve_data(keyword=None, severity=None, page=1, limit=10):
    """
    Search CVEs using NVD API with keyword and severity filters.
    Fallback to local cache if the API call fails.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY} if API_KEY else {}

    print(f"API Key present: {bool(API_KEY)}")
    if API_KEY:
        print(f"API Key starts with: {API_KEY[:10]}...")

    # Clean up severity parameter
    if severity:
        severity = severity.strip().upper()
        if severity in ("", "ALL"):
            severity = None

    # Get total results for pagination
    total_results = get_total_cve_count_filtered(keyword, severity)
    total_pages = (total_results + limit - 1) // limit if total_results > 0 else 0

    # Calculate start index for current page
    start_index = (page - 1) * limit
    fetch_limit = min(limit, max(0, total_results - start_index))

    if total_results == 0 or fetch_limit <= 0 or start_index >= total_results:
        return [], False, total_pages

    params = {
        "resultsPerPage": fetch_limit,
        "startIndex": start_index
    }
    if keyword:
        params["keywordSearch"] = keyword
    if severity and severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        params["cvssV3Severity"] = severity

    try:
        print(f"API search params: {params}")
        print(f"API search URL: {url}")
        response = requests.get(url, headers=headers, params=params)
        print(f"Response status: {response.status_code}")
        response.raise_for_status()
        data = response.json()
        print(f"API returned {len(data.get('vulnerabilities', []))} results")

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

        has_next = page < total_pages
        return results, has_next, total_pages

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            print("NVD rate limit exceeded.")
            return "RATE_LIMIT", False, total_pages
        print(f"HTTP error: {e}")
        # Fallback to local cache/filter if NVD fails
        if keyword:
            print("Trying local cache fallback...")
            try:
                results, has_next, total_pages = filter_cve_data(keyword=keyword, severity=severity, page=page, limit=limit)
                return results, has_next, total_pages
            except Exception as local_e:
                print(f"Local cache fallback failed: {local_e}")
        return [], False, total_pages
    except Exception as e:
        print(f"Search error: {e}")
        # Fallback to local cache/filter if NVD fails
        if keyword:
            print("Trying local cache fallback...")
            try:
                results, has_next, total_pages = filter_cve_data(keyword=keyword, severity=severity, page=page, limit=limit)
                return results, has_next, total_pages
            except Exception as local_e:
                print(f"Local cache fallback failed: {local_e}")
        return [], False, total_pages
    
def get_cve_by_id(cve_id):
    """
    Get CVE by ID - first check cache, then API if not found
    """
    # Check all loaded batches first
    for batch in cve_superbatch_cache.values():
        for cve in batch:
            if cve["id"] == cve_id:
                return cve
    
    # If not found in cache, try API search
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": API_KEY} if API_KEY else {}
        params = {"cveId": cve_id}
        
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        if data.get("vulnerabilities"):
            cve = data["vulnerabilities"][0].get("cve", {})
            return {
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
                "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
                "published_date": cve.get("published", "").split("T")[0]
            }
    except Exception as e:
        print(f"Error fetching CVE {cve_id}: {e}")
    
    return None