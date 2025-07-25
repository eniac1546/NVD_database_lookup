import requests
import os
from dotenv import load_dotenv
import time
import json
import boto3

load_dotenv()

def get_secret_api_key(secret_name="nvd_api_key_secret", key="NVD_API_KEY", region="us-east-2"):
    # Try to get from environment (local or deployment env)
    api_key = os.getenv(key)
    if api_key:
        print(f"[INFO] Loaded API_KEY from environment variable: {api_key[:6]}***")
        return api_key

    # Try to get from AWS Secrets Manager
    try:
        
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name=region)
        response = client.get_secret_value(SecretId=secret_name)
        secret_str = response['SecretString']
        secret_dict = json.loads(secret_str)
        api_key = secret_dict.get(key)
        if api_key:
            print(f"[INFO] Loaded API_KEY from AWS Secrets Manager: {api_key[:6]}***")
            return api_key
        else:
            print(f"[ERROR] Key '{key}' not found in secret '{secret_name}'")
    except Exception as e:
        print(f"[ERROR] Could not load API_KEY from AWS Secrets Manager: {e}")

    # 3. Neither found, fail with error
    raise RuntimeError(
        "No NVD API key found! Please set NVD_API_KEY in environment/.env for local dev, "
        "or configure it in AWS Secrets Manager under the secret name 'nvd_api_key_secret'.")

# API Key Variable:
API_KEY = get_secret_api_key()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
BATCH_SIZE = 2000
SAFE_SLEEP = 1   # seconds between requests
CACHE_FILE = "cve_cache.json"

# Main in-memory cache
cve_cache = []

def save_cache_to_file():
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cve_cache, f)
    print(f"Saved {len(cve_cache)} CVEs to disk.")

def load_cache_from_file():
    global cve_cache
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            cve_cache = json.load(f)
        cve_cache.sort(key=lambda x: x["published_date"], reverse=True)
        print(f"Loaded {len(cve_cache)} CVEs from disk (sorted by newest).")

    
def fetch_total_cve_count():
    headers = {"apiKey": API_KEY}
    resp = requests.get(NVD_API_URL, headers=headers, params={"resultsPerPage": 1})
    resp.raise_for_status()
    return int(resp.json().get("totalResults", 0))

def fetch_batch(start_index, batch_size):
    headers = {"apiKey": API_KEY}
    params = {
        "resultsPerPage": batch_size,
        "startIndex": start_index
    }
    print(f"[API LOG] NVD API call: startIndex={start_index}, batchSize={batch_size}, apiKey={API_KEY[:6]}***")
    resp = requests.get(NVD_API_URL, headers=headers, params=params)
    if resp.status_code == 429:
        print("NVD rate limit exceeded in fetch_batch!")
        return "RATE_LIMIT"
    resp.raise_for_status()
    cves = []
    for item in resp.json().get("vulnerabilities", []):
        cve = item.get("cve", {})
        cves.append({
            "id": cve.get("id"),
            "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
            "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
            "published_date": cve.get("published", "").split("T")[0]
        })
    return cves

def fetch_all_cves_reverse():
    global cve_cache
    print("Checking for cache file...")
    load_cache_from_file()
    if cve_cache:
        print("CVE Loaded.")
        return

    print("Fetching total CVE count from NVD...")
    total_cves = fetch_total_cve_count()
    print(f"Total CVEs reported: {total_cves}")
    batch_count = (total_cves + BATCH_SIZE - 1) // BATCH_SIZE

    # Fetch newest batches first
    for batch_num in range(batch_count):
        start_index = max(total_cves - (batch_num + 1) * BATCH_SIZE, 0)
        batch_size = BATCH_SIZE if (total_cves - batch_num * BATCH_SIZE) > BATCH_SIZE else (total_cves % BATCH_SIZE or BATCH_SIZE)
        print(f"Fetching batch {batch_num+1}/{batch_count}: startIndex={start_index}, batchSize={batch_size}")
        batch_cves = fetch_batch(start_index, batch_size)
        if batch_cves == "RATE_LIMIT":
            print("NVD API rate limit hit, aborting batch fetch.")
            return "RATE_LIMIT"
        cve_cache[0:0] = batch_cves  # Prepend to keep latest-first
        print(f"Total cached so far: {len(cve_cache)}")
        save_cache_to_file()
        time.sleep(SAFE_SLEEP)
    print("All CVEs have been fetched and cached.")
    #reverse sorting
    cve_cache.sort(key=lambda x: x["published_date"], reverse=True)
    save_cache_to_file()  # Save again after sorting, optional but recommended
    print("All CVEs have been fetched, sorted, and cached.")

def filter_cve_data(severity=None, keyword=None, page=1, limit=10):
    """
    Filters local cache by severity/keyword, paginates.
    """
    cves = cve_cache
    if severity and severity.upper() not in ("", "ALL"):
        cves = [c for c in cves if c.get("severity", "UNKNOWN").upper() == severity.upper()]
    if keyword:
        keyword = keyword.lower()
        cves = [c for c in cves if keyword in c.get("id", "").lower() or keyword in c.get("description", "").lower()]
    total = len(cves)
    total_pages = (total + limit - 1) // limit
    start = (page - 1) * limit
    end = start + limit
    return cves[start:end], total_pages

def get_cve_by_id(cve_id):
    for cve in cve_cache:
        if cve["id"] == cve_id:
            return cve
    return None

def get_latest_cached_date():
    # Returns the latest published date in cache (ISO string, e.g. '2024-07-04')
    if not cve_cache:
        return None
    # Cache is sorted, so first entry is latest
    return cve_cache[0]['published_date']


def update_cache_with_latest_cves():
    latest_cached_date = get_latest_cached_date()
    if not latest_cached_date:
        print("No cache available, skipping update check.")
        return

    pub_start = f"{latest_cached_date}T00:00:00.000Z"
    headers = {"apiKey": API_KEY}
    params = {"resultsPerPage": 2000, "pubStartDate": pub_start}
    print(f"Checking for new CVEs since {pub_start}...")
    print(f"[API LOG] NVD API call: Checking for new CVEs since {pub_start}, apiKey={API_KEY[:6]}***")
    try:
        resp = requests.get(NVD_API_URL, headers=headers, params=params)
        if resp.status_code == 404:
            print("No new CVEs found (API returned 404).")
            return
        resp.raise_for_status()
    except requests.HTTPError as e:
        print(f"Error checking for new CVEs: {e}")
        return

    data = resp.json()
    new_cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        new_cve = {
            "id": cve.get("id"),
            "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
            "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
            "published_date": cve.get("published", "").split("T")[0]
        }
        if all(new_cve["id"] != cached["id"] for cached in cve_cache):
            new_cves.append(new_cve)
    if new_cves:
        print(f"Found {len(new_cves)} new CVEs! Appending to cache.")
        cve_cache[0:0] = new_cves
        cve_cache.sort(key=lambda x: x["published_date"], reverse=True)
        save_cache_to_file()
    else:
        print("No new CVEs found.")