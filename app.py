from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for
from utils import get_cve_by_id, filter_cve_data, fetch_all_cves_reverse, update_cache_with_latest_cves

import io
import csv
import json
import re

app = Flask(__name__)

# Fetch/load all CVEs on startup (from disk or API)
fetch_all_cves_reverse()

@app.route('/')
def index():
    rate_limit_error = update_cache_with_latest_cves()   # <-- capture the return value here!
    page = request.args.get('page', default=1, type=int)
    severity = request.args.get('severity', '')
    cve_list, total_pages = filter_cve_data(severity=severity, page=page, limit=10)
    error = None  # default value
    if rate_limit_error == "RATE_LIMIT":
        error = "RATE_LIMIT"


    # Handle page exceeded
    if total_pages and page > total_pages:
        cve_list, total_pages = filter_cve_data(severity=severity, page=total_pages, limit=10)
        return render_template(
            "index.html",
            cve_list=cve_list,
            error="PAGE_EXCEEDED",
            page=total_pages,
            selected_severity=severity,
            total_pages=total_pages
        )

    # Handle empty list
    if not cve_list:
        return render_template(
            "index.html",
            cve_list=[],
            error=error,
            page=page,
            selected_severity=severity,
            total_pages=total_pages
        )

    # Render normally if no errors
    return render_template(
        "index.html",
        cve_list=cve_list,
        error=None,
        page=page,
        selected_severity=severity,
        total_pages=total_pages
    )

@app.route('/vulnerabilities', methods=['GET'])
def get_vulns():
    limit = request.args.get('limit', default=10, type=int)
    results, _ = filter_cve_data(limit=limit)
    return jsonify(results)

@app.route('/vulnerability/<cve_id>')
def get_vuln(cve_id):
    cve = get_cve_by_id(cve_id)
    if not cve:
        return f"CVE Not Found: {cve_id}", 404
    return render_template("cve_detail.html", cve=cve)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '').strip()
    severity = request.args.get('severity', '').strip()

    if not query:
        return redirect(url_for('filter_route', severity=severity))

    cve_id_pattern = re.compile(r"(CVE-)?(\d{4})-(\d{4,7})", re.IGNORECASE)
    partial_cve_pattern = re.compile(r"(CVE-)?(\d{4})$", re.IGNORECASE)
    is_cve_id = cve_id_pattern.fullmatch(query)
    is_partial_cve = partial_cve_pattern.fullmatch(query)
    is_cve_year = re.fullmatch(r"\d{4}", query)
    is_numeric = query.isdigit()

    # Exact CVE ID (from cache, not API)
    if is_cve_id:
        cve_id = f"CVE-{is_cve_id.group(2)}-{is_cve_id.group(3)}"
        cve = get_cve_by_id(cve_id)
        if cve:
            return render_template("cve_detail.html", cve=cve)
        return redirect(url_for('filter_route', q=cve_id, severity=severity, page=1))

    # Partial CVE or year search
    if is_partial_cve or is_cve_year or (is_numeric and len(query) == 4):
        year = is_partial_cve.group(2) if is_partial_cve else query
        search_term = f"CVE-{year}-"
        return redirect(url_for('filter_route', q=search_term, severity=severity, page=1))

    # Quoted phrase search
    if query.startswith('"') and query.endswith('"') and len(query) > 2:
        phrase = query[1:-1]
        return redirect(url_for('filter_route', q=phrase, severity=severity, page=1))

    # Otherwise, general keyword search
    return redirect(url_for('filter_route', q=query, severity=severity, page=1))

@app.route('/filter')
def filter_route():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '').strip()
    keyword = request.args.get('q', '').strip()
    cve_list, total_pages = filter_cve_data(severity=severity, keyword=keyword, page=page, limit=10)

    error = None
    if not cve_list:
        error = "No results found."

    if total_pages > 0 and page > total_pages:
        cve_list, total_pages = filter_cve_data(severity=severity, keyword=keyword, page=total_pages, limit=10)
        error = "PAGE_EXCEEDED"
        page = total_pages

    return render_template(
        "index.html",
        cve_list=cve_list,
        error=error,
        page=page,
        total_pages=total_pages,
        selected_severity=severity,
        search_query=keyword
    )

@app.route('/export/csv', defaults={'cve_id': None})
@app.route('/export/csv/<cve_id>')
def export_csv(cve_id):
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['CVE ID', 'Description', 'Severity', 'Published Date'])
    if cve_id:
        cve = get_cve_by_id(cve_id)
        if not cve:
            return "CVE not found", 404
        rows = [[cve['id'], cve['description'], cve['severity'], cve['published_date']]]
        filename = f'{cve_id}.csv'
    else:
        severity = request.args.get('severity', '')
        keyword = request.args.get('q', '').strip()
        page = request.args.get('page', type=int)
        # Determine if exporting page or all filtered results
        if page:  # Export current page only
            limit = 10  # match your UI page size
            cves, _ = filter_cve_data(severity=severity, keyword=keyword, page=page, limit=limit)
        else:  # Export all matching results
            cves, _ = filter_cve_data(severity=severity, keyword=keyword, page=1, limit=1000000)
        rows = [[cve['id'], cve['description'], cve['severity'], cve['published_date']] for cve in cves]
        filename = 'cves.csv'
    cw.writerows(rows)
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name=filename)


@app.route('/export/json', defaults={'cve_id': None})
@app.route('/export/json/<cve_id>')
def export_json(cve_id):
    if cve_id:
        cve = get_cve_by_id(cve_id)
        if not cve:
            return jsonify({'error': 'CVE not found'}), 404
        data = cve
        filename = f'{cve_id}.json'
    else:
        severity = request.args.get('severity', '')
        keyword = request.args.get('q', '').strip()
        page = request.args.get('page', type=int)
        if page:  # Export current page only
            limit = 10
            data, _ = filter_cve_data(severity=severity, keyword=keyword, page=page, limit=limit)
        else:  # Export all matching results
            data, _ = filter_cve_data(severity=severity, keyword=keyword, page=1, limit=1000000)
        filename = 'cves.json'
    response = app.response_class(
        response=json.dumps(data, indent=2),
        mimetype='application/json'
    )
    response.headers.set('Content-Disposition', 'attachment', filename=filename)
    return response

@app.route('/health')
def health_check():
    from utils import API_KEY
    import requests

    # Quick check: hit the NVD API for one record (lightweight)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY}
    params = {"resultsPerPage": 1}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            return jsonify({"status": "ok", "nvd_api_status": "reachable", "api_key_status": "valid"}), 200
        elif resp.status_code == 403:
            return jsonify({"status": "fail", "nvd_api_status": "reachable", "api_key_status": "forbidden"}), 403
        elif resp.status_code == 429:
            return jsonify({"status": "fail", "nvd_api_status": "rate_limited", "api_key_status": "rate_limited"}), 429
        else:
            return jsonify({"status": "fail", "nvd_api_status": f"HTTP {resp.status_code}", "api_key_status": "unknown"}), 500
    except Exception as e:
        return jsonify({"status": "fail", "nvd_api_status": "unreachable", "api_key_status": "unknown", "error": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True)
