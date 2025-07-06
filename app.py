from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for
from utils import get_cve_by_id, filter_cve_data, cve_superbatch_cache, search_cve_data
from flask import send_file
import io
import csv
import json
import re

app = Flask(__name__)

@app.route('/')
def index():
    page = request.args.get('page', default=1, type=int)
    severity = request.args.get('severity', '')

    # Use the new cache-based filtering
    cve_list, has_next, total_pages = filter_cve_data(severity=severity, page=page, limit=10)

    # Handle page exceeded
    if total_pages and page > total_pages:
        cve_list, has_next, _ = filter_cve_data(severity=severity, page=total_pages, limit=10)
        return render_template(
            "index.html",
            cve_list=cve_list,
            error="PAGE_EXCEEDED",
            page=total_pages,
            has_next=has_next,
            selected_severity=severity,
            total_pages=total_pages
        )

    # Handle empty list
    if not cve_list:
        return render_template(
            "index.html",
            cve_list=[],
            error="No results found.",
            page=page,
            has_next=False,
            selected_severity=severity,
            total_pages=total_pages
        )

    # Render normally if no errors
    return render_template(
        "index.html",
        cve_list=cve_list,
        error=None,
        page=page,
        has_next=has_next,
        selected_severity=severity,
        total_pages=total_pages
    )

@app.route('/vulnerabilities', methods=['GET'])
def get_vulns():
    limit = request.args.get('limit', default=10, type=int)
    results, _, _ = filter_cve_data(limit=limit)
    return jsonify(results)

@app.route('/vulnerability/<cve_id>')
def get_vuln(cve_id):
    """
    Fetch the vulnerability details by CVE ID from the NVD API.
    """
    cve = get_cve_by_id(cve_id)
    if not cve:
        return f"CVE Not Found: {cve_id}", 404
    return render_template("cve_detail.html", cve=cve)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '').strip()
    severity = request.args.get('severity', '').strip()  # Get severity from search form
    
    if not query:
        return redirect(url_for('filter_route', severity=severity))

    # Enhanced CVE ID pattern matching
    cve_id_pattern = re.compile(r"(CVE-)?(\d{4})-(\d{4,7})", re.IGNORECASE)
    partial_cve_pattern = re.compile(r"(CVE-)?(\d{4})$", re.IGNORECASE)  # For partial matches like CVE-2025
    is_cve_id = cve_id_pattern.fullmatch(query)
    is_partial_cve = partial_cve_pattern.fullmatch(query)
    is_cve_year = re.fullmatch(r"\d{4}", query)
    is_numeric = query.isdigit()

    # Try exact CVE ID search first
    if is_cve_id:
        cve_id = f"CVE-{is_cve_id.group(2)}-{is_cve_id.group(3)}"
        cve_list, has_next, total_pages = search_cve_data(keyword=cve_id, severity=severity, page=1, limit=1)
        if cve_list and cve_list != "RATE_LIMIT" and cve_list[0]['id'].upper() == cve_id.upper():
            return render_template("cve_detail.html", cve=cve_list[0])
        # Fallback to keyword search if exact match not found
        return redirect(url_for('filter_route', q=cve_id, severity=severity, page=1))

    # Handle partial CVE ID (like CVE-2025 or just 2025)
    if is_partial_cve:
        year = is_partial_cve.group(2)
        search_term = f"CVE-{year}-"  # This will match all CVEs from that year
        return redirect(url_for('filter_route', q=search_term, severity=severity, page=1))

    # Try year search (e.g. 2023 returns all 2023 CVEs)
    if is_cve_year:
        search_term = f"CVE-{query}-"
        return redirect(url_for('filter_route', q=search_term, severity=severity, page=1))

    # Try numeric search as year
    if is_numeric and len(query) == 4:
        search_term = f"CVE-{query}-"
        return redirect(url_for('filter_route', q=search_term, severity=severity, page=1))

    # Try quoted phrase search (strip quotes, treat as exact phrase)
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

    print(f"Filter route - Page: {page}, Severity: '{severity}', Keyword: '{keyword}'")

    if keyword:
        # Use API-based search for pagination with proper severity handling
        result = search_cve_data(keyword=keyword, severity=severity, page=page, limit=10)
        
        # Handle rate limit response
        if result[0] == "RATE_LIMIT":
            return render_template(
                "index.html",
                cve_list=[],
                error="RATE_LIMIT",
                page=page,
                has_next=False,
                total_pages=0,
                selected_severity=severity,
                search_query=keyword
            )
        
        cve_list, has_next, total_pages = result
    else:
        # Use local cache/batch for fast latest-batch browsing
        cve_list, has_next, total_pages = filter_cve_data(severity=severity, page=page, limit=10)

    error = None
    if not cve_list:
        error = "No results found."

    # Fix: Correct page if exceeded (works for both search modes)
    if total_pages > 0 and page > total_pages:
        if keyword:
            result = search_cve_data(keyword=keyword, severity=severity, page=total_pages, limit=10)
            if result[0] != "RATE_LIMIT":
                cve_list, has_next, _ = result
        else:
            cve_list, has_next, _ = filter_cve_data(severity=severity, page=total_pages, limit=10)
        error = "PAGE_EXCEEDED"
        page = total_pages

    print(f"Returning {len(cve_list) if cve_list else 0} results")

    return render_template(
        "index.html",
        cve_list=cve_list,
        error=error,
        page=page,
        has_next=has_next,
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
        # Export all cached data
        cve_list = []
        for batch in cve_superbatch_cache.values():
            cve_list.extend(batch)
        rows = [[cve['id'], cve['description'], cve['severity'], cve['published_date']] for cve in cve_list]
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
        # Support optional filters for bulk export
        severity = request.args.get('severity', '')
        keyword = request.args.get('q', '').strip()
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 0, type=int)  # 0 means "all"
        if limit > 0:
            data, _, _ = filter_cve_data(severity=severity, keyword=keyword, page=page, limit=limit)
        else:
            # Export all (filtered) data
            data, _, _ = filter_cve_data(severity=severity, keyword=keyword, page=1, limit=1000000)
        filename = 'cves.json'
    response = app.response_class(
        response=json.dumps(data, indent=2),
        mimetype='application/json'
    )
    response.headers.set('Content-Disposition', 'attachment', filename=filename)
    return response

if __name__ == '__main__':
    app.run(debug=True)