from flask import Flask, render_template,jsonify, request
from utils import get_cve_data, get_cve_by_id
from flask import send_file
import io
import csv
import json

app = Flask(__name__)

@app.route('/')
def index():
    page = request.args.get('page', default=1, type=int)
    severity = request.args.get('severity', '')

    # Fetch CVE data
    result = get_cve_data(limit=10, page=page, severity=severity)
    if len(result) == 3:
        cve_list, has_next, total_pages = result
    else:
        cve_list, has_next = result
        total_pages = 1  # fallback

    # Handle errors (rate limit, string error, etc)
    if isinstance(cve_list, str):
        error_msg = (
            "NVD rate limit exceeded. Please wait a minute and try again."
            if cve_list == "RATE_LIMIT"
            else cve_list
        )
        return render_template(
            "index.html",
            cve_list=[],
            error=error_msg,
            page=page,
            has_next=False,
            selected_severity=severity
        )

     # Handle page exceeded
    if total_pages and page > total_pages:
        last_result = get_cve_data(limit=10, page=total_pages, severity=severity)
        if len(last_result) == 3:
            last_page_cves, has_next, _ = last_result
        else:
            last_page_cves, has_next = last_result
        return render_template(
            "index.html",
            cve_list=last_page_cves,
            error="PAGE_EXCEEDED",
            page=total_pages,
            has_next=has_next,
            selected_severity=severity
        )

    # Handle empty list
    if not cve_list:
        return render_template(
            "index.html",
            cve_list=[],
            error="No results found.",
            page=page,
            has_next=False,
            selected_severity=severity
        )

    # Render normally if no errors
    return render_template(
        "index.html",
        cve_list=cve_list,
        error=None,
        page=page,
        has_next=has_next,
        selected_severity=severity
    )



@app.route('/vulnerabilities', methods=['GET'])
def get_vulns():
    """
    Fetch all CVEs from the NVD API.
    Optional query param: limit (default 10)
    Example: /vulnerabilities?limit=100

    """
    limit = request.args.get('limit', default=10, type=int)
    cve_list = get_cve_data(limit=limit)
    return jsonify(cve_list)


@app.route('/vulnerability/<cve_id>')
def get_vuln(cve_id):
    """
    Fetch the vulnerability deatails by CVE Ids from the NVD API.

    """
    cve = get_cve_by_id(cve_id)
    if not cve:
        return render_template("cve_not_found.html", cve_id=cve_id), 404
    return render_template("cve_detail.html", cve=cve)


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '').strip()
    page = request.args.get('page', default=1, type=int)
    severity = request.args.get('severity', '')

    # If searching for a specific CVE ID first
    if query:
        cve = get_cve_by_id(query)
        if cve == "RATE_LIMIT":
            return render_template(
                "index.html",
                cve_list=[],
                error="NVD rate limit exceeded. Please wait a minute and try again.",
                page=page,
                search_query=query,
                has_next=False,
                total_pages=1,
                selected_severity=severity
            )
        if cve:
            if severity and cve.get('severity', '').upper() != severity.upper():
                return render_template(
                    "index.html",
                    cve_list=[],
                    error=f"No results found for '{query}' with severity '{severity}'." if severity else f"No results found for '{query}'.",
                    page=page,
                    search_query=query,
                    has_next=False,
                    total_pages=1,
                    selected_severity=severity
                )
            return render_template("cve_detail.html", cve=cve)
        else:
            cve_list, has_next, total_pages = get_cve_data(limit=10, page=page, keyword=query, severity=severity)

            # ---------- PAGE EXCEEDS HANDLING FOR QUERY BRANCH ----------
            if total_pages > 0 and page > total_pages:
                cve_list, has_next, _ = get_cve_data(limit=10, page=total_pages, keyword=query, severity=severity)
                if isinstance(cve_list, str):
                    return render_template(
                        "index.html",
                        cve_list=[],
                        error="NVD rate limit exceeded. Please wait a minute and try again." if cve_list == "RATE_LIMIT" else cve_list,
                        page=total_pages,
                        search_query=query,
                        has_next=False,
                        total_pages=total_pages,
                        selected_severity=severity
                    )
                return render_template(
                    "index.html",
                    cve_list=cve_list,
                    error="PAGE_EXCEEDED",
                    page=total_pages,
                    search_query=query,
                    has_next=False,
                    total_pages=total_pages,
                    selected_severity=severity
                    )
            # -----------------------------------------------------------

            if isinstance(cve_list, str):  # Handles RATE_LIMIT or any string error
                return render_template(
                    "index.html",
                    cve_list=[],
                    error="NVD rate limit exceeded. Please wait a minute and try again." if cve_list == "RATE_LIMIT" else cve_list,
                    page=page,
                    search_query=query,
                    has_next=False,
                    total_pages=total_pages,
                    selected_severity=severity
                )
            if not cve_list:
                return render_template(
                    "index.html",
                    cve_list=[],
                    error=f"No results found for '{query}'.",
                    page=page,
                    search_query=query,
                    has_next=False,
                    total_pages=total_pages,
                    selected_severity=severity
                )
            return render_template(
                "index.html",
                cve_list=cve_list,
                error=None,
                page=page,
                search_query=query,
                has_next=has_next,
                total_pages=total_pages,
                selected_severity=severity
            )
    # If no query, fallback to paged browse (same as /)
    cve_list, has_next, total_pages = get_cve_data(limit=10, page=page, severity=severity)

    # ---------- PAGE EXCEEDS HANDLING FOR NO QUERY BRANCH ----------
    if total_pages > 0 and page > total_pages:
        cve_list, has_next, _ = get_cve_data(limit=10, page=total_pages, severity=severity)
        if isinstance(cve_list, str):
            return render_template(
                "index.html",
                cve_list=[],
                error="NVD rate limit exceeded. Please wait a minute and try again." if cve_list == "RATE_LIMIT" else cve_list,
                page=total_pages,
                has_next=False,
                total_pages=total_pages,
                selected_severity=severity
            )
        return render_template(
            "index.html",
            cve_list=cve_list,
            error="PAGE_EXCEEDED",
            page=total_pages,
            has_next=False,
            total_pages=total_pages,
            selected_severity=severity
        )
    # --------------------------------------------------------------

    if isinstance(cve_list, str):
        return render_template(
            "index.html",
            cve_list=[],
            error="NVD rate limit exceeded. Please wait a minute and try again." if cve_list == "RATE_LIMIT" else cve_list,
            page=page,
            has_next=False,
            total_pages=total_pages,
            selected_severity=severity
        )
    if not cve_list:
        return render_template(
            "index.html",
            cve_list=[],
            error="No results found.",
            page=page,
            has_next=False,
            total_pages=total_pages,
            selected_severity=severity
        )
    return render_template(
        "index.html",
        cve_list=cve_list,
        error=None,
        page=page,
        has_next=has_next,
        total_pages=total_pages,
        selected_severity=severity
    )


@app.route('/export/json')
def export_json():
    cve_list = get_cve_data(limit=10)
    response = app.response_class(
        response=json.dumps(cve_list, indent=2),
        mimetype='application/json'
    )
    response.headers.set('Content-Disposition', 'attachment', filename='cves.json')
    return response


@app.route('/export/csv')
def export_csv():
    cve_list, _, _ = get_cve_data(limit=10)
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['CVE ID', 'Description', 'Severity', 'Published Date'])
    for cve in cve_list:
        cw.writerow([cve['id'], cve['description'], cve['severity'], cve['published_date']])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='cves.csv')


@app.route('/export/json/<cve_id>')
def export_json_single(cve_id):
    cve = get_cve_by_id(cve_id)
    if not cve:
        return jsonify({'error': 'CVE not found'}), 404
    response = app.response_class(
        response=json.dumps(cve, indent=2),
        mimetype='application/json'
    )
    response.headers.set('Content-Disposition', 'attachment', filename=f'{cve_id}.json')
    return response


@app.route('/export/csv/<cve_id>')
def export_csv_single(cve_id):
    cve = get_cve_by_id(cve_id)
    if not cve:
        return "CVE not found", 404
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['CVE ID', 'Description', 'Severity', 'Published Date'])
    cw.writerow([cve['id'], cve['description'], cve['severity'], cve['published_date']])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name=f'{cve_id}.csv')


if __name__ == '__main__':
    app.run(debug=True)