from flask import Flask, render_template,jsonify, request
from utils import get_cve_data, get_cve_by_id
from flask import send_file
import io
import csv
import json

app = Flask(__name__)

@app.route('/')
def index():
    # Get 'page' and 'severity' from URL query parameters
    page = request.args.get('page', default=1, type=int)
    severity = request.args.get('severity', '')

    # Fetch CVE data using your data-fetching function
    cve_list, has_next = get_cve_data(limit=50, page=page, severity=severity)
    print("Fetched CVEs:", cve_list)

    # ---- Error Handling Block ----
    # Handle string error cases (e.g., rate limit or fetch error)
    if isinstance(cve_list, str):  
        return render_template(
            "index.html",
            cve_list=[],
            error=cve_list,
            page=page,
            has_next=False,
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
    # ---- End Error Handling ----

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
    Optional query param: limit (default 50)
    Example: /vulnerabilities?limit=100

    """
    limit = request.args.get('limit', default=50, type=int)
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


# app route to handle search logic, rate ,limit logic, and severity logic 
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '').strip()
    page = request.args.get('page', default=1, type=int)
    severity = request.args.get('severity', '')

    if query:
        cve = get_cve_by_id(query)
        if cve == "RATE_LIMIT":
            return render_template(
                "index.html",
                cve_list=[], page=page, search_query=query,
                rate_limited=True, selected_severity=severity, has_next=False
            )
        if cve:
            if severity and cve.get('severity', '').upper() != severity.upper():
                return render_template(
                    "index.html",
                    cve_list=[], page=page, search_query=query,
                    selected_severity=severity, has_next=False
                )
            return render_template("cve_detail.html", cve=cve)
        else:
            cve_list, has_next = get_cve_data(limit=50, page=page, keyword=query, severity=severity)
            if cve_list == "RATE_LIMIT":
                return render_template(
                    "index.html",
                    cve_list=[], page=page, search_query=query,
                    rate_limited=True, selected_severity=severity, has_next=False
                )
            return render_template(
                "index.html",
                cve_list=cve_list, page=page, search_query=query,
                selected_severity=severity, has_next=has_next
            )
    cve_list, has_next = get_cve_data(limit=50, page=page, severity=severity)
    if cve_list == "RATE_LIMIT":
        return render_template(
            "index.html",
            cve_list=[], page=page, rate_limited=True,
            selected_severity=severity, has_next=False
        )
    return render_template(
        "index.html",
        cve_list=cve_list,
        page=page,
        has_next=has_next,
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
    cve_list = get_cve_data(limit=10)
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
