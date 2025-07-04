from flask import Flask, render_template,jsonify, request
from utils import get_cve_data, get_cve_by_id

app = Flask(__name__)

@app.route('/')
def index():
    cve_list = get_cve_data(limit=10)
    print("Fetched CVEs:", cve_list)  # <--- Add this line
    return render_template("index.html", cve_list=cve_list)


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


@app.route('/search', methods=['GET'])
def search():
    """
    Search feature to get the particular CVE details
    
    """
    query = request.args.get('q', '').strip()
    if query:
        cve = get_cve_by_id(query)
        if cve:
            return render_template("cve_detail.html", cve=cve)
        else:
            return render_template("cve_not_found.html", cve_id=query), 404
    return render_template("index.html", cve_list=[])



@app.route('/export/json')
def export_json():
    return "JSON export coming soon!"

@app.route('/export/csv')
def export_csv():
    return "CSV export coming soon!"


if __name__ == '__main__':
    app.run(debug=True)
