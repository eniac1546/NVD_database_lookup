from flask import Flask, render_template,jsonify, request
from utils import get_cve_data

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
    Optional query param: limit (default 10)
    Example: /vulnerabilities?limit=20
    """
    limit = request.args.get('limit', default=10, type=int)
    cve_list = get_cve_data(limit=limit)
    return jsonify(cve_list)

if __name__ == '__main__':
    app.run(debug=True)


@app.route('/export/json')
def export_json():
    return "JSON export coming soon!"

@app.route('/export/csv')
def export_csv():
    return "CSV export coming soon!"
