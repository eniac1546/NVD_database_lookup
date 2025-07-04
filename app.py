from flask import Flask, render_template
from utils import get_cve_data

app = Flask(__name__)

@app.route('/')
def index():
    cve_list = get_cve_data(limit=10)
    return render_template("index.html", cve_list=cve_list)

if __name__ == '__main__':
    app.run(debug=True)


@app.route('/export/json')
def export_json():
    return "JSON export coming soon!"

@app.route('/export/csv')
def export_csv():
    return "CSV export coming soon!"
