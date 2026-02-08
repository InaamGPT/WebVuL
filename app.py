import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# Import the refactored scanner module
from scanner import run_industrial_scan

app = Flask(__name__)
CORS(app)  # Allows your frontend to communicate with this backend

# Configuration
REPORTS_DIR = "reports"
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

@app.route('/api/scan', methods=['POST'])
def start_audit():
    """
    Endpoint to trigger an assertive industrial scan.
    Expects: {"url": "http://target.com/page.php?id=1"}
    """
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({
            "status": "error", 
            "message": "Missing 'url' parameter in request body."
        }), 400

    target_url = data['url']

    # Ensure a fresh session by cleaning the temporary CSV
    temp_csv = os.path.join(REPORTS_DIR, "security_audit_report.csv")
    if os.path.exists(temp_csv):
        try:
            os.remove(temp_csv)
        except Exception as e:
            return jsonify({"status": "error", "message": f"Failed to clear old data: {e}"}), 500

    try:
        # Call the refactored scanner function
        # This will trigger the assertive remedies from cvss_map.py
        scan_results = run_industrial_scan(target_url)

        if scan_results["status"] == "success":
            return jsonify(scan_results), 200
        else:
            return jsonify(scan_results), 400

    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": f"System Failure during scan: {str(e)}"
        }), 500

@app.route('/api/reports', methods=['GET'])
def get_reports_list():
    """Returns a list of all timestamped PDF reports available."""
    try:
        files = [f for f in os.listdir(REPORTS_DIR) if f.endswith('.pdf')]
        # Sort by newest first
        files.sort(reverse=True)
        return jsonify({"reports": files}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports/<filename>', methods=['GET'])
def download_audit_report(filename):
    """Securely serves the generated PDF report."""
    # Ensure the user isn't trying to access files outside the reports directory
    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Invalid filename"}), 400
        
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)

if __name__ == '__main__':
    print(" [!] Industrial Audit Backend starting on http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)