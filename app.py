import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# Import the refactored scanner module
from scanner import run_industrial_scan

app = Flask(__name__)
CORS(app)  # Allows your frontend to communicate with this backend

# CONFIGURATION FOR GOOGLE CLOUD STORAGE MOUNT
# Using absolute path /app/reports to match the GCS Volume Mount
REPORTS_DIR = "/app/reports"

if not os.path.exists(REPORTS_DIR):
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
    except Exception as e:
        print(f"Warning: Could not create directory {REPORTS_DIR}: {e}")

@app.route('/')
def health():
    return jsonify({"status": "online", "system": "Industrial Audit Backend"}), 200

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

    # Ensure a fresh session by cleaning the temporary CSV inside the mount
    temp_csv = os.path.join(REPORTS_DIR, "security_audit_report.csv")
    if os.path.exists(temp_csv):
        try:
            os.remove(temp_csv)
        except Exception as e:
            # We log this but don't stop the scan if it's just a file lock
            print(f"Cleanup Warning: {e}")

    try:
        # Call the refactored scanner function
        # This will trigger the assertive remedies from cvss_map.py
        scan_results = run_industrial_scan(target_url)

        if scan_results.get("status") == "success":
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
    """Returns a list of all timestamped PDF reports available in the bucket."""
    try:
        if not os.path.exists(REPORTS_DIR):
            return jsonify({"reports": []}), 200
            
        files = [f for f in os.listdir(REPORTS_DIR) if f.endswith('.pdf')]
        # Sort by newest first
        files.sort(reverse=True)
        return jsonify({"reports": files}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports/<filename>', methods=['GET'])
def download_audit_report(filename):
    """Securely serves the generated PDF report from the mounted GCS bucket."""
    # Security: Ensure the user isn't trying to access files outside the directory
    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Invalid filename"}), 400
        
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)

if __name__ == '__main__':
    # Cloud Run provides the PORT environment variable. Default to 8080 for GCP.
    port = int(os.environ.get('PORT', 8080))
    print(f" [!] Industrial Audit Backend starting on port {port}")
    # Set debug=False for production deployment
    app.run(debug=False, host='0.0.0.0', port=port)