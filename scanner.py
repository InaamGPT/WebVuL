import os
from datetime import datetime
from headers import ga, headers_reader
import vulnz
from reporter import generate_pdf

def run_industrial_scan(target_url):
    """
    Core scanning function designed for backend integration.
    Returns a result dictionary for API responses.
    """
    url = target_url.strip()
    
    # Validation
    if "?" not in url:
        return {
            "status": "error",
            "message": "Target URL must have parameters (e.g., ?id=1)"
        }

    # Ensure reports directory exists
    if not os.path.exists("reports"):
        os.makedirs("reports")

    # 1. Start Fingerprinting
    # Directly calling the imported headers_reader resolves Pylance "not accessed" warnings
    headers_reader(url)
    
    # 2. Execute Assertive Vulnerability Modules
    # These functions now use the alarming tone logic from cvss_map.py
    total = 0
    total += vulnz.sqli_func(url)
    total += vulnz.rce_func(url)
    total += vulnz.xss_func(url)
    total += vulnz.lfi_func(url)
    
    print(f"\n{ga.BLUE}{ga.BOLD} [!] Audit Complete. {total} Unique vulnerabilities logged.{ga.END}")
    
    # 3. Generate Timestamped Report
    if total > 0:
        csv_path = os.path.join("reports", "security_audit_report.csv")
        
        if os.path.exists(csv_path):
            # Unique filename for history tracking
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            report_name = f"Industrial_Report_{timestamp}.pdf"
            
            print(f"{ga.YELLOW} [!] Finalizing ASSERTIVE IEC 62443 Report: {report_name}{ga.END}")
            # Generate PDF with correct table outlines and assertive remedies
            generate_pdf(csv_path, report_name)
            
            return {
                "status": "success",
                "findings": total,
                "report_name": report_name
            }
        else:
            return {"status": "error", "message": "CSV data missing; report failed."}
            
    return {"status": "success", "findings": 0, "message": "No vulnerabilities detected."}

if __name__ == "__main__":
    # Standard CLI execution for manual testing
    try:
        # Clean the temporary CSV for a fresh session
        temp_csv = os.path.join("reports", "security_audit_report.csv")
        if os.path.exists(temp_csv):
            os.remove(temp_csv)
            
        target = input(f"{ga.GREEN} Enter target URL: {ga.END}")
        scan_results = run_industrial_scan(target)
        print(f"\nFinal Result: {scan_results}")
        
    except KeyboardInterrupt:
        print(f"\n{ga.YELLOW} [!] User stopped the scan.{ga.END}")