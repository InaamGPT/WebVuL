import os
import csv
from fpdf import FPDF
from datetime import datetime

class IEC62443Report(FPDF):
    def header(self):
        # Industrial Header [cite: 1]
        self.set_font('Arial', 'B', 15)
        self.set_text_color(44, 62, 80) 
        self.cell(0, 10, 'CYBERSECURITY AUDIT', 0, 1, 'C')
        self.set_font('Arial', 'I', 9)
        self.cell(0, 5, f'Security Level Target: SL-2 | Audit Date: {datetime.now().strftime("%Y-%m-%d")}', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        # Page Footer with Restricted Label [cite: 37]
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()} - Restricted Security Audit Data', 0, 0, 'C')

    def chapter_header(self, title):
        # Section Titles [cite: 3, 6]
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(52, 73, 94) 
        self.set_text_color(255, 255, 255) 
        self.cell(0, 10, f" {title}", 1, 1, 'L', 1)
        self.ln(4)

    def vuln_entry(self, data, fr_mapping):
        # Severity Color Mapping 
        severity = data['Severity'].upper()
        if "CRITICAL" in severity:
            header_color = (192, 57, 43) # Red
        elif "HIGH" in severity:
            header_color = (211, 84, 0)  # Orange
        elif "MEDIUM" in severity:
            header_color = (41, 128, 185) # Blue
        else:
            header_color = (127, 140, 141) # Grey

        # --- Section 1: Finding Title ---
        self.set_font('Arial', 'B', 11)
        self.set_fill_color(*header_color)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, f" FINDING: {data['Vulnerability Type']} | SEVERITY: {severity}", "LTR", 1, 'L', 1)
        
        # --- Section 2: Metadata Table (Continuous Borders) ---
        self.set_text_color(0, 0, 0)
        self.set_font('Arial', 'B', 9)
        self.set_fill_color(245, 245, 245)
        
        # Row: Requirement [cite: 8, 26, 48]
        self.cell(50, 8, " Requirement Reference", "LR", 0, 'L', 1)
        self.set_font('Arial', '', 9)
        self.cell(0, 8, f" {fr_mapping}", "R", 1, 'L')

        # Row: Component [cite: 9, 28, 50]
        self.set_font('Arial', 'B', 9)
        self.cell(50, 8, " Target Component", "LR", 0, 'L', 1)
        self.set_font('Arial', '', 8)
        self.cell(0, 8, f" {data['POC URL']}", "R", 1, 'L')

        # Row: Payload [cite: 10, 29, 51]
        self.set_font('Arial', 'B', 9)
        self.cell(50, 8, " Payload Triangulated", "LRB", 0, 'L', 1)
        self.set_font('Arial', '', 8)
        self.cell(0, 8, f" {data['Payload']}", "RB", 1, 'L')

        # --- Section 3: Remediation Box (Enclosed Outline) [cite: 12, 31, 53] ---
        self.ln(2)
        self.set_font('Arial', 'B', 10)
        self.set_text_color(*header_color)
        self.cell(0, 8, " REQUIRED ENGINEERING COUNTERMEASURES", "LTR", 1, 'L')
        
        self.set_text_color(0, 0, 0)
        self.set_font('Arial', '', 9)
        
        # Cleaned Remedy Body with full border enclosure [cite: 24, 75]
        # We add a small newline for internal padding
        remedy_text = data['AI Suggested Remedy'].strip()
        self.multi_cell(0, 6, f"\n{remedy_text}\n ", border=1) 
        self.ln(8)

def generate_pdf(csv_file, output_filename):
    output_folder = "reports"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    pdf = IEC62443Report()
    pdf.add_page()
    
    # Introduction Section [cite: 3, 4, 5]
    pdf.chapter_header("1.0 SYSTEM UNDER CONSIDERATION (SuC) & SCOPE")
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 6, "Automated assessment of web-based interface controls to verify adherence to "
                         "IEC 62443-3-3 security requirements. Vulnerabilities are triaged based on "
                         "impact to System Integrity and Use Control.")
    pdf.ln(5)

    # Detailed Analysis Section [cite: 6]
    pdf.chapter_header("2.0 VULNERABILITY ANALYSIS & FOUNDATIONAL REQUIREMENTS")
    
    fr_map = {
        "SQLi": "FR 3 - System Integrity",
        "RCE": "FR 3 - System Integrity",
        "XSS": "FR 4 - Data Confidentiality",
        "LFI": "FR 2 - Use Control"
    }

    try:
        with open(csv_file, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                fr = fr_map.get(row['Vulnerability Type'], "FR 3 - System Integrity")
                pdf.vuln_entry(row, fr)
    except Exception as e:
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, f"Error processing findings: {e}", 0, 1)

    report_path = os.path.join(output_folder, output_filename)
    pdf.output(report_path)
    print(f"\n [+] Industrial Report Generated: {report_path}")