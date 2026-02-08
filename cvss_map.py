import google.generativeai as genai
import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

class CVSSMapping:
    # Standard mapping for IEC 62443 compliance metrics
    MAP = {
        "RCE": {"range": "9.0 - 10.0", "severity": "CRITICAL", "desc": "Remote Code Execution"},
        "SQLi": {"range": "7.0 - 9.0", "severity": "HIGH", "desc": "SQL Injection"},
        "XSS": {"range": "4.0 - 7.0", "severity": "MEDIUM", "desc": "Cross-Site Scripting"},
        "LFI": {"range": "6.0 - 8.0", "severity": "HIGH", "desc": "Local File Inclusion"}
    }

    # Configuration using the environment variable
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        genai.configure(api_key=api_key)

    @classmethod
    def get_ai_remedy(cls, v_type):
        """
        Fetches alarming, engineering-grade remediation from Gemini.
        Tone shifts to high-urgency for Critical/High findings.
        """
        if not cls.api_key:
            return "1. Error: API Key not found. Immediate manual intervention required."

        # Fetch severity to adjust the prompt tone
        severity_info = cls.MAP.get(v_type, {"severity": "UNKNOWN"})
        severity = severity_info["severity"]

        # Assertive prompt logic
        tone = "URGENT AND ALARMING" if severity in ["CRITICAL", "HIGH"] else "PROFESSIONAL"
        
        try:
            model = genai.GenerativeModel('gemini-2.5-flash')
            
            prompt = (
                f"Act as a Lead Industrial Cyber-Response Engineer. "
                f"A {severity} {v_type} vulnerability has been detected in a Production Zone. "
                f"Provide an {tone} technical directive and immediate countermeasures "
                f"to meet IEC 62443-3-3 standards. "
                f"Use commanding language (e.g., 'IMMEDIATELY RESTRICT', 'MANDATORY REFACTOR'). "
                f"Format as a numbered list (1, 2, 3). No markdown, no bolding, no asterisks. "
                f"Limit to 85 words."
            )
            
            response = model.generate_content(prompt)
            # Remove markdown artifacts for clean PDF rendering
            clean_text = response.text.replace("**", "").replace("#", "").replace("*", "-").strip()
            return clean_text
            
        except Exception:
            return (
                "1. CRITICAL: Isolate the affected asset from the control network immediately.\n"
                "2. MANDATORY: Deploy server-side whitelisting and input sanitization.\n"
                "3. REQUIRED: Implement strict Use Control (FR 2) and Least Privilege."
            )

    @classmethod
    def get_details(cls, v_type):
        details = cls.MAP.get(v_type, {"range": "N/A", "severity": "INFO", "desc": "N/A"}).copy()
        details['remedy'] = cls.get_ai_remedy(v_type)
        return details