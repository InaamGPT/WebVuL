import requests

class colors:
    def __init__(self):
        self.GREEN = "\033[92m"
        self.BLUE = "\033[94m"
        self.BOLD = "\033[1m"
        self.YELLOW = "\033[93m"
        self.RED = "\033[91m"
        self.END = "\033[0m"

ga = colors()

def headers_reader(url):
    print(f"{ga.BOLD}\n [!] Fingerprinting Server...{ga.END}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        res = requests.get(url, headers=headers, timeout=5, verify=False)
        print(f"{ga.GREEN} [!] Status code: {res.status_code}{ga.END}")
        print(f"{ga.GREEN} [!] Server: {res.headers.get('Server', 'Unknown')}{ga.END}")
    except Exception as e:
        print(f"{ga.RED} [!] Connection Failed: {e}{ga.END}")