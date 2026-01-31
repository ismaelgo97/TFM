import requests

class WebScanner:
    def __init__(self, target, username, password):
        self.target = target
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.base_url = f"http://{target}"

    def login(self):
        """Automates login to DVWA to capture session cookies."""
        login_url = f"{self.base_url}/login.php"
        
        payload = {
            "username": self.username,
            "password": self.password,
            "Login": "Login"
        }

        try:
            print(f"[*] Attempting login at {login_url}...")
            response = self.session.post(login_url, data=payload)
            
            if "Login failed" not in response.text and response.status_code == 200:
                print(f"[+] Login successful for user: {self.username}")
                return True
            else:
                print("[-] Login failed. Check credentials or DVWA state.")
                return False
        except Exception as e:
            print(f"[-] Connection error during login: {e}")
            return False

    def execute(self):
        """Entry point for web scanning phase."""
        if self.login():
            print(f"[*] Starting web vulnerability scan on {self.target}...")
            # Future logic for XSS/SQLi scanning goes here
        else:
            print("[-] Aborting web scan due to authentication failure.")