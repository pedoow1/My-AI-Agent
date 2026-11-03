# CyberSentinel Local Lab: XSS Cookie Theft & DOM Credential Harvesting Demonstration
# This file serves as a local lab environment within our workspace to demonstrate
# how JavaScript (document object) interacts with cookies and input fields in XSS attacks.

class SimulatedDOM:
    def __init__(self):
        self.elements = {}
        self.cookies = {}

    def set_element_value(self, element_id: str, value: str):
        self.elements[element_id] = {"value": value}

    def set_cookie(self, name: str, value: str, http_only: bool = False):
        self.cookies[name] = {"value": value, "http_only": http_only}

    def execute_xss_script_simulation(self) -> dict:
        """
        Simulates what malicious JavaScript (XSS) can read via the `document` object:
        1. document.cookie (if not HttpOnly)
        2. document.getElementById('username').value / document.getElementById('password').value
        """
        stolen_cookies = "; ".join(
            f"{k}={v['value']}" for k, v in self.cookies.items() if not v["http_only"]
        )
        
        # Harvesting user input fields from the DOM
        stolen_credentials = {
            "username": self.elements.get("username", {}).get("value"),
            "email": self.elements.get("email", {}).get("value"),
            "password": self.elements.get("password", {}).get("value"),
        }

        return {
            "stolen_cookies": stolen_cookies,
            "stolen_credentials": stolen_credentials
        }

def test_local_lab_vulnerable_cookie_theft():
    dom = SimulatedDOM()
    dom.set_cookie("session_id", "secret_token_123", http_only=False)
    
    result = dom.execute_xss_script_simulation()
    print(f"\n[Local Lab] Stolen Cookies: {result['stolen_cookies']}")
    assert "session_id=secret_token_123" in result["stolen_cookies"]

def test_local_lab_dom_credential_harvesting():
    """
    Demonstrates how an XSS payload uses document.getElementById to harvest
    usernames, emails, and passwords typed into form inputs by a victim on the admin login page (https://cafe-winter.at/admin/login).
    """
    dom = SimulatedDOM()
    # Victim types their credentials into admin login inputs
    dom.set_element_value("username", "jacob-winter")
    dom.set_element_value("email", "jacob@cafe-winter.at")
    dom.set_element_value("password", "SuperSecretPassword123!")

    # Malicious script executes via XSS (document inspection)
    result = dom.execute_xss_script_simulation()
    creds = result["stolen_credentials"]

    print(f"[Local Lab] Admin Login Page: https://cafe-winter.at/admin/login")
    print(f"[Local Lab] Harvested Username: {creds['username']}")
    print(f"[Local Lab] Harvested Email: {creds['email']}")
    print(f"[Local Lab] Harvested Password: {creds['password']}")

    assert creds["username"] == "jacob-winter"
    assert creds["email"] == "jacob@cafe-winter.at"
    assert creds["password"] == "SuperSecretPassword123!"
