import pytest
from scanners.web_scanner import WebScanner

# Configuration for the test environment
TARGET_IP = "192.168.122.27/DVWA"
USER = "admin"
PASS = "password"

@pytest.fixture
def scanner_instance():
    """Fixture to initialize the scanner for each test."""
    return WebScanner(TARGET_IP, USER, PASS)

def test_zap_connectivity(scanner_instance):
    """Verifies that the ZAP API is reachable."""
    assert scanner_instance.check_zap_status() is True

def test_login_and_security_level(scanner_instance):
    """Verifies successful login and security level setting to 'low'."""
    # The login() method returns True if both login and set_security_low succeed
    success = scanner_instance.login()
    assert success is True
    
    # Check if the session cookie actually contains 'security=low'
    cookies = scanner_instance.session.cookies.get_dict()
    assert cookies.get("security") == "low"

def test_vulnerability_detection_logic(scanner_instance):
    """
    Smoke test: Runs a targeted scan on the SQLi page 
    and asserts that a vulnerability is found.
    """
    # We only seed the SQLi route to keep the test fast
    test_routes = ["/vulnerabilities/sqli/"]
    scanner_instance.run_scan(seed_routes=test_routes)
    
    # Access ZAP alerts
    alerts = scanner_instance.zap.core.alerts(baseurl=scanner_instance.base_url)
    
    # Assert that we found at least one alert (SQLi should be High/Medium)
    assert len(alerts) > 0
    
    # Optional: Assert specifically for High risk
    high_risk_alerts = [a for a in alerts if a['risk'] == 'High']
    assert len(high_risk_alerts) > 0