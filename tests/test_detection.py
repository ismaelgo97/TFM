from detection.anomalies import AnomalyEngine
from detection.correlation import CorrelationEngine
from detection.signatures import SignatureEngine


def make_event(**overrides):
    base = {
        "timestamp": "2026-04-21T12:00:00.000Z",
        "client_ip": "10.0.0.1",
        "request": "/index.php",
        "status": 200,
        "method": "GET",
        "user_agent": "Mozilla/5.0",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Signature engine
# ---------------------------------------------------------------------------

class TestSignatureEngine:
    def setup_method(self):
        self.engine = SignatureEngine()

    def test_detects_sqli_union(self):
        event = make_event(request="/vulns/sqli/?id=1 UNION SELECT 1,2,3--")
        hits = self.engine.inspect(event)
        assert any(h["attack_type"] == "SQL Injection" for h in hits)

    def test_detects_sqli_boolean(self):
        event = make_event(request="/login?user=admin' or '1'='1")
        hits = self.engine.inspect(event)
        assert any(h["attack_type"] == "SQL Injection" for h in hits)

    def test_detects_xss(self):
        event = make_event(request="/search?q=<script>alert(1)</script>")
        hits = self.engine.inspect(event)
        assert any(h["attack_type"] == "Cross-Site Scripting (XSS)" for h in hits)

    def test_detects_path_traversal(self):
        event = make_event(request="/download?f=../../../etc/passwd")
        hits = self.engine.inspect(event)
        assert any(h["attack_type"] == "Path Traversal" for h in hits)

    def test_detects_command_injection(self):
        event = make_event(request="/exec?cmd=127.0.0.1;cat /etc/passwd")
        hits = self.engine.inspect(event)
        assert any(h["attack_type"] == "Command Injection" for h in hits)

    def test_detects_file_inclusion(self):
        event = make_event(request="/view?page=php://filter/read/")
        hits = self.engine.inspect(event)
        assert any(h["attack_type"] == "File Inclusion" for h in hits)

    def test_ignores_clean_request(self):
        event = make_event(request="/dashboard/stats")
        assert self.engine.inspect(event) == []

    def test_handles_missing_request(self):
        event = make_event(request="")
        assert self.engine.inspect(event) == []


# ---------------------------------------------------------------------------
# Anomaly engine
# ---------------------------------------------------------------------------

class TestAnomalyEngine:
    def setup_method(self):
        self.engine = AnomalyEngine()

    def test_flags_volume_spike(self):
        events = [
            make_event(client_ip="9.9.9.9", request=f"/page/{i}")
            for i in range(120)
        ]
        events += [make_event(client_ip="1.1.1.1"), make_event(client_ip="2.2.2.2")]
        alerts = self.engine.inspect(events)
        assert any(a["client_ip"] == "9.9.9.9" for a in alerts)

    def test_flags_error_burst(self):
        events = [
            make_event(client_ip="9.9.9.9", status=404, request=f"/missing/{i}")
            for i in range(20)
        ]
        alerts = self.engine.inspect(events)
        assert any(
            a["client_ip"] == "9.9.9.9" and "error" in a["evidence"]
            for a in alerts
        )

    def test_flags_path_enumeration(self):
        events = [
            make_event(client_ip="9.9.9.9", request=f"/page-{i}")
            for i in range(40)
        ]
        alerts = self.engine.inspect(events)
        assert any("enumeration" in a["evidence"] for a in alerts)

    def test_empty_input(self):
        assert self.engine.inspect([]) == []

    def test_clean_traffic_ignored(self):
        events = [
            make_event(client_ip=f"10.0.0.{i}", request="/index.php")
            for i in range(5)
        ]
        assert self.engine.inspect(events) == []


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

class TestCorrelationEngine:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_multi_vector(self):
        prior = [
            {
                "source": "signature",
                "attack_type": "SQL Injection",
                "client_ip": "5.5.5.5",
                "timestamp": "2026-04-21T12:00:00.000Z",
            },
            {
                "source": "signature",
                "attack_type": "Cross-Site Scripting (XSS)",
                "client_ip": "5.5.5.5",
                "timestamp": "2026-04-21T12:01:00.000Z",
            },
        ]
        alerts = self.engine.inspect([], prior)
        assert any(a["attack_type"] == "Multi-Vector Attack" for a in alerts)

    def test_multi_vector_ignores_single_family(self):
        prior = [
            {
                "source": "signature",
                "attack_type": "SQL Injection",
                "client_ip": "5.5.5.5",
                "timestamp": "2026-04-21T12:00:00.000Z",
            },
        ]
        assert self.engine.inspect([], prior) == []

    def test_recon_then_exploit(self):
        events = [
            make_event(client_ip="8.8.8.8", status=404)
            for _ in range(20)
        ]
        prior = [{
            "source": "signature",
            "attack_type": "SQL Injection",
            "client_ip": "8.8.8.8",
            "timestamp": "2026-04-21T12:05:00.000Z",
            "request": "/sqli?id=1 union select",
            "status": 200,
        }]
        alerts = self.engine.inspect(events, prior)
        assert any(
            a["attack_type"] == "Recon Followed by Exploit" for a in alerts
        )

    def test_brute_force(self):
        events = [
            make_event(
                client_ip="7.7.7.7",
                request="/login.php",
                method="POST",
            )
            for _ in range(15)
        ]
        alerts = self.engine.inspect(events, [])
        assert any(
            a["attack_type"] == "Authentication Brute Force" for a in alerts
        )

    def test_distributed_scan(self):
        events = [
            make_event(client_ip=f"6.6.6.{i}", request="/admin/config.php")
            for i in range(6)
        ]
        alerts = self.engine.inspect(events, [])
        assert any(a["attack_type"] == "Distributed Scan" for a in alerts)

    def test_distributed_scan_ignores_root(self):
        events = [
            make_event(client_ip=f"6.6.6.{i}", request="/index.php")
            for i in range(6)
        ]
        assert self.engine.inspect(events, []) == []

    def test_empty_input(self):
        assert self.engine.inspect([], []) == []
