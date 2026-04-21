from collections import defaultdict


class CorrelationEngine:
    """Joins primitive alerts and raw events to surface multi-stage attacks.

    Runs after the signature and anomaly engines because it uses their
    output as one of its inputs. Four scenarios are currently modelled:

        * Multi-vector attack      - one IP triggering several families
        * Recon followed by exploit - 4xx burst preceding a signature hit
        * Authentication brute force - repeated login attempts
        * Distributed scan          - many IPs hitting the same path
    """

    BRUTE_FORCE_THRESHOLD = 10
    RECON_FAILED_REQUESTS = 15
    DISTRIBUTED_IP_THRESHOLD = 5

    # Paths we don't want to flag as "distributed scan" - too noisy.
    IGNORED_PATHS = {
        "", "/", "/index.php", "/favicon.ico", "/robots.txt", "/login.php",
    }

    def inspect(self, events, prior_alerts):
        alerts = []
        alerts.extend(self._multi_vector(prior_alerts))
        alerts.extend(self._recon_then_exploit(events, prior_alerts))
        alerts.extend(self._brute_force(events))
        alerts.extend(self._distributed_scan(events))
        return alerts

    def _multi_vector(self, prior_alerts):
        by_ip = defaultdict(set)
        last_ts = {}
        for alert in prior_alerts:
            if alert.get("source") != "signature":
                continue
            ip = alert.get("client_ip")
            if not ip:
                continue
            by_ip[ip].add(alert["attack_type"])
            ts = alert.get("timestamp")
            if ts and (ip not in last_ts or ts > last_ts[ip]):
                last_ts[ip] = ts

        out = []
        for ip, families in by_ip.items():
            if len(families) < 2:
                continue
            out.append({
                "source": "correlation",
                "attack_type": "Multi-Vector Attack",
                "risk": "High",
                "client_ip": ip,
                "timestamp": last_ts.get(ip),
                "request": "",
                "status": None,
                "evidence": (
                    f"same source matched {len(families)} categories: "
                    + ", ".join(sorted(families))
                ),
            })
        return out

    def _recon_then_exploit(self, events, prior_alerts):
        failures_by_ip = defaultdict(int)
        for ev in events:
            try:
                if int(ev.get("status") or 0) >= 400:
                    failures_by_ip[ev.get("client_ip")] += 1
            except (TypeError, ValueError):
                continue

        out = []
        seen_ips = set()
        for alert in prior_alerts:
            if alert.get("source") != "signature":
                continue
            ip = alert.get("client_ip")
            if ip in seen_ips:
                continue
            if failures_by_ip.get(ip, 0) < self.RECON_FAILED_REQUESTS:
                continue
            seen_ips.add(ip)
            out.append({
                "source": "correlation",
                "attack_type": "Recon Followed by Exploit",
                "risk": "High",
                "client_ip": ip,
                "timestamp": alert.get("timestamp"),
                "request": alert.get("request"),
                "status": alert.get("status"),
                "evidence": (
                    f"{failures_by_ip[ip]} failed requests preceded "
                    f"{alert.get('attack_type')}"
                ),
            })
        return out

    def _brute_force(self, events):
        attempts = defaultdict(int)
        last_seen = {}
        for ev in events:
            req = (ev.get("request") or "").lower()
            if "login.php" not in req:
                continue
            ip = ev.get("client_ip")
            if not ip:
                continue
            attempts[ip] += 1
            ts = ev.get("timestamp")
            if ts and (ip not in last_seen or ts > last_seen[ip]):
                last_seen[ip] = ts

        out = []
        for ip, count in attempts.items():
            if count < self.BRUTE_FORCE_THRESHOLD:
                continue
            out.append({
                "source": "correlation",
                "attack_type": "Authentication Brute Force",
                "risk": "High",
                "client_ip": ip,
                "timestamp": last_seen.get(ip),
                "request": "/login.php",
                "status": None,
                "evidence": f"{count} login attempts in window",
            })
        return out

    def _distributed_scan(self, events):
        per_path = defaultdict(set)
        for ev in events:
            path = (ev.get("request") or "").split("?", 1)[0]
            if path in self.IGNORED_PATHS:
                continue
            ip = ev.get("client_ip")
            if ip:
                per_path[path].add(ip)

        out = []
        for path, ips in per_path.items():
            if len(ips) < self.DISTRIBUTED_IP_THRESHOLD:
                continue
            out.append({
                "source": "correlation",
                "attack_type": "Distributed Scan",
                "risk": "Medium",
                "client_ip": "multiple",
                "timestamp": None,
                "request": path,
                "status": None,
                "evidence": f"{len(ips)} distinct IPs hit {path}",
            })
        return out
