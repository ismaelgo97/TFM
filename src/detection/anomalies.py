import math
from collections import defaultdict


class AnomalyEngine:
    """Statistical detector.

    For every observation window we build a baseline across all client IPs
    and flag the ones whose behaviour sits outside it. Three metrics are
    tracked: request volume, error-response ratio and path enumeration.
    A hard floor is kept alongside the dynamic threshold so a single noisy
    client still gets picked up when the sample is too small for the
    standard deviation to mean much.
    """

    # Hard floors. Used when the std-deviation band is too narrow to matter,
    # which happens when most IPs in the window sent only a handful of hits.
    MIN_REQUESTS_PER_IP = 80
    MIN_ERROR_RATIO = 0.5
    MIN_UNIQUE_PATHS = 30

    # Number of standard deviations above the mean to treat as suspicious.
    STDEV_MULTIPLIER = 2.5

    # Below this many requests an IP is ignored for error-ratio alerts.
    ERROR_SAMPLE_FLOOR = 10

    def inspect(self, events):
        if not events:
            return []

        per_ip = self._summarise(events)
        volume_threshold = self._volume_threshold(per_ip)

        alerts = []
        for ip, stats in per_ip.items():
            reasons = []

            if stats["requests"] >= volume_threshold:
                reasons.append(
                    f"high request volume ({stats['requests']} hits)"
                )

            ratio = (
                stats["errors"] / stats["requests"]
                if stats["requests"] else 0
            )
            if (
                stats["requests"] >= self.ERROR_SAMPLE_FLOOR
                and ratio >= self.MIN_ERROR_RATIO
            ):
                reasons.append(
                    f"excessive error responses ({int(ratio * 100)}% 4xx/5xx)"
                )

            if len(stats["paths"]) >= self.MIN_UNIQUE_PATHS:
                reasons.append(
                    f"path enumeration ({len(stats['paths'])} unique URLs)"
                )

            if not reasons:
                continue

            alerts.append({
                "source": "anomaly",
                "attack_type": "Anomalous Traffic",
                "risk": "High" if len(reasons) > 1 else "Medium",
                "client_ip": ip,
                "timestamp": stats["last_seen"],
                "request": (
                    f"{stats['requests']} requests, "
                    f"{len(stats['paths'])} unique URLs"
                ),
                "status": None,
                "evidence": "; ".join(reasons),
            })
        return alerts

    @staticmethod
    def _summarise(events):
        """Fold the event list into one record per client IP."""
        per_ip = defaultdict(lambda: {
            "requests": 0,
            "errors": 0,
            "paths": set(),
            "agents": set(),
            "first_seen": None,
            "last_seen": None,
        })

        for ev in events:
            ip = ev.get("client_ip") or "Unknown"
            stats = per_ip[ip]
            stats["requests"] += 1

            status = ev.get("status")
            try:
                if status is not None and int(status) >= 400:
                    stats["errors"] += 1
            except (TypeError, ValueError):
                pass

            path = (ev.get("request") or "").split("?", 1)[0]
            if path:
                stats["paths"].add(path)

            agent = ev.get("user_agent")
            if agent:
                stats["agents"].add(agent)

            ts = ev.get("timestamp")
            if ts:
                # ISO 8601 strings sort correctly via lexicographic compare
                stats["first_seen"] = (
                    ts if not stats["first_seen"] else min(stats["first_seen"], ts)
                )
                stats["last_seen"] = (
                    ts if not stats["last_seen"] else max(stats["last_seen"], ts)
                )
        return per_ip

    def _volume_threshold(self, per_ip):
        counts = [s["requests"] for s in per_ip.values()]
        if not counts:
            return self.MIN_REQUESTS_PER_IP
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        stdev = math.sqrt(variance)
        return max(
            self.MIN_REQUESTS_PER_IP,
            mean + self.STDEV_MULTIPLIER * stdev,
        )
