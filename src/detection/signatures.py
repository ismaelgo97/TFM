import re

# Catalogue of known attack patterns. The regexes are intentionally loose:
# false positives are cheaper than false negatives when feeding the response
# layer, and anything flagged here is cross-checked by the correlation engine.
PATTERNS = {
    "SQL Injection": [
        r"\bunion\b[^a-z]+\bselect\b",
        r"\bselect\b.+\bfrom\b",
        r"(\'|%27)?\s*\b(or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
        r"--\s",
        r";\s*drop\s+table",
        r"sleep\s*\(\s*\d+\s*\)",
    ],
    "Cross-Site Scripting (XSS)": [
        r"<\s*script",
        r"javascript:",
        r"on(error|load|click|mouseover)\s*=",
        r"<\s*iframe",
        r"document\.cookie",
    ],
    "Path Traversal": [
        r"\.\./",
        r"\.\.%2f",
        r"\.\.\\",
        r"/etc/passwd",
        r"boot\.ini",
    ],
    "Command Injection": [
        r";\s*(cat|ls|whoami|id|uname)\b",
        r"\|\s*(nc|bash|sh|curl|wget)\b",
        r"&&\s*(cat|ls|whoami|id)\b",
        r"`[^`]+`",
        r"\$\([^)]+\)",
    ],
    "File Inclusion": [
        r"php://",
        r"data://",
        r"expect://",
        r"file://",
    ],
}


class SignatureEngine:
    """Rule based detector. Walks each request against a catalogue of regexes."""

    def __init__(self):
        self._compiled = {
            category: [re.compile(p, re.IGNORECASE) for p in patterns]
            for category, patterns in PATTERNS.items()
        }

    def inspect(self, event):
        """Returns the list of alerts raised by a single log event.

        A request may match more than one category (e.g. SQLi and XSS in the
        same payload), so we walk every family and stop at the first regex
        that fires for each one to avoid duplicate evidence lines.
        """
        request = event.get("request") or ""
        if not request:
            return []

        hits = []
        for category, regexes in self._compiled.items():
            for rx in regexes:
                if rx.search(request):
                    hits.append({
                        "source": "signature",
                        "attack_type": category,
                        "risk": "High",
                        "timestamp": event.get("timestamp"),
                        "client_ip": event.get("client_ip"),
                        "request": request,
                        "status": event.get("status"),
                        "evidence": f"matched /{rx.pattern}/",
                    })
                    break
        return hits
