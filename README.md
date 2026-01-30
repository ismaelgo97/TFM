# Development of a System for Attack Detection and Prevention in Web Applications

A Master's Thesis (TFM) project focused on building an advanced system to safeguard web applications through integrated detection and prevention mechanisms.

---

## Project Overview

This project aims to move beyond surface-level protection to provide a comprehensive security solution that identifies, classifies, and mitigates vulnerabilities in real-time. The system integrates detection and prevention mechanisms to protect web applications from common attacks and misconfigurations.

---

## Objectives

- **Vulnerability Analysis** — Perform exhaustive scans using automated and manual tools to identify and prioritize flaws based on severity.
- **Intrusion Detection** — Monitor web traffic in real-time using signature analysis and anomaly detection.
- **Attack Prevention** — Implement proactive measures against common threats like SQL Injection, XSS, and CSRF.
- **Logging & Reporting** — Establish a system for generating periodic reports on threats and implemented defenses.
- **Continuous Integration** — Ensure security is automatically validated during application updates.

---

## Methodology

The development follows an **Agile (SCRUM)** framework to allow for iterative improvements. It also incorporates **DevSecOps** principles to ensure security is integrated throughout the entire lifecycle.

---

## Technology Stack

| Area | Technology |
|------|------------|
| **Target Environment** | Damn Vulnerable Web App (DVWA) |
| **Security Scanning** | OWASP ZAP, Burp Suite |
| **Monitoring (SIEM)** | ELK Stack (Elasticsearch, Logstash, Kibana) |
| **WAF** | ModSecurity |
| **Development** | Python (managed with [uv](https://github.com/astral-sh/uv)), Visual Studio Code |