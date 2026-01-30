# Development of a System for Attack Detection and Prevention in Web Applications

A Master's Thesis (TFM) project that builds a system to detect and prevent attacks in web applications.

---

## Project Overview

The goal is to build a security system that finds, classifies, and mitigates vulnerabilities in real time. It combines detection and prevention to protect web apps from common attacks and misconfigurations.

---

## Objectives

- **Vulnerability Analysis** — Run full scans (automated and manual) to find and prioritize flaws by severity.
- **Intrusion Detection** — Monitor web traffic in real time with signature and anomaly detection.
- **Attack Prevention** — Defend against common threats (SQL Injection, XSS, CSRF).
- **Logging & Reporting** — Generate periodic reports on threats and defenses.
- **Continuous Integration** — Ensure security is automatically validated during application updates.

---

## Methodology

Development uses **Agile (SCRUM)** for iterative work and **DevSecOps** so security is part of the whole process.

---

## Technology Stack

| Area | Technology |
|------|------------|
| **Target Environment** | Damn Vulnerable Web App (DVWA) |
| **Security Scanning** | OWASP ZAP, Burp Suite |
| **Monitoring (SIEM)** | ELK Stack (Elasticsearch, Logstash, Kibana) |
| **WAF** | ModSecurity |
| **Development** | Python (managed with [uv](https://github.com/astral-sh/uv)), Visual Studio Code |

---

## Project Phases & Status

### Phase 1: Vulnerability Analysis (In Progress)
- **1.1 Network & service scanning**: Automated Nmap-based scanning.
- **1.1 Web scanning** (pending): DAST for web paths (e.g. /DVWA/).
- **1.2 Classification & Prioritization**(pending): Sorting findings by severity.

