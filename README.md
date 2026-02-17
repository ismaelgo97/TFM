# Attack Detection and Prevention System for Web Applications

A Master's Thesis (TFM) project that builds a system to detect and prevent attacks in web applications.

---

## Project Overview

The goal is to build a security system that finds, classifies and mitigates vulnerabilities in real time. It combines detection and prevention to protect web apps from common attacks and misconfigurations.

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

### Phase 1: Vulnerability Analysis
- **1.1 Network & service scanning**: Uses `python-nmap` to identify open ports and services.
- **1.1 Web scanning (DAST)**: Automated authenticated scanning using **OWASP ZAP**.
- **1.2 Classification**: Results are automatically prioritized by severity and stored as JSON.
- **1.3 Automated Reporting**: Detailed logs are generated in the `/data/scans/` directory.

