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

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   HOST MACHINE                      │
│                                                     │
│  Python Scanner (this repo)                         │
│    ├── uv run tool scan <ip>          (uses nmap)   │
│    ├── uv run tool web-scan <url>     (uses ZAP)    │
│    └── uv run tool detect             (queries ES)  │
│                                                     │
│  nmap        → install via scripts/setup-nmap       │
│  OWASP ZAP   → install via scripts/setup-zap        │
└────────────────────────┬────────────────────────────┘
                         │ ports 80, 9200, 5601
┌────────────────────────▼────────────────────────────┐
│                  DOCKER STACK                       │
│                                                     │
│  dvwa          :80    ← scan target (DVWA + Apache) │
│  db                   ← MariaDB for DVWA            │
│  elasticsearch :9200  ← SIEM backend                │
│  filebeat             ← ships Apache logs → ES      │
│  kibana        :5601  ← log visualisation           │
└─────────────────────────────────────────────────────┘
```

Apache log flow: `dvwa` writes to a shared Docker volume → `filebeat` reads and ships to `elasticsearch` in ECS format → Python `detect` command queries for attack patterns.

---

## Quick Start

### 1. Start the Docker stack

```bash
cd docker
docker compose up -d --build
```

| Service | URL |
|---------|-----|
| DVWA | http://localhost/DVWA (admin / password) |
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |

### 2. Install host tools

```bash
# Phase 1 — network scanner
make -C scripts/setup-nmap

# Phase 1 — web scanner
make -C scripts/setup-zap install
```

### 3. Run the tools

```bash
uv sync                    # install Python dependencies (first time only)

# Network scan
uv run tool scan 127.0.0.1

# Web scan — ZAP must be running first
make -C scripts/setup-zap run
uv run tool web-scan 127.0.0.1/DVWA -u admin -p password

# Intrusion detection — queries last N minutes of Apache logs from Elasticsearch
uv run tool detect --interval 60
```

Reports are saved automatically to `/data/scans/`.

---

## Prerequisites

### Phase 1 — Vulnerability Analysis

These tools run on the **host machine** and connect to the DVWA container.

| Tool | Install | Notes |
|------|---------|-------|
| **nmap** | `make -C scripts/setup-nmap` | Required for `uv run tool scan` |
| **OWASP ZAP** | `make -C scripts/setup-zap install` | Must be running before `uv run tool web-scan` |
| **Python deps** | `uv sync` | Managed with [uv](https://github.com/astral-sh/uv) |

ZAP runs as a daemon on `127.0.0.1:8080` with the API key disabled:

```bash
make -C scripts/setup-zap run      # background — terminal returns, logs go to /tmp/zap.log
make -C scripts/setup-zap run-fg   # foreground — output visible in terminal, Ctrl+C to stop
make -C scripts/setup-zap stop
make -C scripts/setup-zap status
```

### Phase 2 — Threat Detection

No additional host tools required. Elasticsearch and Filebeat run inside Docker and are started automatically with `docker compose up`. The `detect` command connects to `http://localhost:9200` by default.

To load the Kibana data view and saved searches bundled with the repo:

```bash
make -C scripts/setup-kibana install
```

Open `http://localhost:5601` → *Discover* and pick any of the `TFM - …` saved searches to tail hostile traffic in real time.

---

## Project Phases & Status

### Phase 1: Vulnerability Analysis
- **1.1 Network & service scanning**: Uses `python-nmap` to identify open ports and services.
- **1.1 Web scanning (DAST)**: Automated authenticated scanning using **OWASP ZAP**.
- **1.2 Classification**: Results are automatically prioritized by severity and stored as JSON.
- **1.3 Automated Reporting**: Detailed logs are generated in the `/data/scans/` directory.

### Phase 2: Threat Detection & Active Mitigation
- **2.1 SIEM Integration**: Centralized logging using Elasticsearch and Filebeat to monitor Apache2 traffic in real-time.
- **2.2 Log Parsing**: Automatic mapping of raw web logs to Elastic Common Schema (ECS) for standardized analysis.
- **2.3 Three-layer Detection Engine** (`src/detection/`):
  - *Signature engine* — regex catalogue covering SQLi, XSS, path traversal, command injection and file inclusion.
  - *Anomaly engine* — per-IP statistical baseline (request volume, 4xx rate, path enumeration) with adaptive thresholds.
  - *Correlation engine* — joins signature and anomaly findings to surface multi-vector attacks, recon→exploit chains, authentication brute force and distributed scans.
- **2.4 Kibana Visibility**: `scripts/setup-kibana` imports a data view plus saved searches for SQLi, XSS, path traversal, 4xx bursts and authentication attempts.
- **2.5 Active Response**: Automated identification and blacklisting of malicious IPs, stored in `/data/firewall/blocked_ips.txt`.

---

## Technology Stack

| Area | Technology |
|------|------------|
| **Target Environment** | Damn Vulnerable Web App (DVWA) |
| **Security Scanning** | OWASP ZAP, nmap |
| **Monitoring (SIEM)** | ELK Stack (Elasticsearch, Filebeat, Kibana) |
| **WAF** | ModSecurity *(planned)* |
| **Development** | Python (managed with [uv](https://github.com/astral-sh/uv)), Visual Studio Code |
| **Infrastructure** | Docker, Docker Compose |

---

## Running without Docker

To run DVWA and the ELK stack on a separate Ubuntu server instead of Docker:

### ELK Stack on Ubuntu

1. Add the Elastic APT repo and install `elasticsearch` and `filebeat`.
2. Edit `/etc/elasticsearch/elasticsearch.yml`:
   ```yaml
   network.host: 0.0.0.0
   discovery.type: single-node
   xpack.security.enabled: false
   xpack.security.http.ssl.enabled: false
   ```
3. Enable and configure the Filebeat Apache module:
   ```bash
   sudo filebeat modules enable apache
   # In /etc/filebeat/modules.d/apache.yml set access.enabled: true
   ```
4. Start both services: `sudo systemctl start elasticsearch filebeat`

Then point the `detect` command at your server:
```bash
uv run tool detect --host <server-ip>
```

Use `make -C scripts/setup-elk status` to verify the stack is reachable.
