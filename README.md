# PhishGuard AI

![CI](https://github.com/venkatvatsav2003/PhishGuard-AI/actions/workflows/ci.yml/badge.svg)
![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

**Phishing email detection with pattern analysis, domain intelligence, and URL reputation.**

## Install & Run

```bash
# One-liner
pip install phishguard && phishguard --interactive

# Or clone and run
git clone https://github.com/venkatvatsav2003/PhishGuard-AI.git
cd PhishGuard-AI && pip install -r requirements.txt
./analyze.sh --interactive

# Analyze an email file
./analyze.sh -f email.txt

# Docker
docker-compose run phishguard --interactive
```

## Features

- **8 Detection Categories** — credential harvesting, urgency, brand impersonation, financial scams, and more
- **Domain Intelligence** — WHOIS age verification, MX/SPF record checks
- **URL Analysis** — suspicious TLD detection, link shortener identification
- **Email Parsing** — analyze `.eml` files directly
- **Configurable Patterns** — YAML-based rule engine
- **JSON Output** — machine-readable for automation/SIEM
- **API Mode** — REST API for integration with mail servers

## Quick Start

```bash
# Interactive
./analyze.sh --interactive

# CLI
./analyze.sh -s "Urgent Password Reset" -d "secure-bank.com" -b "Click here"

# File
./analyze.sh -f email.eml

# JSON output
./analyze.sh --interactive --json
```

## Scoring

| Score | Verdict | Action |
|-------|---------|--------|
| 0-5 | SAFE | Allow delivery |
| 6-9 | SUSPICIOUS | Flag for review |
| 10+ | PHISHING | Quarantine / block |

## Project Structure

```
PhishGuard-AI/
├── phishguard.py            # Python engine
├── analyze.sh               # Bash launcher
├── pyproject.toml           # pip install
├── docker-compose.yml       # Docker one-command
├── .env.example             # Config template
├── config/patterns.yml      # Detection rules
├── data/samples/            # Example emails
├── tests/
├── Dockerfile
└── Makefile
```
