# PhishGuard AI

![CI](https://github.com/venkatvatsav2003/PhishGuard-AI/actions/workflows/ci.yml/badge.svg)
![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Language](https://img.shields.io/badge/language-Python%20%2B%20Bash-blue)

An AI-powered phishing email detection engine that combines pattern analysis, domain reputation checking (WHOIS, MX, SPF), URL risk scoring, and behavioral heuristics to classify emails as Safe, Suspicious, or Phishing.

## Features

- **8-Category Pattern Analysis** — Credential harvesting, urgency, brand impersonation, financial scams, and more
- **Domain Intelligence** — WHOIS age verification, MX record presence, SPF record validation
- **URL Analysis** — Suspicious TLD detection, link shortener identification, numerical domain detection
- **Weighted Scoring** — Configurable per-category weights for risk calculation
- **Multi-Mode Input** — Interactive, CLI arguments, file-based analysis
- **JSON Output** — Machine-readable for SIEM/automation integration
- **No ML Dependencies** — Pure heuristics, no training data needed
- **CI/CD Ready** — GitHub Actions workflow included

## Quick Start

```bash
# Interactive analysis
./analyze.sh --interactive

# CLI analysis
./analyze.sh -s "Urgent Password Reset" -d "secure-bank.com" -b "Click here to verify"

# File analysis
./analyze.sh -f email.txt

# JSON output
./analyze.sh --interactive --json
```

## Example Output

```
============================================================
  PhishGuard AI — Email Analysis Report
============================================================
  Subject:    Urgent: Your Account Has Been Suspended
  From:       secure-bank.com
  Risk Score: 11/23
  Verdict:    PHISHING

  Indicators:
    - Urgency / social engineering tactics
    - Credential harvesting language
    - Brand impersonation detected
    - Suspicious domain (12 days old)
    - No SPF record

  Domain:
    Age:       12 days
    MX Record: YES
    SPF:       NO
============================================================
```

## Scoring

| Score Range | Verdict | Action |
|-------------|---------|--------|
| 0-5 | SAFE | Allow delivery |
| 6-9 | SUSPICIOUS | Flag for review |
| 10+ | PHISHING | Quarantine / block |

## Project Structure

```
PhishGuard-AI/
├── phishguard.py           # Python detection engine
├── analyze.sh              # Bash orchestrator
├── config/patterns.yml     # Detection patterns & weights
├── data/samples/           # Example phishing/safe emails
├── tests/                  # Pytest suite
├── reports/                # Analysis output
├── Dockerfile
├── Makefile
└── .github/workflows/
```

## Dependencies

- Python 3.8+ (with `pyyaml`, `python-whois`, `dnspython`)
