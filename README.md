# PhishGuard AI

A pattern-based phishing email detection tool built with Python. Analyzes email content for common phishing indicators and produces a risk score.

## How It Works
Scans email subject, sender domain, and body against 8 indicator categories:
- Credential harvesting language
- Urgency/social engineering tactics
- Suspicious link patterns
- Brand impersonation
- Sensitive information requests
- Too-good-to-be-true offers
- Financial scam language
- Malicious attachment indicators

## Usage
```bash
python phishguard.py
```

Then enter the email details when prompted.

## Example
```
=== PhishGuard AI ===
Enter email subject: Urgent Password Reset
Enter sender domain: secure-bank.com
Enter email body: Click here to verify your account immediately.

Risk score: 4/8
Indicators detected: Credential harvesting, Urgency tactic, Suspicious link, Brand impersonation
Verdict: SUSPICIOUS (Medium Risk)
```

## Design
See `DESIGN.md` for architecture, threat model, and design decisions.

## Dependencies
- Python 3 (no external packages required)
