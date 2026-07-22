# PhishGuard AI — Design Document

## Problem Statement
Phishing attacks remain one of the most common and effective cyber threats. Traditional spam filters rely on static rule sets that struggle to keep pace with evolving social engineering tactics.

## Core Ideology
Security must be accessible. Not every organization can deploy enterprise-grade ML infrastructure. PhishGuard AI aims to provide a lightweight, transparent phishing detection engine that anyone can run, audit, and extend.

## Architecture

```
Email Input
    |
    v
[Text Extraction] --> subject, domain, body
    |
    v
[Pattern Matching Engine] --> 8 indicator categories
    |
    v
[Risk Scorer] --> weighted score based on matched indicators
    |
    v
[Verdict] --> Safe / Suspicious / Phishing
```

## Detection Categories
1. **Credential Harvesting** — language asking for account verification, password resets
2. **Urgency Tactics** — time pressure language ("act now", "limited time")
3. **Suspicious Links** — disguised or mismatched URLs
4. **Brand Impersonation** — mentions of known brands/spoofed domains
5. **Sensitive Info Requests** — asking for passwords, SSN, credit card details
6. **Too-Good-To-Be-True** — lottery wins, prizes, inheritances
7. **Financial Scams** — invoice fraud, wire transfer requests
8. **Malicious Attachments** — unexpected file downloads

## Threat Model
- **Attacker capability**: Social engineering via email
- **Attack vector**: Spear phishing, whaling, clone phishing
- **Defense mechanisms**: Pattern matching, domain reputation, linguistic analysis

## Limitations & Future Work
- Currently uses static pattern matching — could be enhanced with NLP-based analysis
- No URL reputation checking (future)
- No attachment sandboxing (future)

## Why This Approach
Pattern-based detection is interpretable (you can explain why an email was flagged), fast, and requires no external dependencies. It serves as a foundation layer that could feed into a broader security stack.
