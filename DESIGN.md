# PhishGuard AI — Design Document

## Problem Statement
Phishing attacks account for 90%+ of data breaches. Traditional spam filters struggle with zero-day phishing campaigns that bypass signature-based detection.

## Design Philosophy
Instead of training ML models (data-hungry, opaque, brittle), PhishGuard uses a multi-layer heuristic engine that is:
- **Interpretable** — every verdict has traceable reasons
- **Extensible** — add patterns without retraining
- **Deterministic** — same input always yields same result
- **Zero-dependency** — no ML frameworks, no training data

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Input Layer                          │
│  CLI args │ Interactive │ File │ stdin           │
└─────────────────────┬───────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────┐
│              Analysis Pipeline                    │
│                                                   │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  │
│  │ Pattern    │  │ Domain     │  │ URL        │  │
│  │ Engine     │  │ Analyzer   │  │ Analyzer   │  │
│  │ (8 cats)   │  │ WHOIS/MX   │  │ TLD/       │  │
│  │            │  │ SPF        │  │ Shortener  │  │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  │
│        └───────────────┼───────────────┘          │
└────────────────────────┼──────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────┐
│              Scoring Engine                       │
│  Weighted sum → Verdict (Safe/Suspicious/Phish)  │
└─────────────────────┬───────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────┐
│              Output Layer                         │
│  Console table │ JSON │ Color-coded verdict       │
└─────────────────────────────────────────────────┘
```

## Detection Categories Researched
1. **Credential Harvesting** — language patterns used in phishing kits
2. **Urgency Tactics** — psychological pressure techniques
3. **Suspicious Links** — URL obfuscation and shortener abuse
4. **Brand Impersonation** — top 10 most impersonated brands
5. **Sensitive Info Requests** — data types targeted by phishers
6. **Too-Good-To-Be-True** — lure tactics
7. **Financial Scams** — wire fraud, crypto scams
8. **Spoofed Sender** — display name vs. actual domain mismatches

## Domain Intelligence
- **WHOIS Age**: Newly registered domains (<30 days) are high risk
- **MX Records**: Legitimate domains have mail servers
- **SPF Records**: Absence indicates unauthenticated sending capability

## Limitations
- No NLP/LLM — cannot understand context or sarcasm
- No attachment scanning — focuses on email content
- Domain checks require network access
