#!/usr/bin/env python3
import re
import sys

PHISHING_PATTERNS = [
    (r"(verify|confirm|update|suspended|locked)\s.*(account|payment|identity)", "Credential harvesting"),
    (r"urgent|immediate action|account will be closed|limited time", "Urgency tactic"),
    (r"(click|tap)\s.*(here|link|button)", "Suspicious link"),
    (r"(bank|paypal|amazon|netflix|apple|crypto|wallet)", "Brand impersonation"),
    (r"(password|ssn|social security|credit card|cvv|pin|otp)", "Sensitive info request"),
    (r"(prize|winner|lotto|inheritance|gift card|free)", "Too-good-to-be-true"),
    (r"(transfer|wire|money|payment|invoice|refund)", "Financial scam"),
    (r"(attachment|download this file)", "Malicious attachment"),
]

def analyze_email(subject, sender_domain, body):
    text = f"{subject} {sender_domain} {body}".lower()
    score = 0
    flags = []
    for pattern, desc in PHISHING_PATTERNS:
        if re.search(pattern, text):
            score += 1
            flags.append(desc)
    return score, flags

if __name__ == "__main__":
    print("=== PhishGuard AI ===")
    subject = input("Enter email subject: ")
    domain = input("Enter sender domain: ")
    body = input("Enter email body: ")
    score, flags = analyze_email(subject, domain, body)
    print(f"\nRisk score: {score}/{len(PHISHING_PATTERNS)}")
    if flags:
        print(f"Indicators detected: {', '.join(flags)}")
    if score >= 5:
        print("Verdict: PHISHING (High Risk)")
    elif score >= 3:
        print("Verdict: SUSPICIOUS (Medium Risk)")
    else:
        print("Verdict: SAFE (Low Risk)")
