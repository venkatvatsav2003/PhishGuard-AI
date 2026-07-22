#!/usr/bin/env python3
import os
import re
import json
import yaml
import socket
import logging
import argparse
import hashlib
import whois
import dns.resolver
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("phishguard")


@dataclass
class EmailAnalysis:
    subject: str = ""
    sender_domain: str = ""
    sender_name: str = ""
    reply_to: str = ""
    body: str = ""
    urls: List[str] = field(default_factory=list)
    score: int = 0
    max_score: int = 0
    verdict: str = "SAFE"
    flags: List[dict] = field(default_factory=list)
    domain_age_days: int = -1
    domain_suspicious: bool = False
    has_mx_record: bool = False
    has_spf: bool = False
    url_risk_count: int = 0
    risk_indicators: List[str] = field(default_factory=list)

    TO_JSON_FIELDS = ["subject", "sender_domain", "score", "max_score", "verdict", "flags", "domain_age_days", "domain_suspicious", "has_mx_record", "has_spf", "url_risk_count", "risk_indicators"]


class PatternEngine:
    CATEGORIES = {
        "credential_harvesting": {
            "patterns": [
                r"(verify|confirm|update|restore|recover)\s.*(account|payment|billing|identity)",
                r"(sign\s?in|log\s?in)\s.*(problem|issue|failed|attempt)",
                r"security\s.*(check|update|verify|alert)",
            ],
            "weight": 3, "description": "Credential harvesting language",
        },
        "urgency": {
            "patterns": [
                r"urgent|immediate\s(action|attention)|time.sensitive|act\snow",
                r"account\s.*(suspended|locked|closed|limited|restricted)",
                r"(within|before|by)\s\d{1,2}\s?(hour|day)",
                r"failure\sto\s(comply|respond|verify)",
            ],
            "weight": 2, "description": "Urgency / social engineering tactics",
        },
        "suspicious_links": {
            "patterns": [
                r"click\s.*(here|link|button|below)",
                r"https?://(bit\.ly|tinyurl|shorturl|t\.co|rb\.gy|ow\.ly)",
                r"<a\s+href",
            ],
            "weight": 2, "description": "Suspicious link patterns",
        },
        "brand_impersonation": {
            "patterns": [
                r"\b(paypal|amazon|netflix|apple|microsoft|google|facebook|instagram|linkedin)\b",
                r"(support|help|service|team)@[a-z]+\.[a-z]+",
                r"(bank|chase|wells\s?fargo|citi|hsbc|barclays)",
            ],
            "weight": 2, "description": "Brand impersonation detected",
        },
        "sensitive_info": {
            "patterns": [
                r"(password|ssn|social.security|credit.card|cvv|pin|atm|otp|secret)",
                r"(date.of.birth|dob|mother.maiden|driver.license)",
                r"(passport|tax.id|election.id)",
            ],
            "weight": 3, "description": "Sensitive information request",
        },
        "too_good_true": {
            "patterns": [
                r"(prize|winner|lotto|lottery|inheritance|bequest)",
                r"(gift\s?card|free\s.*(iphone|macbook|gift))",
                r"congratulations\s.*(won|selected|chosen)",
            ],
            "weight": 2, "description": "Too-good-to-be-true offer",
        },
        "financial_scam": {
            "patterns": [
                r"(transfer|wire|money\sgram|western\sunion)",
                r"(invoice|payment|refund|overpayment|transaction)",
                r"(crypto|bitcoin|btc|ethereum|wallet)",
                r"(nigerian|419|advance\sfee)",
            ],
            "weight": 2, "description": "Financial scam indicators",
        },
        "spoofed_sender": {
            "patterns": [
                r"@(gmail|yahoo|hotmail|outlook)\.com.*@[a-z]+\.[a-z]{2,3}$",
                r"(no.reply|donotreply|noreply)@",
                r"@[a-z]+-[a-z]+\.(com|org|net)",
            ],
            "weight": 2, "description": "Suspicious sender pattern",
        },
    }

    def analyze(self, text: str) -> Tuple[int, List[dict]]:
        text_lower = text.lower()
        score = 0
        flags = []
        for cat, config in self.CATEGORIES.items():
            for pat in config["patterns"]:
                if re.search(pat, text_lower):
                    score += config["weight"]
                    flags.append({"category": cat, "description": config["description"], "weight": config["weight"]})
                    break
        return score, flags


class DomainAnalyzer:
    @staticmethod
    def check_domain(domain: str) -> dict:
        result = {"suspicious": False, "age_days": -1, "has_mx": False, "has_spf": False, "reasons": []}
        try:
            domain_clean = re.sub(r'^https?://', '', domain).split('/')[0].split('@')[-1]

            # Check age via WHOIS
            try:
                w = whois.whois(domain_clean)
                if w.creation_date:
                    if isinstance(w.creation_date, list):
                        cdate = w.creation_date[0]
                    else:
                        cdate = w.creation_date
                    age = (datetime.now() - cdate).days
                    result["age_days"] = age
                    if age < 30:
                        result["suspicious"] = True
                        result["reasons"].append(f"Domain registered {age} days ago (< 30)")
                    elif age < 365:
                        result["reasons"].append(f"Domain registered {age} days ago (< 1 year)")
            except Exception as e:
                result["reasons"].append(f"WHOIS lookup failed: {e}")

            # Check MX records
            try:
                answers = dns.resolver.resolve(domain_clean, 'MX')
                result["has_mx"] = len(answers) > 0
            except:
                result["has_mx"] = False

            # Check SPF
            try:
                answers = dns.resolver.resolve(domain_clean, 'TXT')
                for r in answers:
                    if 'v=spf1' in str(r):
                        result["has_spf"] = True
                        break
            except:
                result["has_spf"] = False

        except Exception as e:
            result["reasons"].append(f"Domain check error: {e}")
        return result


class URLAnalyzer:
    SUSPICIOUS_TLDS = {'.xyz', '.top', '.club', '.work', '.download', '.review', '.date', '.men', '.loan', '.click', '.country', '.faith', '.gq', '.tk', '.ml', '.cf'}
    KNOWN_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'rb.gy', 'shorturl.at', 'buff.ly', 'tiny.cc', 'tr.im', 'is.gd', 'cli.gs'}

    @staticmethod
    def analyze_urls(text: str) -> Tuple[List[str], int]:
        urls = re.findall(r'https?://[^\s<>"\'\[\]]+', text)
        risk_count = 0
        for url in urls:
            domain = url.split('/')[2].lower() if '://' in url else url.split('/')[0].lower()
            if any(domain.endswith(tld) for tld in URLAnalyzer.SUSPICIOUS_TLDS):
                risk_count += 2
            if any(shortener in url for shortener in URLAnalyzer.KNOWN_SHORTENERS):
                risk_count += 1
            if re.search(r'\d+s?\.\w{2,3}$', domain):  # domains like "secure123.xyz"
                risk_count += 1
        return urls, risk_count


class PhishGuardEngine:
    def __init__(self, config_path: str = "config/patterns.yml"):
        self.pattern_engine = PatternEngine()
        self.domain_analyzer = DomainAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.config = {}
        if Path(config_path).exists():
            self.config = yaml.safe_load(Path(config_path).read_text()) or {}

    def analyze(self, subject: str, sender_domain: str, body: str, sender_name: str = "", reply_to: str = "") -> EmailAnalysis:
        result = EmailAnalysis(
            subject=subject,
            sender_domain=sender_domain,
            sender_name=sender_name,
            reply_to=reply_to,
            body=body[:2000],
        )

        full_text = f"{subject} {sender_domain} {sender_name} {reply_to} {body}"

        # Pattern analysis
        pattern_score, flags = self.pattern_engine.analyze(full_text)
        result.score += pattern_score
        result.flags = flags
        result.max_score = sum(c["weight"] for c in PatternEngine.CATEGORIES.values())

        # URL analysis
        urls, url_risk = self.url_analyzer.analyze_urls(full_text)
        result.urls = urls
        result.url_risk_count = url_risk
        result.score += url_risk

        # Domain analysis
        domain_info = self.domain_analyzer.check_domain(sender_domain)
        result.domain_age_days = domain_info["age_days"]
        result.domain_suspicious = domain_info["suspicious"]
        result.has_mx_record = domain_info["has_mx"]
        result.has_spf = domain_info["has_spf"]
        if domain_info["suspicious"]:
            result.score += 3
        if not domain_info["has_spf"] and sender_domain not in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com"):
            result.score += 1

        # Verdict
        if result.score >= 10:
            result.verdict = "PHISHING"
        elif result.score >= 6:
            result.verdict = "SUSPICIOUS"
        else:
            result.verdict = "SAFE"

        result.risk_indicators = [f["description"] for f in result.flags]
        if result.domain_suspicious: result.risk_indicators.append(f"Suspicious domain ({result.domain_age_days} days old)")
        if not result.has_spf: result.risk_indicators.append("No SPF record")
        if result.url_risk_count > 0: result.risk_indicators.append(f"{result.url_risk_count} risky URLs detected")

        return result


def main():
    parser = argparse.ArgumentParser(description="PhishGuard AI — Phishing Email Detection Engine")
    parser.add_argument("-s", "--subject", help="Email subject")
    parser.add_argument("-d", "--domain", help="Sender domain")
    parser.add_argument("-b", "--body", help="Email body")
    parser.add_argument("-n", "--name", help="Sender name")
    parser.add_argument("-r", "--reply-to", help="Reply-To address")
    parser.add_argument("-c", "--config", default="config/patterns.yml")
    parser.add_argument("-f", "--file", help="Analyze email from file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    args = parser.parse_args()

    engine = PhishGuardEngine(args.config)

    if args.interactive or not any([args.subject, args.domain, args.body, args.file]):
        print("=== PhishGuard AI Interactive Analysis ===\n")
        subject = input("Email subject: ")
        domain = input("Sender domain: ")
        body = input("Email body: ")
        name = input("Sender name (optional): ")
        result = engine.analyze(subject, domain, body, name)
    elif args.file:
        content = Path(args.file).read_text()
        result = engine.analyze(args.subject or "", args.domain or "", content, args.name or "", args.reply_to or "")
    else:
        result = engine.analyze(args.subject or "", args.domain or "", args.body or "", args.name or "", args.reply_to or "")

    if args.json:
        print(json.dumps({k: v for k, v in asdict(result).items() if k in result.TO_JSON_FIELDS}, indent=2, default=str))
        return

    print(f"\n{'='*60}")
    print(f"  PhishGuard AI — Email Analysis Report")
    print(f"{'='*60}")
    print(f"  Subject:    {result.subject}")
    print(f"  From:       {result.sender_domain}")
    print(f"  Risk Score: {result.score}/{result.max_score + 10}")
    print(f"  Verdict:    {result.verdict}")
    if result.risk_indicators:
        print(f"\n  Indicators:")
        for ri in result.risk_indicators:
            print(f"    - {ri}")
    print(f"\n  Domain:")
    print(f"    Age:       {result.domain_age_days} days" if result.domain_age_days >= 0 else "    Age:       Unknown")
    print(f"    MX Record: {'YES' if result.has_mx_record else 'NO'}")
    print(f"    SPF:       {'YES' if result.has_spf else 'NO'}")
    if result.urls:
        print(f"\n  URLs ({len(result.urls)} found, {result.url_risk_count} risky):")
        for u in result.urls[:5]:
            print(f"    {u[:80]}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
