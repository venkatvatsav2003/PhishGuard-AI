#!/usr/bin/env bash
set -euo pipefail

VERSION="2.0.0"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

usage() {
    cat <<EOF
PhishGuard AI v$VERSION — Phishing Email Detection

Usage: $0 [options]
   or: $0 --file email.txt
   or: $0 --interactive

Options:
  -s, --subject TEXT    Email subject
  -d, --domain TEXT     Sender domain
  -b, --body TEXT       Email body
  -f, --file FILE       Read email from file
  -n, --name TEXT       Sender display name
  -r, --reply-to TEXT   Reply-To address
  -c, --config FILE     Config file (default: config/patterns.yml)
  --json                JSON output
  -i, --interactive     Interactive mode
  --whois               Force WHOIS lookup
  --dns-check           Check SPF/DKIM/DMARC
  -h, --help            Show this help

Examples:
  $0 --interactive
  $0 -s "Urgent" -d "secure-bank.com" -b "Click here to verify"
  $0 -f phishing.eml
EOF
    exit 0
}

log_info()  { echo -e "${CYAN}[*]${NC} $1" >&2; }
log_ok()    { echo -e "${GREEN}[+]${NC} $1" >&2; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1" >&2; }

check_deps() {
    local missing=()
    python3 -c "import yaml, whois, dns.resolver" 2>/dev/null || missing+=("pyyaml python-whois dnspython")
    if [ ${#missing[@]} -gt 0 ]; then
        log_warn "Installing missing Python packages: ${missing[*]}"
        pip3 install ${missing[*]} -q
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        -s|--subject) SUBJECT="$2"; shift 2 ;;
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -b|--body) BODY="$2"; shift 2 ;;
        -f|--file) FILE="$2"; shift 2 ;;
        -n|--name) NAME="$2"; shift 2 ;;
        -r|--reply-to) REPLY="$2"; shift 2 ;;
        -c|--config) CONFIG="$2"; shift 2 ;;
        --json) JSON="--json"; shift ;;
        -i|--interactive) INTERACTIVE="--interactive"; shift ;;
        --whois) WHOIS="--whois"; shift ;;
        --dns-check) DNS="--dns-check"; shift ;;
        *) log_err "Unknown: $1"; usage ;;
    esac
done

check_deps

ARGS=""
[ -n "${SUBJECT:-}" ] && ARGS="$ARGS -s \"$SUBJECT\""
[ -n "${DOMAIN:-}" ]  && ARGS="$ARGS -d \"$DOMAIN\""
[ -n "${BODY:-}" ]    && ARGS="$ARGS -b \"$BODY\""
[ -n "${FILE:-}" ]    && ARGS="$ARGS -f \"$FILE\""
[ -n "${NAME:-}" ]    && ARGS="$ARGS -n \"$NAME\""
[ -n "${REPLY:-}" ]   && ARGS="$ARGS -r \"$REPLY\""
[ -n "${CONFIG:-}" ]  && ARGS="$ARGS -c \"$CONFIG\""
[ -n "${JSON:-}" ]    && ARGS="$ARGS --json"
[ -n "${INTERACTIVE:-}" ] && ARGS="$ARGS --interactive"

eval "python3 phishguard.py $ARGS"
