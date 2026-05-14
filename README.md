# PhishGuard AI

A simple machine learning script to detect phishing emails. Built using Python and scikit-learn.

## How it works
It uses a Random Forest Classifier and TF-IDF to analyze the text of an email (subject, domain, and body) and classify it as either Phishing or Safe. It trains on a small dummy dataset when you run the script.

## Setup

1. Install the requirements:
```bash
pip install -r requirements.txt
```

2. Run the script:
```bash
python phishguard.py
```

## Example Usage
```text
Loading and training PhishGuard AI...
Training complete! Welcome to PhishGuard AI.

--- New Email Check ---
Enter email subject: Urgent Password Reset
Enter sender domain (e.g., bank.com): support-alert.com
Enter email body: Click here to secure your account immediately!

[!] Analyzing...
RESULT: 🚨 WARNING! This looks like a PHISHING email.
```
