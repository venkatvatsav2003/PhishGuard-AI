import requests
import json

def test_phishing(subject, body, domain):
    url = "http://localhost:8000/api/v1/analyze"
    payload = {
        "subject": subject,
        "body": body,
        "sender_domain": domain
    }
    
    print(f"Testing: {subject}")
    try:
        response = requests.post(url, json=payload)
        result = response.json()
        print(f"Result: {'🚨 PHISHING' if result['is_phishing'] else '✅ BENIGN'}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Threat Level: {result['threat_level']}")
        print("-" * 30)
    except Exception as e:
        print(f"Error: Ensure the server is running on localhost:8000. ({e})")

if __name__ == "__main__":
    print("--- PhishGuard AI Demo ---")
    test_phishing("Urgent: Verify your account", "Please click here to update your password.", "security-bank.net")
    test_phishing("Lunch tomorrow?", "Hey, are we still meeting at the cafe at 12?", "colleague@company.com")
