# PhishGuard AI

An advanced, machine-learning powered Phishing Detection Engine. PhishGuard AI analyzes incoming emails using Natural Language Processing (NLP) and a Random Forest Classifier to detect malicious intent and credential harvesting attempts.

## Features
- **RESTful API:** Built with FastAPI for high performance and easy integration with email servers or SIEMs.
- **Machine Learning Pipeline:** Utilizes `scikit-learn` with TF-IDF vectorization and a Random Forest classifier for robust text analysis.
- **Threat Scoring:** Returns confidence metrics and categorized threat levels for automated incident response.
- **Scalable:** Designed to handle high-throughput email streams.

## Architecture
Incoming emails (subject, body, sender domain) are passed via JSON payload to the `/api/v1/analyze` endpoint. The text is pre-processed and vectorized using TF-IDF, then fed into the ML model which determines if the semantic structure matches known phishing patterns.

## Setup & Execution

### Requirements
- Python 3.9+

### Installation
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the API server:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### Usage Example
```bash
curl -X 'POST' \
  'http://localhost:8000/api/v1/analyze' \
  -H 'Content-Type: application/json' \
  -d '{
  "subject": "Urgent: Account Suspension Notice",
  "body": "Your account will be suspended in 24 hours. Click here to verify your details.",
  "sender_domain": "security-alert-update.com"
}'
```

## Future Enhancements
- Integration with external threat intelligence feeds.
- Advanced URL extraction and sandboxed domain reputation checking.
- Deep Learning (BERT-based) model integration for better context awareness.
