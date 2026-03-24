from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.model import PhishingModel

app = FastAPI(
    title="PhishGuard AI API",
    description="Machine Learning based Phishing Detection Engine",
    version="1.0.0",
)

# Initialize a mock model for the purpose of the project
model = PhishingModel()
model.train_mock_data()

class EmailData(BaseModel):
    subject: str
    body: str
    sender_domain: str

class PredictionResponse(BaseModel):
    is_phishing: bool
    confidence: float
    threat_level: str

@app.post("/api/v1/analyze", response_model=PredictionResponse)
async def analyze_email(email: EmailData):
    try:
        is_phishing, confidence = model.predict(email.subject, email.body, email.sender_domain)
        threat_level = "HIGH" if confidence > 0.85 and is_phishing else "MEDIUM" if is_phishing else "LOW"
        return {
            "is_phishing": is_phishing,
            "confidence": round(confidence, 4),
            "threat_level": threat_level
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy", "model_loaded": True}
