import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

class PhishingModel:
    def __init__(self):
        # Using a Random Forest classifier with TF-IDF features for robust text analysis
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=5000, stop_words='english')),
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])
        self.is_trained = False
        
    def train_mock_data(self):
        # Simulated dataset for demonstration
        texts = [
            "Urgent: Update your account immediately or it will be suspended.",
            "Meeting at 10 AM tomorrow in the main conference room.",
            "You have won a $1000 gift card! Click here to claim your prize.",
            "Please review the attached invoice for your recent purchase.",
            "Your password has expired. Click this link to reset it now.",
            "Hey, just checking in to see if we're still on for lunch.",
            "Security Alert: Unrecognized login detected on your account.",
            "Monthly newsletter: Updates on our new product features.",
            "Verify your bank details to receive the pending wire transfer.",
            "The project deadline has been extended to next Friday."
        ]
        labels = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0] # 1: Phishing, 0: Benign
        
        self.pipeline.fit(texts, labels)
        self.is_trained = True
        
    def predict(self, subject: str, body: str, sender_domain: str) -> tuple[bool, float]:
        if not self.is_trained:
            raise ValueError("Model is not trained.")
            
        # Combine fields into a single text representation
        # A more advanced model might handle these features separately
        combined_text = f"Subject: {subject}\nSender: {sender_domain}\nBody: {body}"
        
        proba = self.pipeline.predict_proba([combined_text])[0]
        prediction = self.pipeline.predict([combined_text])[0]
        
        # probability of class 1 (phishing)
        confidence = proba[1] if prediction == 1 else proba[0]
        
        return bool(prediction), float(confidence)
