import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

print("Loading and training PhishGuard AI...")

# Dummy training data
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
labels = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0] # 1 is Phishing, 0 is Safe

# Process text
vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
X = vectorizer.fit_transform(texts)

# Train model
classifier = RandomForestClassifier(n_estimators=100, random_state=42)
classifier.fit(X, labels)

print("Training complete! Welcome to PhishGuard AI.\n")

def check_email():
    print("--- New Email Check ---")
    subject = input("Enter email subject: ")
    domain = input("Enter sender domain (e.g., bank.com): ")
    body = input("Enter email body: ")
    
    combined = "Subject: " + subject + "\nSender: " + domain + "\nBody: " + body
    
    vec_text = vectorizer.transform([combined])
    prediction = classifier.predict(vec_text)[0]
    
    print("\n[!] Analyzing...")
    if prediction == 1:
        print("RESULT: 🚨 WARNING! This looks like a PHISHING email.")
    else:
        print("RESULT: ✅ SAFE. This email looks benign.")
    print("-" * 25 + "\n")

if __name__ == "__main__":
    while True:
        try:
            check_email()
            again = input("Check another email? (y/n): ")
            if again.lower() != 'y':
                print("Exiting PhishGuard AI. Stay safe!")
                break
        except KeyboardInterrupt:
            print("\nExiting PhishGuard AI. Stay safe!")
            break
