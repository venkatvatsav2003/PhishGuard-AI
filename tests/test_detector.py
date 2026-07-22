import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from phishguard import PatternEngine, EmailAnalysis


def test_phishing_detection():
    engine = PatternEngine()
    text = "Urgent: Your account has been suspended. Click here to verify your password immediately."
    score, flags = engine.analyze(text)
    assert score > 0
    assert len(flags) > 0


def test_safe_email():
    engine = PatternEngine()
    text = "Hey, meeting at 3pm tomorrow. Bring the quarterly report."
    score, flags = engine.analyze(text)
    assert score == 0
    assert len(flags) == 0
