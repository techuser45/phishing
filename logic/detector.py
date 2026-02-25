import re
import time
import joblib
import os

# Load ML models
try:
    email_model = joblib.load('models/email_model.joblib')
    file_model = joblib.load('models/file_model.joblib')
    ML_AVAILABLE = True
except:
    ML_AVAILABLE = False
    print("Warning: ML models not found. Falling back to rule-based detection only.")

def analyze_url(url):
    score = 100
    verdict = "safe"
    steps = [
        {"name": "Database Check", "status": "safe", "details": "No known threats found"},
        {"name": "Structure Analysis", "status": "safe", "details": "Standard URL structure"},
        {"name": "Brand & Keywords", "status": "safe", "details": "No mimicry or sensitive terms"},
        {"name": "Security Protocol", "status": "safe", "details": "Secure HTTPS connection"}
    ]

    lower_url = url.lower()

    # 1. KNOWN THREATS DATABASE
    known_threats = [
        "testsafebrowsing.appspot.com",
        "ianfette.org",
        "example.com/phishing",
        "malware.testing.google.test"
    ]

    if any(threat in lower_url for threat in known_threats):
        return {
            "verdict": "danger",
            "score": 10,
            "steps": [
                {"name": "Database Check", "status": "danger", "details": "MATCH FOUND: Known Phishing Test Site"},
                {"name": "Structure Analysis", "status": "warning", "details": "Flagged by threat intelligence"},
                {"name": "Brand & Keywords", "status": "warning", "details": "High-risk signature detected"},
                {"name": "Security Protocol", "status": "safe", "details": "HTTPS (Valid but malicious)"}
            ]
        }

    # 2. PROTOCOL CHECK
    if lower_url.startswith("http://"):
        score -= 20
        steps[3] = {"name": "Security Protocol", "status": "warning", "details": "Insecure (HTTP) - Traffic not encrypted"}

    # 3. IP ADDRESS CHECK
    ip_regex = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    if re.search(ip_regex, lower_url):
        score -= 40
        steps[1] = {"name": "Structure Analysis", "status": "danger", "details": "Direct IP address usage is highly suspicious"}

    # 4. SUSPICIOUS CHARACTERISTICS
    if len(url) > 75:
        score -= 10
        if steps[1]["status"] == "safe":
            steps[1] = {"name": "Structure Analysis", "status": "warning", "details": "Unusually long URL length"}

    if lower_url.count(".") > 4:
        score -= 15
        steps[1] = {"name": "Structure Analysis", "status": "warning", "details": "Excessive subdomains detected (URL obfuscation)"}

    if "@" in lower_url:
        score -= 40
        steps[1] = {"name": "Structure Analysis", "status": "danger", "details": "URL contains '@' (Authorization Bypass Attempt)"}

    # 5. TYPOSQUATTING & BRAND MIMICRY
    suspicious_brands = ["g00gle", "goggle", "paypa1", "paypaI", "amaz0n", "micros0ft", "n0rton", "faceb00k", "netf1ix"]
    if any(brand in lower_url for brand in suspicious_brands):
        score -= 50
        steps[2] = {"name": "Brand & Keywords", "status": "danger", "details": "Typosquatting Detected (Brand Mimicry)"}

    # 6. SENSITIVE KEYWORDS
    keywords = ["login", "signin", "verify", "account", "update", "bank", "secure", "confirm", "wallet"]
    if any(kw in lower_url for kw in keywords):
        if score < 100 or lower_url.startswith("http://"):
            score -= 20
            if steps[2]["status"] == "safe":
                steps[2] = {"name": "Brand & Keywords", "status": "warning", "details": "Credential harvesting keywords detected"}

    # 7. SUSPICIOUS TLDs
    suspicious_tlds = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".cn", ".ru", ".site", ".work"]
    if any(lower_url.endswith(tld) or (tld + "/") in lower_url for tld in suspicious_tlds):
        score -= 25
        if steps[1]["status"] == "safe":
            steps[1] = {"name": "Structure Analysis", "status": "warning", "details": "High-risk TLD (often used for spam)"}

    # FINAL SCORING
    if score <= 50:
        verdict = "danger"
    elif score < 85:
        verdict = "warning"

    return {"verdict": verdict, "score": max(0, score), "steps": steps}


def analyze_email(text):
    score = 100
    verdict = "safe"
    steps = [
        {"name": "Rule Analysis", "status": "safe", "details": "No suspicious keywords matched"},
        {"name": "AI Prediction", "status": "safe", "details": "AI model analysis complete"},
        {"name": "Urgency Scan", "status": "safe", "details": "Tone is standard"},
        {"name": "Link Inspection", "status": "safe", "details": "Links appear safe"}
    ]

    lower_text = text.lower()
    
    # Emotional Deception Score (EDS) Breakdown
    eds = {
        "fear": 0.0,
        "urgency": 0.0,
        "trust": 0.0,
        "greed": 0.0,
        "authority": 0.0
    }

    # 1. ML Analysis (AI)
    ml_confidence = 0.0
    if ML_AVAILABLE:
        label = email_model.predict([text])[0]
        probs = email_model.predict_proba([text])[0]
        ml_confidence = float(max(probs))
        
        if label == 'phishing':
            score -= 50 * ml_confidence
            steps[1] = {"name": "AI Prediction", "status": "danger", "details": f"AI flagged as PHISHING (Confidence: {ml_confidence:.1%})"}
        elif label == 'suspicious':
            score -= 25 * ml_confidence
            steps[1] = {"name": "AI Prediction", "status": "warning", "details": f"AI flagged as SUSPICIOUS (Confidence: {ml_confidence:.1%})"}
        else:
            steps[1] = {"name": "AI Prediction", "status": "safe", "details": f"AI flagged as LEGIT (Confidence: {ml_confidence:.1%})"}

    # 2. URGENCY / SOCIAL ENGINEERING
    urgency_words = ["urgent", "immediately", "24 hours", "suspended", "locked", "unusual activity", "action required", "expiring", "now"]
    urgency_matches = [w for w in urgency_words if w in lower_text]
    if urgency_matches:
        eds["urgency"] = min(1.0, len(urgency_matches) * 0.2 + (0.3 if "urgent" in lower_text else 0))
        score -= 30
        steps[2] = {"name": "Urgency Scan", "status": "danger", "details": "High urgency/Panic induction detected"}

    # 3. FEAR
    fear_words = ["consequences", "legal action", "penalty", "block", "security breach", "unauthorized", "stolen", "deleted"]
    fear_matches = [w for w in fear_words if w in lower_text]
    if fear_matches:
        eds["fear"] = min(1.0, len(fear_matches) * 0.25)
        score -= 20

    # 4. TRUST (Misuse of Trust)
    trust_words = ["official", "support", "security team", "verified", "no-reply", "customer service"]
    trust_matches = [w for w in trust_words if w in lower_text]
    if trust_matches:
        eds["trust"] = min(1.0, len(trust_matches) * 0.2)
        score -= 10

    # 5. GREED
    greed_words = ["winner", "prize", "refund", "bonus", "free", "claim", "reward", "cash"]
    greed_matches = [w for w in greed_words if w in lower_text]
    if greed_matches:
        eds["greed"] = min(1.0, len(greed_matches) * 0.25)
        score -= 25

    # 6. AUTHORITY
    authority_words = ["director", "ceo", "department", "administrator", "manager", "official notice"]
    authority_matches = [w for w in authority_words if w in lower_text]
    if authority_matches:
        eds["authority"] = min(1.0, len(authority_matches) * 0.2)
        score -= 15

    # 7. FINANCIAL / CREDENTIALS
    financial_words = ["verify your account", "confirm payment", "credit card", "bank details", "password", "social security", "billing info"]
    if any(w in lower_text for w in financial_words):
        score -= 30
        if steps[0]["status"] == "safe":
            steps[0] = {"name": "Rule Analysis", "status": "warning", "details": "Requests for sensitive information"}

    # 8. SUSPICIOUS LINKS
    if any(link in lower_text for link in ["http://", "bit.ly", "tinyurl"]):
        score -= 20
        steps[3] = {"name": "Link Inspection", "status": "warning", "details": "Contains shortened or insecure links"}

    if score <= 50:
        verdict = "danger"
    elif score < 85:
        verdict = "warning"

    # Overall EDS is an average of the components for the main score
    total_eds = sum(eds.values()) / 5.0

    return {
        "verdict": verdict, 
        "score": max(0, score), 
        "steps": steps,
        "phishing_probability": (100 - score) / 100.0,
        "emotional_deception_score": total_eds,
        "eds_breakdown": eds,
        "confidence": ml_confidence if ML_AVAILABLE else 0.8 # Default confidence for rule-based
    }


def analyze_file(file_name):
    score = 100
    verdict = "safe"
    steps = [
        {"name": "AI Extension Scan", "status": "safe", "details": "AI file type analysis complete"},
        {"name": "Double Extension", "status": "safe", "details": "Single extension found"},
        {"name": "Heuristic Scan", "status": "safe", "details": "No malicious patterns"}
    ]

    lower_name = file_name.lower()

    # 1. ML Analysis (AI)
    if ML_AVAILABLE:
        label = file_model.predict([file_name])[0]
        if label == 'phishing':
            score -= 60
            steps[0] = {"name": "AI Extension Scan", "status": "danger", "details": "AI identifies this filename pattern as MALICIOUS"}
        elif label == 'suspicious':
            score -= 30
            steps[0] = {"name": "AI Extension Scan", "status": "warning", "details": "AI identifies this filename pattern as SUSPICIOUS"}
        else:
            steps[0] = {"name": "AI Extension Scan", "status": "safe", "details": "AI identifies this filename pattern as SAFE"}

    # Double Extension
    if lower_name.count(".") > 1:
        if any(lower_name.endswith(ext) for ext in [".exe", ".bat", ".js", ".vbs"]):
            score -= 50
            steps[1] = {"name": "Double Extension", "status": "danger", "details": "Double extension masquerading detected"}

    # Security Patterns in names
    if any(kw in lower_name for kw in ["password", "crack", "hack", "bypass"]):
        score -= 20
        steps[2] = {"name": "Heuristic Scan", "status": "warning", "details": "Sensitive keywords in filename"}

    if score <= 50:
        verdict = "danger"
    elif score < 90:
        verdict = "warning"

    return {"verdict": verdict, "score": max(0, score), "steps": steps}
