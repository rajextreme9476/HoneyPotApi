from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List
import json
import re
from google import genai

#resr
# ======================================================
# CONFIG
# ======================================================
API_KEY = "expected-key"
GEMINI_API_KEY = "AIzaSyBAtsADQoe3y442Z3ShOYkVwIRqbBElLks"
MODEL_NAME = "gemini-2.5-flash"

client = genai.Client(api_key=GEMINI_API_KEY)

app = FastAPI(
    title="Agentic Honeypot – Scam Detection & Intelligence",
    version="2.0"
)

# ======================================================
# DATA MODELS
# ======================================================

class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

class Metadata(BaseModel):
    channel: str
    language: str
    locale: str

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Metadata

# ======================================================
# KEYWORD INTELLIGENCE
# ======================================================

SCAM_KEYWORDS = {
    "KYC": [
        "update kyc", "verify kyc", "kyc pending", "kyc expired"
    ],
    "ACCOUNT_THREAT": [
        "account blocked", "account suspended", "account limited",
        "account deactivated", "account restricted"
    ],
    "SECURITY_ALERT": [
        "security alert", "bank notice", "unusual activity",
        "suspicious activity", "account verification", "immediate verification"
    ],
    "OTP": [
        "otp", "one time password", "verification code",
        "authentication code", "security code", "otp required"
    ],
    "UPI": [
        "upi", "collect request", "refund", "wrong transfer",
        "payment failed", "amount debited", "credit not received",
        "npci", "auto reversal"
    ],
    "SIM": [
        "sim blocked", "sim suspended", "sim upgrade",
        "sim reactivation", "network suspended"
    ],
    "AUTHORITY": [
        "rbi", "reserve bank", "income tax", "cyber crime",
        "government notice", "legal notice", "bank support"
    ],
    "URGENCY": [
        "urgent", "final warning", "last warning",
        "within 24 hours", "within 12 hours",
        "last chance", "legal action"
    ],
    "LINKS": [
        "click here", "tap here", "open link",
        "verify now", "update now", "install app"
    ]
}

def detect_keywords(text: str) -> dict:
    text = text.lower()
    detected = {}
    total_hits = 0

    for category, keywords in SCAM_KEYWORDS.items():
        hits = [k for k in keywords if k in text]
        if hits:
            detected[category] = hits
            total_hits += len(hits)

    return {
        "matchedCategories": list(detected.keys()),
        "matchedKeywords": detected,
        "keywordHitCount": total_hits
    }

# ======================================================
# AUTO SCAM TYPE CLASSIFIER (DETERMINISTIC)
# ======================================================

def classify_scam_type(categories: List[str]) -> dict:
    if "OTP" in categories and "ACCOUNT_THREAT" in categories:
        return {
            "primaryType": "BANKING_OTP_FRAUD",
            "secondaryTypes": ["ACCOUNT_TAKEOVER", "SOCIAL_ENGINEERING"]
        }
    if "KYC" in categories:
        return {
            "primaryType": "KYC_SCAM",
            "secondaryTypes": ["IDENTITY_THEFT"]
        }
    if "SIM" in categories:
        return {
            "primaryType": "SIM_SWAP_FRAUD",
            "secondaryTypes": ["OTP_INTERCEPTION"]
        }
    if "UPI" in categories:
        return {
            "primaryType": "UPI_REFUND_SCAM",
            "secondaryTypes": ["PAYMENT_MANIPULATION"]
        }
    return {
        "primaryType": "GENERIC_SOCIAL_ENGINEERING",
        "secondaryTypes": []
    }

# ======================================================
# BEHAVIOR ANALYSIS (PYTHON)
# ======================================================

def compute_behavioral_metrics(payload: HoneypotRequest) -> dict:
    scammer_msgs = [
        m for m in payload.conversationHistory if m.sender == "scammer"
    ] + [payload.message]

    attempt_count = len(scammer_msgs)
    timestamps = [m.timestamp for m in scammer_msgs]

    time_window = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

    return {
        "urgencyDetected": True,
        "urgencyEscalationPattern": attempt_count >= 5,
        "persistenceLevel": "HIGH" if attempt_count >= 5 else "MEDIUM",
        "attemptCount": attempt_count,
        "responseTolerance": "HIGH",
        "timeWindowMillis": time_window
    }

# ======================================================
# ARTIFACT EXTRACTION
# ======================================================

def extract_artifacts(text: str) -> dict:
    ids = re.findall(r"\b\d{12,16}\b", text)
    upis = re.findall(r"\b[\w.-]+@[\w.-]+\b", text)
    phones = re.findall(r"\+91[-\s]?\d{10}", text)

    return {
        "fakeGovernmentOrBankIds": [
            {"value": i, "type": "FAKE_OFFICIAL_ID", "confidence": 0.97}
            for i in ids
        ],
        "upiHandles": [
            {"value": u, "confidence": 0.99}
            for u in upis
        ],
        "phoneNumbers": [
            {"value": p.replace("-", "").replace(" ", ""), "role": "SCAM_CONTACT", "confidence": 0.95}
            for p in phones
        ]
    }

# ======================================================
# GEMINI PROMPT (CONTROLLED)
# ======================================================

def build_llm_prompt(message: str, keyword_signals: dict) -> str:
    return f"""
You are a banking fraud risk assessor.

Detected keyword signals:
{json.dumps(keyword_signals)}

Return STRICT JSON ONLY with:
scamConfidenceScore
riskLevel
intentSignals
honeypotIntelligence

Message:
{message}
"""

# ======================================================
# CONFIDENCE CALIBRATION
# ======================================================

def calibrate_confidence(llm_score: float, keyword_hits: int) -> float:
    keyword_weight = min(keyword_hits / 10, 1.0)
    calibrated = (llm_score * 0.6) + (keyword_weight * 0.4)
    return round(min(calibrated, 1.0), 2)

# ======================================================
# MAIN ENDPOINT
# ======================================================

@app.post("/api/v1/honeypot/analyze")
def analyze_honeypot(payload: HoneypotRequest, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")

    keyword_signals = detect_keywords(payload.message.text)
    scam_types = classify_scam_type(keyword_signals["matchedCategories"])
    behavioral = compute_behavioral_metrics(payload)
    artifacts = extract_artifacts(payload.message.text)

    llm_response = client.models.generate_content(
        model=MODEL_NAME,
        contents=build_llm_prompt(payload.message.text, keyword_signals)
    )

    try:
        llm = json.loads(llm_response.text)
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid JSON from Gemini")

    final_confidence = calibrate_confidence(
        llm_score=llm["scamConfidenceScore"],
        keyword_hits=keyword_signals["keywordHitCount"]
    )

    return {
        "sessionId": payload.sessionId,
        "overallAssessment": {
            "isScam": True,
            "scamConfidenceScore": final_confidence,
            "riskLevel": llm["riskLevel"]
        },
        "scamClassification": {
            "primaryType": scam_types["primaryType"],
            "secondaryTypes": scam_types["secondaryTypes"],
            "impersonatedEntity": "SBI" if "ACCOUNT_THREAT" in keyword_signals["matchedCategories"] else None
        },
        "behavioralAnalysis": behavioral,
        "intentSignals": llm["intentSignals"],
        "extractedArtifacts": artifacts,
        "channelRiskAssessment": {
            "channel": payload.metadata.channel,
            "simBindingRisk": "HIGH" if "SIM" in keyword_signals["matchedCategories"] else "MEDIUM",
            "otpRelayRisk": "HIGH" if "OTP" in keyword_signals["matchedCategories"] else "MEDIUM"
        },
        "honeypotIntelligence": llm["honeypotIntelligence"],
        "learningSignalsForFutureDetection": {
            "matchedCategories": keyword_signals["matchedCategories"],
            "keywordHitCount": keyword_signals["keywordHitCount"],
            "regionalTargeting": "INDIA"
        }
    }

# ======================================================
# HEALTH
# ======================================================

@app.get("/status")
def status():
    return {
        "service": "Agentic Honeypot",
        "status": "UP",
        "version": "2.0"
    }
