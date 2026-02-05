from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from google import genai
import requests
import re
import json
import logging

# ======================================================
# CONFIGURATION
# ======================================================
API_KEY = "123456789"
MODEL_NAME = "gemini-2.5-flash"
GEMINI_API_KEY = "AIzaSyDa9oLfEYr53eJ36_HfHE0lKm9kSa5TfSc"
FINAL_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Initialize Gemini client (using your working method)
client = genai.Client(api_key=GEMINI_API_KEY)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic HoneyPot – Multi-Lingual Scam Detection",
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
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneyPotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None


# ======================================================
# ENHANCED INTELLIGENCE EXTRACTION
# ======================================================
def extract_intelligence(text: str, conversation_history: List[Message] = None):
    """
    Extract intelligence from current message and entire conversation history
    """
    # Combine current text with conversation history for better extraction
    full_text = text
    if conversation_history:
        for msg in conversation_history:
            full_text += " " + msg.text

    full_text_lower = full_text.lower()

    # Enhanced bank account patterns (Indian formats)
    bank_accounts = []
    seen_accounts = set()

    # Standard formats: 1234567890, 1234-5678-9012, etc.
    bank_patterns = [
        r'\b\d{9,18}\b',  # 9-18 digit account numbers
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4,10}\b',  # Formatted account numbers
        r'account\s*(?:number|no|num)?[:\s]+(\d{9,18})',  # "account: 123456"
        r'ID[:\s]+(\d{10,18})',  # "ID: 1234567890" (scammer IDs)
        r'A/C[:\s]+(\d{9,18})',  # "A/C: 123456"
    ]

    for pattern in bank_patterns:
        matches = re.findall(pattern, full_text, re.IGNORECASE)
        for match in matches:
            # Clean up and validate
            clean_match = match.strip()
            # Must be at least 9 digits and not already seen
            if len(clean_match) >= 9 and clean_match.isdigit() and clean_match not in seen_accounts:
                # Avoid obvious false positives (all same digit, sequential)
                if not all(c == clean_match[0] for c in clean_match):
                    bank_accounts.append(clean_match)
                    seen_accounts.add(clean_match)

    # Enhanced UPI ID patterns with suspicious detection
    upi_patterns = [
        r'\b[\w.-]+@[\w.-]+\b',  # Standard UPI format (user@provider)
        r'\b\d{10}@[\w.-]+\b',  # Phone@provider
        r'[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+',  # Catch-all for any @provider
    ]
    upi_ids = []
    seen_upis = set()

    for pattern in upi_patterns:
        matches = re.findall(pattern, full_text)
        for match in matches:
            # Normalize and check if it looks like UPI/email
            if '@' in match and len(match) > 5:
                # Filter out common false positives
                match_lower = match.lower()
                # Keep if it's a known UPI provider OR has suspicious/scam indicators
                is_known_provider = any(
                    provider in match_lower
                    for provider in ['paytm', 'ybl', 'okhdfcbank', 'okicici', 'upi',
                                     'axl', 'ibl', 'fbl', 'pytm', 'gpay', 'phonepe']
                )
                is_suspicious = any(
                    word in match_lower
                    for word in ['scam', 'fraud', 'fake', 'phish', 'hack', 'bank',
                                 'pay', 'wallet', 'money', 'cash']
                )
                # Also keep numeric prefixes (likely phone@provider)
                is_numeric_prefix = match[0].isdigit()

                # Accept if any condition is met
                if (is_known_provider or is_suspicious or is_numeric_prefix) and match not in seen_upis:
                    upi_ids.append(match)
                    seen_upis.add(match)

    # Enhanced phishing links
    phishing_links = re.findall(r'https?://[^\s]+', full_text)
    # Also catch bit.ly, shortened URLs, suspicious domains
    phishing_links.extend(re.findall(r'\b(?:bit\.ly|tinyurl|goo\.gl)/[^\s]+', full_text))

    # Enhanced phone number patterns (Indian)
    phone_patterns = [
        r'\+91[-\s]?[6-9]\d{9}\b',  # +91-9876543210
        r'\b[6-9]\d{9}\b',  # 9876543210
        r'\b91[6-9]\d{9}\b',  # 919876543210
    ]
    phone_numbers = []
    for pattern in phone_patterns:
        phone_numbers.extend(re.findall(pattern, full_text))

    # Enhanced suspicious keywords (multi-lingual)
    suspicious_keywords_list = [
        # English
        'urgent', 'urgently', 'verify', 'blocked', 'suspended', 'immediately', 'expire',
        'confirm', 'update', 'secure', 'click here', 'link', 'otp', 'pin',
        'password', 'cvv', 'card', 'debit', 'credit', 'transfer', 'refund',
        'prize', 'won', 'lottery', 'claim', 'limited time', 'act now',
        'account number', 'assurance', 'helpline', 'operational', 'status',

        # Hindi/Hinglish
        'turant', 'abhi', 'jaldi', 'block', 'band', 'verify karo', 'confirm karo',
        'aapka', 'apka', 'account', 'khata', 'taal', 'lock',

        # Common across languages
        'KYC', 'PAN', 'Aadhaar', 'aadhar',
    ]

    suspicious_keywords = [
        keyword for keyword in suspicious_keywords_list
        if keyword.lower() in full_text_lower
    ]

    # Deduplicate and clean
    return {
        "bankAccounts": list(set([acc for acc in bank_accounts if len(acc) >= 9]))[:10],
        "upiIds": list(set(upi_ids))[:10],
        "phishingLinks": list(set(phishing_links))[:10],
        "phoneNumbers": list(set(phone_numbers))[:10],
        "suspiciousKeywords": list(set(suspicious_keywords))[:20]
    }


# ======================================================
# SESSION TRACKING (In-memory for demo, use Redis in production)
# ======================================================
session_data = {}


# ======================================================
# GEMINI PROMPTS (Using your working client method)
# ======================================================

def build_agent_prompt(conversation: str) -> str:
    """Build prompt for the agent persona"""
    return f"""
You are a normal, slightly worried Indian person who doesn't understand technology very well.
You are NOT aware this is a scam. You are confused and need help.

CRITICAL RULES:
- Respond ONLY in the SAME language as the incoming message
- If message is in Hinglish (mixed Hindi-English), respond in Hinglish
- If in Tamil/Telugu/Malayalam, respond in that language
- If in Hindi, respond in Hindi
- Keep responses SHORT (1-2 sentences maximum)
- Ask simple clarification questions
- Show concern and worry, not suspicion
- NEVER use words like: scam, fraud, police, RBI, fake, cheat, report
- NEVER warn or accuse
- Act like you believe the message and need guidance
- Use natural, conversational tone

Examples:
English: "I don't understand. What verification do you need?"
Hindi: "Mujhe samajh nahi aa raha. Kya karna hoga?"
Hinglish: "Yaar main confused hoon, kya verification chahiye?"
Tamil: "எனக்கு புரியவில்லை. என்ன சரிபார்ப்பு தேவை?"

Reply with ONE or TWO sentences only. Be natural and worried.

Conversation so far:
{conversation}

Your response (in the SAME language as the last message):"""


def build_scam_analysis_prompt(message_text: str) -> str:
    """Build prompt for scam detection"""
    return f"""
You are a multi-lingual scam detection AI.

Analyze the message for scam intent across ANY language including:
- English, Hindi, Tamil, Telugu, Malayalam
- Hinglish (Hindi-English mix like "aapka account block ho gaya")
- Code-mixed languages

SCAM INDICATORS:
✓ Urgency tactics (immediate action, account blocked, limited time)
✓ Requesting sensitive info (OTP, PIN, password, card details, UPI ID)
✓ Impersonation (bank, government, police, courier)
✓ Money requests or payment links
✓ Threats or fear tactics
✓ Prize/lottery/refund scams
✓ Verification requests with links
✓ Suspicious URLs or phone numbers

Respond with ONLY ONE WORD:
SCAM or NOT_SCAM

No explanation. No extra text.

Message to analyze:
{message_text}

Your response (SCAM or NOT_SCAM):"""


# ======================================================
# MAIN API ENDPOINT
# ======================================================
@app.post("/api/v1/honeypot/analyze")
def analyze_honeypot(
        payload: HoneyPotRequest,
        x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    Main honeypot endpoint that handles incoming scam messages
    """
    # ---------- AUTH ----------
    if x_api_key != API_KEY:
        logger.warning(f"Invalid API key attempted: {x_api_key[:10] if x_api_key else 'None'}...")
        raise HTTPException(status_code=403, detail="Forbidden")

    logger.info(f"Processing session: {payload.sessionId}")

    # ---------- INITIALIZE SESSION TRACKING ----------
    if payload.sessionId not in session_data:
        session_data[payload.sessionId] = {
            "scam_detected": False,
            "message_count": 0,
            "intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            }
        }

    session = session_data[payload.sessionId]
    session["message_count"] += 1

    # ---------- BUILD CONVERSATION CONTEXT ----------
    conversation = ""
    for msg in payload.conversationHistory:
        role = "Scammer" if msg.sender == "scammer" else "You"
        conversation += f"{role}: {msg.text}\n"

    # Add current message
    conversation += f"Scammer: {payload.message.text}\n"

    # ---------- SCAM DETECTION (Using your working Gemini client) ----------
    scam_detected = False
    try:
        logger.info("Running scam analysis...")

        # Using your working client.models.generate_content method
        analysis_response = client.models.generate_content(
            model=MODEL_NAME,
            contents=build_scam_analysis_prompt(payload.message.text)
        )

        verdict = analysis_response.text.strip().upper()
        # Remove markdown if present
        verdict = re.sub(r'^```(?:text)?\n?', '', verdict)
        verdict = re.sub(r'\n?```$', '', verdict)

        scam_detected = "SCAM" in verdict
        logger.info(f"Scam analysis result: {verdict} -> {scam_detected}")

        if scam_detected and not session["scam_detected"]:
            session["scam_detected"] = True
            logger.info(f"Session {payload.sessionId} marked as SCAM")

    except Exception as e:
        logger.error(f"Scam analysis failed: {str(e)}")
        # Conservative approach: assume scam if analysis fails
        scam_detected = True

    # ---------- GENERATE AGENTIC REPLY (Using your working Gemini client) ----------
    try:
        logger.info("Generating agent response...")

        # Using your working client.models.generate_content method
        agent_response = client.models.generate_content(
            model=MODEL_NAME,
            contents=build_agent_prompt(conversation)
        )

        agent_reply = agent_response.text.strip()

        # Remove markdown if present
        if agent_reply.startswith("```"):
            agent_reply = re.sub(r'^```(?:text)?\n?', '', agent_reply)
            agent_reply = re.sub(r'\n?```$', '', agent_reply)

        # Safety check: ensure agent didn't break character
        forbidden_words = ['scam', 'fraud', 'police', 'rbi', 'fake', 'cheat', 'report']
        if any(word in agent_reply.lower() for word in forbidden_words):
            logger.warning("Agent broke character, using fallback")
            agent_reply = "I'm not sure I understand. Can you explain more?"

        logger.info(f"Agent reply: {agent_reply[:100]}...")

    except Exception as e:
        logger.error(f"Agent generation failed: {str(e)}")
        # Fallback responses in multiple languages
        fallback_responses = [
            "Can you please explain what verification is needed?",
            "Mujhe samajh nahi aa raha. Kya karna padega?",
            "I don't understand. What should I do?",
        ]
        agent_reply = fallback_responses[session["message_count"] % len(fallback_responses)]

    # ---------- EXTRACT INTELLIGENCE ----------
    logger.info("Extracting intelligence...")
    intelligence = extract_intelligence(payload.message.text, payload.conversationHistory)

    # Accumulate intelligence in session
    for key in intelligence:
        if isinstance(intelligence[key], list):
            session["intelligence"][key].extend(intelligence[key])
            # Deduplicate
            session["intelligence"][key] = list(set(session["intelligence"][key]))

    logger.info(f"Intelligence extracted: {sum(len(v) for v in intelligence.values())} items")

    # ---------- MANDATORY FINAL CALLBACK ----------
    # Only send after sufficient engagement and intelligence gathering
    should_send_callback = (
            session["scam_detected"] and
            session["message_count"] >= 3 and  # At least 3 messages exchanged
            any(len(session["intelligence"][k]) > 0 for k in session["intelligence"])  # Has some intelligence
    )

    if should_send_callback:
        # Check if we haven't already sent callback for this session
        if not session.get("callback_sent", False):
            logger.info(f"Sending final callback for session {payload.sessionId}")
            callback_payload = {
                "sessionId": payload.sessionId,
                "scamDetected": True,
                "totalMessagesExchanged": session["message_count"],
                "extractedIntelligence": session["intelligence"],
                "agentNotes": (
                    f"Multi-lingual scam engagement completed. "
                    f"Detected urgency tactics and {', '.join([k for k, v in session['intelligence'].items() if v])}. "
                    f"Language: {payload.metadata.language if payload.metadata else 'Unknown'}. "
                    f"Channel: {payload.metadata.channel if payload.metadata else 'Unknown'}."
                )
            }

            logger.info(
                "Sending callback payload:\n%s",
                json.dumps(callback_payload, indent=2, ensure_ascii=False)
            )

            try:
                response = requests.post(
                    FINAL_CALLBACK_URL,
                    json=callback_payload,
                    timeout=15  # Reasonable timeout for callback
                )
                logger.info(f"Callback sent successfully: {response.status_code}")
                session["callback_sent"] = True

            except Exception as e:
                logger.error(f"Callback failed: {str(e)}")
                # Never affect main flow, but log for debugging

    # ---------- RESPONSE (STRICT FORMAT) ----------
    return {
        "status": "success",
        "reply": agent_reply
    }


# ======================================================
# HEALTH CHECK ENDPOINT
# ======================================================
@app.get("/health")
def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "service": "Agentic HoneyPot",
        "version": "2.0",
        "model": MODEL_NAME,
        "active_sessions": len(session_data)
    }


# ======================================================
# STATUS ENDPOINT (Compatible with your existing code)
# ======================================================
@app.get("/status")
def status():
    """Status endpoint"""
    return {
        "service": "Agentic Honeypot",
        "status": "UP",
        "version": "2.0",
        "model": MODEL_NAME
    }


# ======================================================
# ROOT ENDPOINT
# ======================================================
@app.get("/")
def root():
    """Root endpoint"""
    return {
        "service": "Agentic HoneyPot - Multi-Lingual Scam Detection",
        "version": "2.0",
        "model": MODEL_NAME,
        "endpoints": {
            "analyze": "/api/v1/honeypot/analyze",
            "health": "/health",
            "status": "/status"
        }
    }