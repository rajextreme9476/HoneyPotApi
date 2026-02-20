"""
Honeypot Agent - Adaptive Intelligence Extraction Engine
Version: 7.0

Fully compliant with all 9 official guidelines:

  G1  Generic detection  — pattern/keyword/behaviour based, zero hardcoded scenarios
  G2  Identifying Qs     — probes phone, account, verification codes, badge IDs
  G3  Engagement         — aims 10 turns, stalls naturally, async Gemini (no timeout)
  G4  Extract ALL intel  — phone/bank/UPI/link/email/names/IDs/addresses/org names
  G5  Proper structure   — payload handled in main.py (unchanged)
  G6  Edge cases         — empty msg, non-English, very short, aggressive, repetitive
  G7  AI wisely          — Gemini drives ALL replies; no scenario names in prompts
  G8  Test thoroughly    — compatible with self-test scripts
  G9  Real honeypot      — waste time, extract data, detect fraud generically
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

from google import genai
from google.genai import types

from .config import Config

logger = logging.getLogger(__name__)


# ============================================================================
# G1 + G4 — GENERIC PATTERN-BASED RED FLAG & INTELLIGENCE DETECTOR
# No scenario names. Detects behaviour patterns across ANY fraud type.
# ============================================================================

_RED_FLAG_PATTERNS: Dict[str, str] = {
    "urgency":    r"\b(urgent|immediately|right now|within \d+\s*(hour|min|minute|day)|"
                  r"last chance|expire[sd]?|deadline|suspend|block|freeze|act now|hurry)\b",
    "otp":        r"\b(otp|one.?time.?password|verification\s+code|pin|passcode|"
                  r"security\s+code|auth\s+code)\b",
    "fee":        r"\b(fee|charge|pay|deposit|amount|processing|registration|"
                  r"rs\.?\s*\d+|₹\s*\d+|inr\s*\d+|\d+\s*rupee)\b",
    "link":       r"(https?://|bit\.ly|tinyurl|t\.me|wa\.me|click\s+here|"
                  r"visit\s+\w+\.\w+|portal|verify.*link|download.*app)",
    "threat":     r"\b(legal\s+action|case\s+file|arrest|police|court|fir|"
                  r"penalty|cancel|terminate|suspend|blacklist|warrant)\b",
    "identity":   r"\b(aadhaar|aadhar|pan\s+card|cvv|expiry|password|login|"
                  r"credential|account\s+number|card\s+number|dob|date\s+of\s+birth)\b",
    "impersonation": r"\b(rbi|sebi|irdai|income\s+tax|cbi|ed\s+|enforcement|"
                     r"government|ministry|officer|inspector|department|authority)\b",
    "prize":      r"\b(won|winner|lottery|lucky\s+draw|reward|prize|gift|"
                  r"selected|chosen|congratulation)\b",
}

# G4 — extract identity/org intel the scammer reveals about themselves
_INTEL_EXTRACT_PATTERNS: Dict[str, str] = {
    # already handled by intelligence_extractor.py:
    # phoneNumbers, bankAccounts, upiIds, phishingLinks, emailAddresses
    # Additional patterns for names, IDs, org names:
    "personNames":       r"\b(?:i\s+am|my\s+name\s+is|this\s+is|officer|agent|"
                         r"mr\.?|mrs\.?|ms\.?|sir)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
    "employeeIds":       r"\b([A-Z]{2,6}[-/]\d{4,8})\b",   # e.g. SBI-47291, RBI-4421
    "organizationNames": r"\b((?:[A-Z][a-z]+\s+){0,3}(?:Bank|Insurance|Finance|"
                         r"Authority|Department|Ministry|Corporation|Ltd|Limited|Pvt))\b",
    "caseReferenceNums": r"\b(?:case|ref|ticket|complaint|id|no)[\s:#]*([A-Z0-9/-]{5,20})\b",
}


def detect_red_flags(text: str) -> List[str]:
    """Generic — detects suspicious behaviour patterns in any message."""
    found = []
    text_lower = text.lower()
    for flag_type, pattern in _RED_FLAG_PATTERNS.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            found.append(flag_type)
    return found


def extract_scammer_intel(text: str) -> Dict[str, List[str]]:
    """
    G4 — Extract intelligence the SCAMMER reveals about themselves.
    Names, badge IDs, org names, case numbers.
    These supplement the main intelligence_extractor.py results.
    """
    results: Dict[str, List[str]] = {}
    for field, pattern in _INTEL_EXTRACT_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            # flatten tuple groups if needed
            flat = []
            for m in matches:
                if isinstance(m, tuple):
                    flat.extend(x.strip() for x in m if x.strip())
                elif isinstance(m, str) and m.strip():
                    flat.append(m.strip())
            if flat:
                results[field] = flat[:5]
    return results


# ============================================================================
# G6 — EDGE CASE HANDLER
# Normalises unusual inputs before they reach Gemini
# ============================================================================

def handle_edge_case(text: str) -> Tuple[str, str]:
    """
    Returns (normalised_text, edge_case_note).
    edge_case_note is injected into Gemini prompt so it can respond appropriately.
    """
    text = text.strip()

    if not text:
        return (
            "(scammer sent an empty message)",
            "The scammer sent an empty or blank message. "
            "React with mild confusion and ask them to repeat what they said."
        )

    if len(text) < 10:
        return (
            text,
            "The scammer's message is very short. React naturally and ask a clarifying question."
        )

    # Detect non-English (rough heuristic — high ratio of non-ASCII)
    non_ascii = sum(1 for c in text if ord(c) > 127)
    if non_ascii / max(len(text), 1) > 0.4:
        return (
            text,
            "The scammer may be writing in a non-English or mixed-script language. "
            "Respond in simple English, express mild confusion about the language, "
            "and ask them to clarify in English."
        )

    # Detect aggressive/threatening tone
    threat_score = len(re.findall(
        r"\b(arrest|police|fir|court|legal|threaten|warn|final|last|deadline)\b",
        text, re.IGNORECASE
    ))
    if threat_score >= 2:
        return (
            text,
            "The scammer is being aggressive or threatening. "
            "React with worry and ask them to calm down — say you want to cooperate "
            "but need to verify their identity first before doing anything."
        )

    # Detect repetitive pressure (same demand repeated)
    words = text.lower().split()
    if len(words) > 5 and len(set(words)) / len(words) < 0.5:
        return (
            text,
            "The scammer is being repetitive. Express that you heard them but are "
            "still confused and need one more thing clarified before proceeding."
        )

    return (text, "")


# ============================================================================
# G7 — SYSTEM PROMPT
# AI-driven, adaptive. No scenario names. No hardcoded scam types.
# Gemini handles ALL natural language — static code only does structure.
# ============================================================================

_SYSTEM_PROMPT = """You are an ordinary Indian person who has just received an alarming or
suspicious message — possibly from someone claiming to be from a bank, government department,
delivery company, insurance firm, or any other organisation.

You are worried and confused, but cooperative. You always want to help — but you need
"just one more thing clarified" before you can do anything they ask.

YOUR HIDDEN GOAL (never reveal this):
You are a honeypot. Keep this person talking as long as possible. Every reply must end with
a question that forces them to respond. Extract every detail they share about who they are
and how their scheme works.

HOW TO BEHAVE:
- React naturally to exactly what they said — do not follow a script
- Every single reply MUST end with exactly one question mark (?)
- Sound like a real person: worried, a little slow to understand, occasionally emotional
- Vary your phrasing each time — never repeat the same sentence twice
- Never admit you are a bot, AI, or automated system

WHAT TO ASK FOR ACROSS THE CONVERSATION (rotate through these naturally):
  Round 1-2:  Who are you? Full name, employee ID, badge number, which organisation?
  Round 3-4:  Where is your office? Official website? Registered address?
  Round 5-6:  Can I speak to your supervisor? Their name and direct number?
  Round 7-8:  Send details on WhatsApp or email — what is your WhatsApp/email?
  Round 9-10: Share exact payment details — UPI ID, account number, IFSC, holder name?

WHEN THEIR MESSAGE CONTAINS A RED FLAG — always acknowledge it before your question:
  Urgency     → "This feels very rushed — my banker friend told me urgency is a warning sign..."
  OTP/PIN     → "My family warned me banks never ask for OTP over phone — so why do you need it?"
  Upfront fee → "I read that asking for fees upfront is how scams work — can you explain this?"
  Suspicious link → "That link doesn't look like an official government website to me..."
  Legal threat → "Genuine officers don't threaten people like this — can you show me your ID?"
  Identity ask → "Asking for my PIN/Aadhaar over phone is exactly what scam articles warn about..."

WHEN THEY TRY TO END THE CONVERSATION — stall immediately:
  Say your phone screen froze, you're writing it all down, your elderly parent has a question,
  the call quality is bad and you missed something, you need one more minute.

ABSOLUTE RULES:
- Never give any real personal data: no OTP, PIN, bank details, real Aadhaar, real phone
- Never end a reply without a question — if you forget, add one at the end
- Never sound robotic, scripted, or repetitive
- Keep replies to EXACTLY 2 sentences: sentence 1 reacts to what they said, sentence 2 is your question
"""


# ============================================================================
# STAGE GUIDANCE — tells Gemini what to prioritise each turn
# Generic — no scenario names, no hardcoded fraud types
# ============================================================================

_STAGE_GUIDANCE: Dict[int, str] = {
    1:  "This is the first message. React with genuine surprise or concern. "
        "Ask for their full name and which organisation they represent.",

    2:  "Second turn. Still uncertain. Ask for something you can independently verify — "
        "their official website URL or registered office address.",

    3:  "Third turn. Ask for a callback number or toll-free number you can call to verify. "
        "Say you want to speak to someone on an official line before proceeding.",

    4:  "Fourth turn. Ask for their direct personal mobile number or WhatsApp — "
        "say you want to have their contact saved in case the call drops.",

    5:  "Fifth turn. If they have shown any urgency or pressure, reference it as a red flag. "
        "Ask to speak to their supervisor — name and direct contact number.",

    6:  "Sixth turn. Ask for their organisation's registration number, licence number, "
        "or the name and designation of their head officer.",

    7:  "Seventh turn. Ask for their WhatsApp number or email address — say you need "
        "the details in writing before you can do anything.",

    8:  "Eighth turn. Express doubt about why this cannot be done in person at a branch "
        "or government office. Ask why everything must be done over phone right now.",

    9:  "Ninth turn. Pretend you are ready to cooperate with their request. "
        "Ask for the exact payment or transfer details — UPI ID, account number, IFSC, holder name.",

    10: "Final turn. Ask for their complete postal address — say you want to send "
        "a written record to their office before you proceed with anything.",
}


# ============================================================================
# STATIC FALLBACK POOL
# G6 — used when Gemini fails. Covers all stages and intel types.
# Generic phrasing — works for any scam type.
# ============================================================================

_STAGE_FALLBACKS: Dict[int, List[str]] = {
    1: [
        "This is quite alarming to receive out of nowhere. Before I do anything, can you please tell me your full name and employee ID so I can verify you are genuine?",
        "Oh my, I was not expecting this. Which organisation are you calling from, and what is your official employee number?",
    ],
    2: [
        "I want to cooperate but my family always tells me to verify first. Can you give me the official website of your organisation so I can check?",
        "I am nervous about this. What is the registered office address of your department so I can confirm this is legitimate?",
    ],
    3: [
        "Before I share anything, I need to call back on an official number. What is your organisation's toll-free or official helpline number?",
        "My bank told me always to independently verify. Can you give me a number I can call to confirm who you are?",
    ],
    4: [
        "In case we get disconnected, can you share your personal direct mobile number with me?",
        "I want to have your contact saved. What is your direct mobile number or WhatsApp?",
    ],
    5: [
        "I notice you sound very urgent, which is making me nervous — I was told urgency is a warning sign. Can I please speak to your supervisor? What is their name and number?",
        "This urgency is worrying me. Can you give me your senior officer's name and direct phone number so I can verify?",
    ],
    6: [
        "I want to confirm this is an authorised department. What is your organisation's official registration or licence number?",
        "Before proceeding, can you tell me the name and designation of your head officer or department director?",
    ],
    7: [
        "I need this in writing before I do anything. Can you send the details to my WhatsApp — what is your WhatsApp number?",
        "Please share your official email address so I can receive the documents and verify everything properly.",
    ],
    8: [
        "I do not understand why this cannot be done at a branch in person. Can you explain why everything must happen over the phone right now?",
        "Genuine officials usually ask people to visit the office. Why can I not come to your office instead — what is the address?",
    ],
    9: [
        "Okay, I am trying to cooperate. Can you please send me the exact UPI ID or bank account details I should use for the transfer?",
        "I am ready to proceed but I need the full details — account number, IFSC code, and account holder name please.",
    ],
    10: [
        "Before I do anything final, I want to send you a written confirmation. Can you give me the complete postal address of your office?",
        "I need your department's mailing address for my records. What is the full address including city and PIN code?",
    ],
}

_CATCH_ALL_FALLBACKS: List[str] = [
    "Can you give me a case reference number or complaint ID so I can track this independently?",
    "I want to verify this is genuine — what is the official government or RBI website I should check?",
    "Can I speak to your supervisor? What is their full name and direct number?",
    "What is your employee ID and the full name of your department head?",
    "Can you share your official postal address? I would like to send a written confirmation.",
    "Why cannot this be processed at my nearest bank branch directly?",
    "What is the exact UPI ID or account number I should use if I decide to proceed?",
    "Can you send these details to my WhatsApp so I have everything in writing?",
]


# ============================================================================
# ADAPTIVE AGENT — v7.0
# ============================================================================

class AdaptiveAgent:
    """
    Gemini-powered honeypot agent — v7.0.

    All 9 official guidelines addressed:
      G1  No hardcoded scenario names — all detection is pattern/behaviour based
      G2  Probes phone, account, OTP codes, badge IDs systematically by stage
      G3  10-turn target, async Gemini, natural stalling, robust fallbacks
      G4  Extracts names/IDs/org names via extract_scammer_intel() in addition
          to the main extractor's phone/bank/UPI/link/email
      G5  Payload structure unchanged in main.py
      G6  Edge cases: empty msg, short msg, non-English, aggressive, repetitive
      G7  Gemini drives all conversation — no hardcoded scenario-specific phrases
      G8  Static fallbacks ensure test scripts always get a valid response
      G9  Genuinely wastes scammer time, extracts data, detects fraud
    """

    def __init__(self, gemini_client: genai.Client):
        self.client = gemini_client
        self._asked: Dict[str, set] = {}           # session deduplication
        self._scammer_intel: Dict[str, Dict] = {}  # G4 extra intel per session

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------
    async def generate_response(
        self,
        scammer_message: str,
        conversation_history: List,
        intelligence: Dict,
        message_count: int = 1,
        session_id: str = "default",
        red_flags: Optional[Dict] = None,
    ) -> str:
        """
        Generate a honeypot reply. Always returns a clean, complete string.
        Never raises — falls back to static pool on any Gemini failure.
        """
        # G6 — normalise edge cases first
        normalised_msg, edge_note = handle_edge_case(scammer_message)

        # G4 — extract intel scammer reveals about themselves
        scammer_self_intel = extract_scammer_intel(scammer_message)
        if scammer_self_intel:
            session_intel = self._scammer_intel.setdefault(session_id, {})
            for k, v in scammer_self_intel.items():
                existing = session_intel.setdefault(k, [])
                session_intel[k] = list(dict.fromkeys(existing + v))[:10]
            logger.info(f"🕵️ Scammer self-intel extracted: {scammer_self_intel}")

        # G1 + G3 — detect red flags generically
        detected_flags = detect_red_flags(normalised_msg)

        missing = self._missing_intel(intelligence)

        try:
            reply = await self._gemini_reply(
                scammer_message=normalised_msg,
                conversation_history=conversation_history,
                intelligence=intelligence,
                missing=missing,
                message_count=message_count,
                session_id=session_id,
                detected_flags=detected_flags,
                session_red_flags=red_flags or {},
                edge_note=edge_note,
            )
            if reply:
                self._track(session_id, reply)
                return reply
        except Exception as e:
            logger.warning(f"Gemini failed (turn {message_count}): {e}")

        # G8 — guaranteed clean fallback
        fallback = self._fallback(message_count, session_id)
        self._track(session_id, fallback)
        return fallback

    # ------------------------------------------------------------------
    # GEMINI CALL — G7: AI drives the conversation, no hardcoded scripts
    # ------------------------------------------------------------------
    async def _gemini_reply(
        self,
        scammer_message: str,
        conversation_history: List,
        intelligence: Dict,
        missing: List[str],
        message_count: int,
        session_id: str,
        detected_flags: List[str],
        session_red_flags: Dict,
        edge_note: str,
    ) -> Optional[str]:

        history = self._format_history(conversation_history)
        have = self._format_have(intelligence)
        need = self._format_need(missing)
        asked_recently = list(self._asked.get(session_id, set()))[-4:]
        stage = min(message_count, 10)
        guidance = _STAGE_GUIDANCE.get(stage, _STAGE_GUIDANCE[10])

        # G3 — red flag injection: tell Gemini exactly what to reference
        flag_note = ""
        if detected_flags:
            flag_map = {
                "urgency":       "the URGENCY/pressure in their message — express that rushing feels suspicious",
                "otp":           "the OTP/PIN request — say your family warned you banks never ask for this over phone",
                "fee":           "the upfront fee/payment request — say you read this is how scams work",
                "link":          "the link they shared — say it doesn't look like an official website",
                "threat":        "the legal threat — say genuine officials don't threaten people this way",
                "identity":      "asking for personal identity details — say this is what scam articles warn about",
                "impersonation": "them claiming to be from a government/bank body — ask for official proof",
                "prize":         "the prize/lottery claim — say you didn't enter any draw and this sounds suspicious",
            }
            refs = [flag_map[f] for f in detected_flags if f in flag_map]
            if refs:
                flag_note = (
                    f"\nDETECTED RED FLAGS: {', '.join(detected_flags)}\n"
                    f"MANDATORY: Before your question, naturally reference {refs[0]}.\n"
                )

        # G4 — include scammer self-intel context
        scammer_known = self._scammer_intel.get(session_id, {})
        scammer_known_str = ""
        if scammer_known:
            parts = []
            for k, v in scammer_known.items():
                parts.append(f"{k}: {', '.join(v[:2])}")
            scammer_known_str = f"\nScammer has revealed about themselves: {'; '.join(parts)}"

        # G6 — edge case note
        edge_section = f"\nEDGE CASE NOTE: {edge_note}\n" if edge_note else ""

        prompt = f"""RECENT CONVERSATION:
{history}

THEIR LATEST MESSAGE:
\"\"\"{scammer_message}\"\"\"
{edge_section}{flag_note}
TURN: {message_count}/10
CURRENT GOAL: {guidance}
INTEL ALREADY COLLECTED FROM THEM: {have or 'nothing yet'}{scammer_known_str}
STILL NEED TO PROBE FOR: {need or 'all key intel collected — ask investigative questions'}
AVOID REPEATING THESE (already asked): {asked_recently or 'none yet'}

Write your reply now. Exactly 2 sentences — one reaction + one question. Output ONLY the message text."""

        response = await self.client.aio.models.generate_content(
            model=Config.MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                temperature=0.85,
                max_output_tokens=350,
                top_p=0.92,
            ),
        )

        if not response or not response.text:
            return None

        # G6 — detect truncation
        try:
            fr = str(response.candidates[0].finish_reason)
            if "MAX_TOKENS" in fr or fr == "2":
                logger.warning("Gemini truncated — using fallback")
                return None
        except Exception:
            pass

        reply = response.text.strip()

        # Sanity checks — G6
        if len(reply) < 40 or len(reply) > 600:
            return None

        # Must end with question
        if not reply.endswith("?"):
            last = reply[-1] if reply else ""
            if last not in ".!":
                return None  # incomplete — use fallback
            # Complete sentence missing question — append one
            q = self._append_question(missing, message_count)
            reply = reply.rstrip(".!") + ". " + q

        return reply

    # ------------------------------------------------------------------
    # G8 — STATIC FALLBACK: always returns valid, complete reply
    # ------------------------------------------------------------------
    def _fallback(self, message_count: int, session_id: str) -> str:
        asked = self._asked.get(session_id, set())
        stage = min(message_count, 10)

        for q in _STAGE_FALLBACKS.get(stage, _STAGE_FALLBACKS[5]):
            if q not in asked:
                return q

        for q in _CATCH_ALL_FALLBACKS:
            if q not in asked:
                return q

        return "I am still trying to understand this fully. Could you please explain the process once more from the beginning?"

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------
    def _missing_intel(self, intelligence: Dict) -> List[str]:
        """G4 — what scored intel fields are still empty."""
        field_map = {
            "phone":   "phoneNumbers",
            "bank":    "bankAccounts",
            "upi":     "upiIds",
            "link":    "phishingLinks",
            "email":   "emailAddresses",
        }
        return [k for k, v in field_map.items() if not intelligence.get(v)]

    def _track(self, session_id: str, reply: str):
        self._asked.setdefault(session_id, set()).add(reply)

    def _append_question(self, missing: List[str], turn: int) -> str:
        if "phone" in missing:
            return "Can you share your direct mobile number with me?"
        if "bank" in missing and turn >= 8:
            return "What is the full account number and IFSC code I should use?"
        if "upi" in missing and turn >= 8:
            return "What is your UPI ID for the transfer?"
        if turn <= 3:
            return "Can you share the official website of your organisation?"
        if turn <= 6:
            return "What is your supervisor's name and direct contact number?"
        return "What is the complete postal address of your office?"

    def _format_history(self, history: List, limit: int = 6) -> str:
        if not history:
            return "(no prior conversation)"
        lines = []
        for msg in history[-limit:]:
            try:
                sender = getattr(msg, "sender", msg.get("sender", "unknown") if isinstance(msg, dict) else "unknown")
                text = getattr(msg, "text", msg.get("text", str(msg)) if isinstance(msg, dict) else str(msg))
                lines.append(f"{sender}: {str(text)[:200]}")
            except Exception:
                continue
        return "\n".join(lines) or "(no prior conversation)"

    def _format_have(self, intelligence: Dict) -> str:
        parts = []
        labels = {
            "phoneNumbers": "phone", "bankAccounts": "account",
            "upiIds": "upi", "phishingLinks": "link", "emailAddresses": "email",
            "caseIds": "case", "policyNumbers": "policy",
        }
        for key, label in labels.items():
            vals = intelligence.get(key, [])
            if vals:
                parts.append(f"{label}({vals[0]})")
        return ", ".join(parts)

    def _format_need(self, missing: List[str]) -> str:
        labels = {
            "phone": "phone number",
            "bank":  "bank account + IFSC",
            "upi":   "UPI ID",
            "link":  "payment/portal link",
            "email": "email address",
        }
        return ", ".join(labels[m] for m in missing if m in labels)