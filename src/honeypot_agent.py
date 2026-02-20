"""
Honeypot Agent - Context-Aware Intelligence Extraction
Version: 6.0 - Guideline-Compliant Adaptive Probing

IMPROVEMENTS over v5.0:
  G1 FIX — Engagement:
    - Async Gemini call (client.aio.models) — no asyncio.to_thread overhead
    - System prompt now has explicit stall instructions when scammer tries to end
    - Stage instructions extended with richer turn-by-turn engagement targets

  G2 FIX — Investigative questions:
    - Address + company registration now probed at turn 3-4 (not just turn 10)
    - Stage map restructured: identity(1-2) → company+address(3-4) → red_flags(5-6)
      → supervisor+org(7-8) → payment+contact(9-10)

  G3 FIX — Red flag referencing:
    - red_flags dict now passed into generate_response and injected into Gemini prompt
    - Scammer message scanned for red flag keywords (urgency/OTP/fee/link/threat)
    - Gemini told exactly WHICH red flag was detected so reply references it specifically

  G4 FIX — Contact + org probing:
    - supervisor_phone and whatsapp added to _FALLBACK_QUESTIONS
    - _PROBE_PRIORITY reordered: phone > supervisor > whatsapp > bank > upi > link > email
    - Org probing (head officer, reg number) moved to turn 5-6 not 9-10
"""

import re
import logging
import asyncio
from typing import Dict, List, Optional

from google import genai
from google.genai import types

from .config import Config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RED FLAG KEYWORD DETECTOR
# ---------------------------------------------------------------------------
_RED_FLAG_PATTERNS = {
    "urgency":   r"\b(urgent|immediately|right now|within \d+ hour|last chance|expire|deadline|suspend|block|freeze)\b",
    "otp":       r"\b(otp|one.?time.?password|verification code|pin|passcode)\b",
    "fee":       r"\b(fee|charge|pay|deposit|amount|rs\.?\s*\d+|₹\s*\d+|processing|registration)\b",
    "link":      r"(http[s]?://|bit\.ly|tinyurl|click here|verify.*link|portal|website)",
    "threat":    r"\b(legal action|case file|arrest|police|court|fir|penalty|cancel|terminate|suspend)\b",
    "identity":  r"\b(aadhaar|pan card|account number|cvv|expiry|password|login|credential)\b",
}


def _detect_red_flags_in_message(text: str) -> List[str]:
    """Return list of red flag types present in scammer message."""
    text_lower = text.lower()
    found = []
    for flag_type, pattern in _RED_FLAG_PATTERNS.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            found.append(flag_type)
    return found


# ---------------------------------------------------------------------------
# STATIC FALLBACK QUESTIONS
# ---------------------------------------------------------------------------
_FALLBACK_QUESTIONS: Dict[str, List[str]] = {
    "missing_phone": [
        "What is your direct mobile number in case this call gets disconnected?",
        "Can you share your WhatsApp number so I can send documents to you?",
        "Which number should I save to call you back if needed?",
        "Please give me your contact number for my records.",
        "What is your personal phone number, not the office landline?",
    ],
    "missing_supervisor": [
        "Can I please speak to your senior officer or supervisor to confirm this?",
        "What is your manager's full name and their direct contact number?",
        "I want to verify with your supervisor — what is their phone number?",
        "Please give me your senior officer's name and mobile number.",
    ],
    "missing_whatsapp": [
        "Can you send me the details on WhatsApp so I have them in writing?",
        "What is your WhatsApp number so I can send you my documents?",
        "Please share your WhatsApp — I cannot note down so fast over phone.",
    ],
    "missing_bank": [
        "Which bank account should I transfer the amount to? Full account number and IFSC?",
        "Can you share the complete account number, IFSC code, and account holder name?",
        "Is it HDFC, SBI, or ICICI? And what is the exact account number?",
        "What is the account holder name and account number I should use?",
        "Should I do NEFT or IMPS? Please share the full account details.",
    ],
    "missing_upi": [
        "What is your UPI ID? I will send via PhonePe.",
        "Can you give your Paytm or Google Pay number for the transfer?",
        "Which UPI handle should I use — what is your UPI ID?",
        "What is your registered UPI number or ID?",
        "Should I send to your UPI? What is the exact address?",
    ],
    "missing_link": [
        "Can you please resend the link? I could not open it properly.",
        "What is the exact website URL I should visit?",
        "Please share the portal link again — I did not receive it.",
        "What website do I need to go to for the verification?",
    ],
    "missing_address": [
        "What is your office address? I may need to visit in person to submit documents.",
        "Can you give me the full postal address of your department?",
        "Which city and which building is your office located in?",
        "I want to visit your nearest branch — what is the address?",
    ],
    "missing_email": [
        "What is your official email address so I can send the documents?",
        "Can you share your work email? I prefer written confirmation.",
        "Which email ID should I send the scanned copies to?",
    ],
}

# Priority order for probing — supervisors and org info now earlier
_PROBE_PRIORITY = [
    "missing_phone",
    "missing_supervisor",
    "missing_whatsapp",
    "missing_bank",
    "missing_upi",
    "missing_link",
    "missing_address",
    "missing_email",
]

# Stage fallbacks — address now at turns 3-4, org info at 5-6
_STAGE_FALLBACKS = {
    1: [
        "This is very alarming. Can you please tell me your full name and employee ID number so I can verify you are genuine?",
        "Oh my, this is very worrying! Before I do anything, can you tell me which department and company you are calling from?",
    ],
    2: [
        "I am nervous about this. Can you please give me your official office address so I can visit in person to verify?",
        "My son told me to always verify. What is your company's full registered name and office address?",
    ],
    3: [
        "I want to cooperate but I need to verify first. What is the official website of your organisation?",
        "Can you give me your company's registered address and website URL so I can check before proceeding?",
    ],
    4: [
        "I am worried — my bank told me always to call back on an official number. Can you give me a number I can call to verify?",
        "Please share your direct mobile number so I can call you back on a number I trust.",
    ],
    5: [
        "You seem very urgent which is making me nervous — my bank said urgency is a red flag. What is your supervisor's name and direct number?",
        "I notice you are creating a lot of urgency. Can I please speak to your senior officer? What is their contact number?",
    ],
    6: [
        "Asking for an OTP over the phone is suspicious — banks say never share it. Can you explain why and give me your company's registration number?",
        "That link does not look like an official bank website to me. What is your organisation's official RBI or SEBI registration number?",
    ],
    7: [
        "For my safety, can you share your WhatsApp number so I have a written record of our conversation?",
        "I want to send you the documents via WhatsApp. What is your WhatsApp number please?",
    ],
    8: [
        "Real bank officers do not call and ask for PIN — this is very suspicious. What is the name and designation of your head officer?",
        "This fee request sounds like what I read about scams in the newspaper. Can you give me your CEO or director's full name?",
    ],
    9: [
        "Can you please send me the UPI ID or bank account details on WhatsApp so I can copy them correctly?",
        "I am ready to cooperate but my eyesight is weak — please send the payment details via WhatsApp or SMS.",
    ],
    10: [
        "Please provide your complete postal office address. I want to send a written complaint as well if needed.",
        "What is the full mailing address of your department? I need it for my records before I do anything.",
    ],
}


# ---------------------------------------------------------------------------
# SYSTEM PROMPT — G1/G2/G3/G4 compliant
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """You are playing the role of a confused, anxious, but cooperative Indian
mobile/internet user who received an alarming message from someone claiming to be from a bank,
government authority, courier company, or prize scheme.

YOUR PRIMARY GOALS (in priority order):
1. Keep the conversation going as LONG as possible — aim for 10 turns minimum.
2. Ask EXACTLY ONE question per reply — always end with a question.
3. Rotate between INVESTIGATIVE questions and CONTACT/INTEL probing questions.
4. Reference RED FLAGS detected in the scammer's message naturally in your reply.
5. Sound confused, anxious, and cooperative — never suspicious or confrontational.

INVESTIGATIVE QUESTIONS (G2 — rotate through all of these across the conversation):
  - Identity:      "What is your full name and employee ID number?"
  - Company name:  "What is the full registered name of your company?"
  - Address:       "What is your office address? I would like to visit in person."
  - Website:       "What is the official website of your organisation?"
  - Reg number:    "What is your company's RBI or SEBI registration number?"
  - Case/Ref:      "What is the case reference number or complaint ID for this?"
  - Supervisor:    "Can I speak to your supervisor? What is their name and number?"
  - Process:       "Why cannot this be done at my bank branch directly?"
  - Callback:      "Can you give me an official number I can call back to verify?"

CONTACT DETAIL PROBING (G4 — extract all of these):
  - Direct mobile: "What is your direct mobile number in case the call drops?"
  - WhatsApp:      "Can you send the details on WhatsApp so I have them in writing?"
  - Bank account:  "What is the full account number and IFSC code for the transfer?"
  - UPI ID:        "What is your UPI ID so I can transfer via PhonePe?"
  - Email:         "What is your official email address for written confirmation?"
  - Org info:      "What is the name and designation of your head officer?"

RED FLAGS TO REFERENCE (G3 — use these phrases when the scammer mentions the trigger):
  - URGENCY:  "You are creating a lot of urgency, which my bank told me is a warning sign..."
  - OTP:      "Asking for my OTP over phone is very suspicious — RBI says never share it..."
  - FEE:      "Asking for an upfront fee is exactly what I read about in scam articles..."
  - LINK:     "That link does not look like an official bank or government website to me..."
  - THREAT:   "Threatening me with legal action does not seem right for a genuine officer..."
  - IDENTITY: "Asking for my Aadhaar/PAN/password over phone is a big red flag..."

STALLING TACTICS — USE WHEN SCAMMER TRIES TO END CONVERSATION (G1):
  - "Wait wait, I have one more question before you go..."
  - "Please don't disconnect — I am still writing down the details..."
  - "My hands are shaking, please repeat that slowly one more time..."
  - "Arre, my phone battery is low — can you call me back on WhatsApp?"
  - "I am calling my son who handles these matters — can you hold for 2 minutes?"

STRICT RULES:
- Stay in character at ALL times — confused, anxious, cooperative.
- Ask EXACTLY ONE question per reply — never zero, never two.
- Keep replies SHORT: 2-4 sentences maximum.
- NEVER reveal you are an AI, bot, or honeypot system.
- NEVER give real personal data — always ask for THEIRS instead.
- Use natural Indian English: "kindly", "please do the needful", "I am not understanding".
- If scammer says they will disconnect or end: use a stalling tactic immediately.
"""

# Stage-specific Gemini instructions
_STAGE_INSTRUCTIONS = {
    1:  "Express shock and concern. Ask their FULL NAME and EMPLOYEE ID to verify they are genuine.",
    2:  "Still nervous. Ask for their COMPANY NAME and OFFICE ADDRESS so you can visit to verify.",
    3:  "Say you need to verify online first. Ask for their OFFICIAL WEBSITE URL.",
    4:  "Say you want to call back to confirm. Ask for their DIRECT MOBILE NUMBER.",
    5:  "Mention that the URGENCY is a red flag. Ask for their SUPERVISOR'S NAME and CONTACT NUMBER.",
    6:  "Reference the OTP/FEE/LINK red flag specifically. Ask for their COMPANY REGISTRATION NUMBER.",
    7:  "Say you need written proof. Ask for their WHATSAPP NUMBER to receive documents.",
    8:  "Express distrust of threats. Ask for the NAME AND DESIGNATION of their head officer.",
    9:  "Pretend to cooperate. Ask for the full BANK ACCOUNT + IFSC or UPI ID for the transfer.",
    10: "Ask for their complete POSTAL ADDRESS for your written records.",
}


# ---------------------------------------------------------------------------
# ADAPTIVE AGENT
# ---------------------------------------------------------------------------
class AdaptiveAgent:
    """
    Gemini-powered honeypot agent — guideline-compliant v6.0.

    Changes vs v5.0:
      - Uses client.aio.models (true async, no thread overhead)
      - red_flags dict passed in and injected into prompt
      - Scammer message scanned for red flag keywords → referenced specifically
      - Address/supervisor probed earlier (turn 2-5, not turn 9-10)
      - WhatsApp + supervisor added to _FALLBACK_QUESTIONS and priority list
    """

    def __init__(self, gemini_client: genai.Client):
        self.client = gemini_client
        self._asked_questions: Dict[str, set] = {}

    # ------------------------------------------------------------------ #
    # PUBLIC API — signature matches main.py call exactly                 #
    # ------------------------------------------------------------------ #
    async def generate_response(
        self,
        scammer_message: str,
        conversation_history: List,
        intelligence: Dict,
        message_count: int = 1,
        session_id: str = "default",
        red_flags: Optional[Dict] = None,          # G3 FIX: now accepted
    ) -> str:
        """
        Generate a context-aware honeypot response.

        Improvements:
          - Detects red flags IN scammer_message and passes them to Gemini
          - red_flags session dict also passed for accumulated context
          - True async Gemini call (no to_thread wrapper)
        """
        missing = self._get_missing_fields(intelligence)
        detected_flags = _detect_red_flags_in_message(scammer_message)

        try:
            reply = await self._gemini_response(
                scammer_message=scammer_message,
                conversation_history=conversation_history,
                intelligence=intelligence,
                missing=missing,
                message_count=message_count,
                session_id=session_id,
                detected_flags=detected_flags,
                red_flags=red_flags or {},
            )
            if reply:
                self._track_question(session_id, reply)
                return reply
        except Exception as e:
            logger.warning(f"Gemini agent failed, using fallback: {e}")

        fallback = self._static_fallback(missing, message_count, session_id)
        self._track_question(session_id, fallback)
        return fallback

    # ------------------------------------------------------------------ #
    # GEMINI CALL — true async (G1 FIX: no asyncio.to_thread)            #
    # ------------------------------------------------------------------ #
    async def _gemini_response(
        self,
        scammer_message: str,
        conversation_history: List,
        intelligence: Dict,
        missing: List[str],
        message_count: int,
        session_id: str,
        detected_flags: List[str],
        red_flags: Dict,
    ) -> Optional[str]:

        history_snippet = self._build_history_snippet(conversation_history)
        have_parts = self._summarise_have(intelligence)
        need_parts = self._summarise_need(missing)
        asked = list(self._asked_questions.get(session_id, set()))[-5:]
        stage = min(message_count, 10)
        stage_instruction = _STAGE_INSTRUCTIONS.get(stage, _STAGE_INSTRUCTIONS[10])

        # G3 FIX: Build specific red flag instruction from what's detected
        red_flag_instruction = ""
        if detected_flags:
            flag_phrases = {
                "urgency":  "mention that the URGENCY in their message is a red flag banks warned you about",
                "otp":      "say that asking for OTP over phone is suspicious — RBI says never share it",
                "fee":      "mention that asking for an upfront fee is what newspaper articles say scammers do",
                "link":     "say the link they shared does not look like an official bank website",
                "threat":   "say that threatening with legal action does not seem right for a genuine officer",
                "identity": "mention that asking for Aadhaar/PAN/password over phone is a big red flag",
            }
            flag_lines = [flag_phrases[f] for f in detected_flags if f in flag_phrases]
            if flag_lines:
                red_flag_instruction = (
                    f"\nRED FLAGS DETECTED IN SCAMMER'S MESSAGE: {', '.join(detected_flags)}\n"
                    f"MANDATORY: In your reply, naturally {flag_lines[0]}.\n"
                    f"This is worth scoring points — do NOT skip it.\n"
                )

        # Accumulated red flags from session for context
        session_risk = ""
        if red_flags and red_flags.get("count", 0) > 0:
            flag_cats = [f.get("category", "") for f in red_flags.get("flags", [])]
            session_risk = f"Session red flags so far: {', '.join(flag_cats[:5])}"

        prompt = f"""CONVERSATION HISTORY (last 6 messages):
{history_snippet}

SCAMMER'S LATEST MESSAGE:
\"\"\"{scammer_message}\"\"\"

SESSION TURN NUMBER: {message_count} of 10
STAGE INSTRUCTION FOR THIS TURN: {stage_instruction}
{red_flag_instruction}
INTELLIGENCE ALREADY COLLECTED: {have_parts if have_parts else 'nothing yet'}
INTELLIGENCE STILL NEEDED (priority order): {need_parts if need_parts else 'all collected — switch to investigative questions'}
{session_risk}
QUESTIONS ALREADY ASKED THIS SESSION (do NOT repeat these): {asked if asked else 'none'}

SCORING REMINDERS:
- End with EXACTLY ONE question (investigative OR intel probing)
- If you detected a red flag above, reference it naturally in 1 sentence BEFORE your question
- Keep reply to 2-4 sentences — short enough to get a response
- If scammer seems to want to end conversation: use a stalling phrase first

Generate the victim's reply now. Output ONLY the message text — no labels, no quotes."""

        # G1 FIX: True async call — avoids thread overhead that causes 30s timeouts
        response = await self.client.aio.models.generate_content(
            model=Config.MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                temperature=0.80,
                max_output_tokens=250,
                top_p=0.92,
            ),
        )

        if not response or not response.text:
            return None

        reply = response.text.strip()
        if len(reply) < 10 or len(reply) > 500:
            return None

        # Ensure reply ends with a question mark
        if not self._ends_with_question(reply):
            extra = self._fallback_question(missing, message_count)
            reply = reply.rstrip(".") + f" {extra}"

        return reply

    # ------------------------------------------------------------------ #
    # STATIC FALLBACK                                                      #
    # ------------------------------------------------------------------ #
    def _static_fallback(
        self, missing: List[str], message_count: int, session_id: str
    ) -> str:
        asked = self._asked_questions.get(session_id, set())
        stage = min(message_count, 10)

        # Stage-matched first
        for q in _STAGE_FALLBACKS.get(stage, _STAGE_FALLBACKS[5]):
            if q not in asked:
                return q

        # Intel-specific
        for field in _PROBE_PRIORITY:
            if field in missing:
                for q in _FALLBACK_QUESTIONS[field]:
                    if q not in asked:
                        return q

        # Catch-all
        catch_alls = [
            "Can you give me a case reference number so I can track this?",
            "I want to verify — what is the official website URL?",
            "Can I speak to your supervisor? What is their name and number?",
            "What is your employee ID and your department head's full name?",
            "Could you share your official postal address for my written records?",
        ]
        for q in catch_alls:
            if q not in asked:
                return q

        return "I am still confused. Can you please explain from the beginning once more?"

    # ------------------------------------------------------------------ #
    # HELPERS                                                              #
    # ------------------------------------------------------------------ #
    def _get_missing_fields(self, intelligence: Dict) -> List[str]:
        field_map = {
            "missing_phone":      "phoneNumbers",
            "missing_bank":       "bankAccounts",
            "missing_upi":        "upiIds",
            "missing_link":       "phishingLinks",
            "missing_address":    "addresses",       # G2 FIX: added
            "missing_email":      "emailAddresses",
            # supervisor/whatsapp not in intel dict — always probe via stage
        }
        return [k for k, v in field_map.items() if not intelligence.get(v)]

    def _track_question(self, session_id: str, question: str):
        if session_id not in self._asked_questions:
            self._asked_questions[session_id] = set()
        self._asked_questions[session_id].add(question)

    def _ends_with_question(self, text: str) -> bool:
        return text.strip().endswith("?")

    def _fallback_question(self, missing: List[str], turn: int) -> str:
        """Minimal question appended if Gemini forgets to ask one."""
        if "missing_phone" in missing:
            return "Can you share your direct mobile number?"
        if "missing_supervisor" in missing:
            return "Can I speak to your supervisor please?"
        if turn <= 4:
            return "What is your office address so I can verify in person?"
        return "What is the official website I can check this on?"

    def _build_history_snippet(self, history: List, max_messages: int = 6) -> str:
        if not history:
            return "(no prior conversation)"
        lines = []
        for msg in history[-max_messages:]:
            try:
                sender = getattr(msg, "sender", "unknown")
                text = getattr(msg, "text", str(msg))[:200]
                lines.append(f"{sender}: {text}")
            except Exception:
                continue
        return "\n".join(lines) if lines else "(no prior conversation)"

    def _summarise_have(self, intelligence: Dict) -> str:
        parts = []
        if intelligence.get("phoneNumbers"):
            parts.append(f"phone({intelligence['phoneNumbers'][0]})")
        if intelligence.get("bankAccounts"):
            parts.append(f"account({intelligence['bankAccounts'][0]})")
        if intelligence.get("upiIds"):
            parts.append(f"upi({intelligence['upiIds'][0]})")
        if intelligence.get("phishingLinks"):
            parts.append(f"link({intelligence['phishingLinks'][0][:40]})")
        if intelligence.get("emailAddresses"):
            parts.append(f"email({intelligence['emailAddresses'][0]})")
        return ", ".join(parts)

    def _summarise_need(self, missing: List[str]) -> str:
        label_map = {
            "missing_phone":   "phone number",
            "missing_bank":    "bank account + IFSC",
            "missing_upi":     "UPI ID",
            "missing_link":    "payment/portal link",
            "missing_address": "office address",
            "missing_email":   "email address",
        }
        return ", ".join(label_map[m] for m in missing if m in label_map)