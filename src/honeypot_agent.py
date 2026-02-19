"""
Honeypot Agent - Context-Aware Intelligence Extraction
Version: 5.0 - Gemini-Powered Adaptive Probing

IMPROVEMENTS over v4.0:
- Uses Gemini to generate context-aware, natural responses instead of cycling
  through static question lists that scammers can easily detect.
- Probing strategy is chosen dynamically based on conversation stage and what
  intelligence is still missing, making the "victim" feel more realistic.
- Fallback static questions retained for resilience if Gemini call fails.
- Deduplication guard: never asks the same question twice in a session.
"""
import re
import logging
import asyncio
from typing import Dict, List, Optional

from google import genai
from .config import Config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# STATIC FALLBACK QUESTIONS  (used only when Gemini is unavailable)
# ---------------------------------------------------------------------------
_FALLBACK_QUESTIONS: Dict[str, List[str]] = {
    "missing_phone": [
        "What's your WhatsApp number so I can verify?",
        "Can you share your mobile number? I want to call and confirm.",
        "Which number should I save to call you back?",
        "What's your contact number?",
        "Please share your phone number so I can reach you.",
    ],
    "missing_bank": [
        "Which bank account should I transfer the money to?",
        "Can you share the full account number and IFSC code?",
        "Is it HDFC, SBI, or ICICI? And what's the account number?",
        "What's the account holder name and account number?",
        "Should I do NEFT or IMPS? Please share account details.",
    ],
    "missing_upi": [
        "What's your UPI ID? I'll send via PhonePe.",
        "Can you give your Paytm or GPay number?",
        "Which UPI handle should I use for the payment?",
        "What's your registered UPI number or ID?",
        "Should I send to your UPI? What's the address?",
    ],
    "missing_link": [
        "Where should I go to complete the verification?",
        "Can you send the link for the portal?",
        "What website do I need to visit?",
        "Please share the URL — I couldn't find it.",
        "Can you resend the verification link?",
    ],
    "missing_email": [
        "What email address should I send the documents to?",
        "Can you share your official email?",
        "Which email ID should I use to contact you?",
    ],
}

# Priority order for probing when multiple fields are missing
_PROBE_PRIORITY = [
    "missing_phone",
    "missing_bank",
    "missing_upi",
    "missing_link",
    "missing_email",
]

# System prompt for the Gemini-powered honeypot persona
_SYSTEM_PROMPT = """You are playing the role of a naive, slightly anxious Indian mobile/internet user 
who has received a message that appears to be from a bank, government authority, or prize scheme.
Your GOAL is to keep the scammer engaged while extracting as much information as possible — 
specifically: phone numbers, bank account details, UPI IDs, payment links, and email addresses.

RULES:
1. Always stay in character as a confused but cooperative victim.
2. Ask EXACTLY ONE specific question per reply — never multiple questions at once.
3. The question must target the most important missing piece of intelligence listed in the prompt.
4. Keep replies SHORT (1-3 sentences max). Sound natural and slightly nervous/eager.
5. NEVER reveal you are an AI, a honeypot, or a scam-detection system.
6. NEVER make up account details or personal information — always ask for theirs.
7. Use mild Indian English phrasing to sound authentic (e.g., "kindly", "please do the needful").
8. If the scammer has already provided some details, acknowledge them briefly before asking for more.
9. Vary your phrasing — do not repeat the same question verbatim across turns.
"""


class AdaptiveAgent:
    """
    Gemini-powered honeypot agent that generates context-aware responses
    to keep scammers engaged and extract maximum intelligence.
    """

    def __init__(self, gemini_client: genai.Client):
        self.client = gemini_client
        self._asked_questions: Dict[str, set] = {}  # session_id -> set of asked questions

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
    ) -> str:
        """
        Generate a context-aware honeypot response.

        Strategy:
          1. Identify what intelligence is still missing.
          2. Use Gemini to craft a natural, context-sensitive reply that probes
             for the highest-priority missing piece.
          3. Fall back to a static question if Gemini fails.
        """
        missing = self._get_missing_fields(intelligence)

        try:
            reply = await self._gemini_response(
                scammer_message,
                conversation_history,
                intelligence,
                missing,
                message_count,
                session_id,
            )
            if reply:
                self._track_question(session_id, reply)
                return reply
        except Exception as e:
            logger.warning(f"Gemini agent response failed, using fallback: {e}")

        # Fallback path
        fallback = self._static_fallback(missing, message_count, session_id)
        self._track_question(session_id, fallback)
        return fallback

    # ------------------------------------------------------------------
    # GEMINI-POWERED RESPONSE
    # ------------------------------------------------------------------
    async def _gemini_response(
        self,
        scammer_message: str,
        conversation_history: List,
        intelligence: Dict,
        missing: List[str],
        message_count: int,
        session_id: str,
    ) -> Optional[str]:
        """Ask Gemini to generate a natural, context-aware victim reply."""

        # Build conversation snippet for context
        history_snippet = self._build_history_snippet(conversation_history)

        # Describe what we already have vs what we need
        have_parts = self._summarise_have(intelligence)
        need_parts = self._summarise_need(missing)

        # Previously asked questions (to avoid repetition)
        asked = list(self._asked_questions.get(session_id, set()))[-5:]  # last 5

        prompt = f"""CONVERSATION HISTORY (last messages):
{history_snippet}

SCAMMER'S LATEST MESSAGE:
\"\"\"{scammer_message}\"\"\"

INTELLIGENCE ALREADY COLLECTED: {have_parts if have_parts else 'nothing yet'}
INTELLIGENCE STILL NEEDED (priority order): {need_parts}
QUESTIONS ALREADY ASKED (do NOT repeat these): {asked if asked else 'none yet'}
MESSAGE NUMBER IN SESSION: {message_count}

Generate a single SHORT reply (1-3 sentences) from the victim's perspective.
The reply MUST naturally lead the scammer to provide: {need_parts.split(',')[0].strip() if need_parts else 'more details'}.
Reply ONLY with the victim's message — no explanation, no quotes around it."""

        response = await asyncio.to_thread(
            self.client.models.generate_content,
            model=Config.MODEL_NAME,
            contents=[
                {"role": "user", "parts": [{"text": _SYSTEM_PROMPT}]},
                {"role": "model", "parts": [{"text": "Understood. I will act as instructed."}]},
                {"role": "user", "parts": [{"text": prompt}]},
            ],
        )

        if not response or not response.text:
            return None

        reply = response.text.strip()
        # Sanity check: must be reasonable length
        if len(reply) < 10 or len(reply) > 500:
            return None

        return reply

    # ------------------------------------------------------------------
    # STATIC FALLBACK
    # ------------------------------------------------------------------
    def _static_fallback(
        self, missing: List[str], message_count: int, session_id: str
    ) -> str:
        """Return a static fallback question, avoiding repetition."""
        asked = self._asked_questions.get(session_id, set())

        for field in _PROBE_PRIORITY:
            if field in missing:
                for q in _FALLBACK_QUESTIONS[field]:
                    if q not in asked:
                        return q
                # All questions for this field asked — pick first anyway
                return _FALLBACK_QUESTIONS[field][message_count % len(_FALLBACK_QUESTIONS[field])]

        # If nothing is missing, ask for confirmation
        return "Could you please confirm all the details once more? I want to make sure I have everything correct."

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------
    def _get_missing_fields(self, intelligence: Dict) -> List[str]:
        """Return list of missing intelligence field keys in priority order."""
        field_map = {
            "missing_phone": "phoneNumbers",
            "missing_bank": "bankAccounts",
            "missing_upi": "upiIds",
            "missing_link": "phishingLinks",
            "missing_email": "emailAddresses",
        }
        return [key for key, ikey in field_map.items() if not intelligence.get(ikey)]

    def _track_question(self, session_id: str, question: str):
        """Record asked question to avoid repetition."""
        if session_id not in self._asked_questions:
            self._asked_questions[session_id] = set()
        self._asked_questions[session_id].add(question)

    def _build_history_snippet(self, history: List, max_messages: int = 6) -> str:
        """Build a readable snippet of recent conversation history."""
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
        """Human-readable summary of collected intelligence."""
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
        """Human-readable list of what's still needed."""
        label_map = {
            "missing_phone": "phone number",
            "missing_bank": "bank account number + IFSC",
            "missing_upi": "UPI ID",
            "missing_link": "payment/phishing link",
            "missing_email": "email address",
        }
        return ", ".join(label_map[m] for m in missing if m in label_map) or "additional confirmation"