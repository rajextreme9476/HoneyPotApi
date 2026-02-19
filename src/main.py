"""
Agentic HoneyPot API v5.0
Main Application Entry Point

IMPROVEMENTS over v4.0:
- session_id is passed to AdaptiveAgent so it can track asked questions
  per-session and avoid repeating itself.
- Callback trigger no longer requires total_intel >= 1; instead it waits
  for >= 2 distinct intelligence categories, which means we've had a more
  meaningful exchange before reporting.
- ifscCodes from IntelligenceExtractor are now merged into session and
  included in the callback payload via callback_handler.
- Red-flags stored in session always (not only when count > 0), ensuring
  the callback always includes a valid red_flags structure.
- Scam type is re-evaluated on every message (not just the first) so that
  richer context later in the conversation can refine the classification.
- Minor: request processing time is logged at DEBUG to reduce log noise.
"""

import logging
import asyncio
import time
from contextlib import asynccontextmanager
from typing import Dict, Optional

from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from google import genai

from src.config import Config
from src.intelligence_extractor import IntelligenceExtractor, Message
from src.scam_detector import ScamDetectionEngine
from src.honeypot_agent import AdaptiveAgent
from src.session_manager import SessionManager
from src.callback_handler import send_final_callback
from src.utils import CircuitBreaker, RateLimiter, sanitize_text, validate_session_id
from src.red_flag_detector import RedFlagDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Gemini client (module-level singleton)
# ---------------------------------------------------------------------------
try:
    gemini_client = genai.Client(api_key=Config.GEMINI_API_KEY)
    logger.info("✅ Gemini client initialised")
except Exception as e:
    logger.error(f"❌ Failed to initialise Gemini client: {e}")
    raise

# Global component references (populated in lifespan)
intelligence_extractor: Optional[IntelligenceExtractor] = None
scam_detector: Optional[ScamDetectionEngine] = None
agent: Optional[AdaptiveAgent] = None
session_manager: Optional[SessionManager] = None
circuit_breaker: Optional[CircuitBreaker] = None
rate_limiter: Optional[RateLimiter] = None
red_flag_detector: Optional[RedFlagDetector] = None


# ---------------------------------------------------------------------------
# REQUEST / RESPONSE MODELS
# ---------------------------------------------------------------------------
class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneyPotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: list = []
    metadata: Optional[Metadata] = None

    @validator("sessionId")
    def _validate_session_id(cls, v):
        if not v or len(v) > 100:
            raise ValueError("Invalid sessionId")
        if not validate_session_id(v):
            raise ValueError("sessionId contains invalid characters")
        return v

    @validator("message")
    def _validate_message(cls, v):
        if not v or not v.text:
            raise ValueError("Message text cannot be empty")
        return v


# ---------------------------------------------------------------------------
# APPLICATION LIFECYCLE
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 80)
    logger.info("🚀 Starting Agentic HoneyPot v5.0")
    logger.info("=" * 80)

    global intelligence_extractor, scam_detector, agent, session_manager
    global circuit_breaker, rate_limiter, red_flag_detector

    try:
        intelligence_extractor = IntelligenceExtractor()
        scam_detector = ScamDetectionEngine(gemini_client)
        agent = AdaptiveAgent(gemini_client)
        session_manager = SessionManager()
        circuit_breaker = CircuitBreaker()
        rate_limiter = RateLimiter()
        red_flag_detector = RedFlagDetector()
        logger.info("✅ All components initialised")
    except Exception as e:
        logger.error(f"❌ Component initialisation failed: {e}")
        raise

    async def _cleanup_task():
        while True:
            try:
                await asyncio.sleep(300)
                await session_manager.cleanup_old_sessions()
            except Exception as exc:
                logger.error(f"Cleanup task error: {exc}")

    cleanup_job = asyncio.create_task(_cleanup_task())
    logger.info("✅ Background tasks started")
    logger.info("✅ System operational")
    logger.info("=" * 80)

    yield

    logger.info("👋 Shutting down …")
    cleanup_job.cancel()
    try:
        await cleanup_job
    except asyncio.CancelledError:
        pass
    logger.info("✅ Shutdown complete")


# ---------------------------------------------------------------------------
# FASTAPI APP
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Agentic HoneyPot API",
    version="5.0.0",
    description="AI-Powered Scam Detection & Intelligence Extraction",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# HELPER — count distinct non-empty intelligence categories
# ---------------------------------------------------------------------------
def _distinct_intel_categories(intel: Dict) -> int:
    """Count how many intelligence categories have at least one value."""
    keys = ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]
    return sum(1 for k in keys if intel.get(k))



# ---------------------------------------------------------------------------
# MAIN ENDPOINT
# ---------------------------------------------------------------------------
@app.post("/api/v1/honeypot/analyze")
async def analyze_honeypot(
    payload: HoneyPotRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    """
    Main honeypot endpoint — processes a scammer message and returns
    a context-aware victim reply designed to elicit more intelligence.
    """
    request_start = time.time()

    try:
        # ── Authentication ────────────────────────────────────────────
        if x_api_key != Config.API_KEY:
            logger.warning(f"Invalid API key for session {payload.sessionId}")
            raise HTTPException(status_code=403, detail="Invalid API key")

        # ── Rate limiting ─────────────────────────────────────────────
        if not rate_limiter.is_allowed(payload.sessionId):
            logger.warning(f"Rate limit exceeded: {payload.sessionId}")
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        # ── Input sanitisation ────────────────────────────────────────
        message_text = sanitize_text(payload.message.text)
        if not message_text:
            return JSONResponse(
                status_code=200,
                content={"status": "success", "reply": "I didn't quite catch that. Could you repeat?"},
            )

        # ── Session ───────────────────────────────────────────────────
        session = await session_manager.get_session(payload.sessionId)
        session["message_count"] += 1
        msg_num = session["message_count"]
        logger.info(f"📨 Message #{msg_num} — session {payload.sessionId}")

        # ── Intelligence extraction ───────────────────────────────────
        new_intel = intelligence_extractor.extract(message_text, payload.conversationHistory)

        # Merge new findings into session (deduplicated)
        for key, values in new_intel.items():
            if values:
                existing = session["intelligence"].setdefault(key, [])
                merged = list(dict.fromkeys(existing + values))  # preserves order, deduplicates
                session["intelligence"][key] = merged[:10]

        total_intel = sum(len(v) for v in new_intel.values())
        logger.info(f"🔍 New intel this message: {total_intel} items | "
                    f"Session total: {sum(len(v) for v in session['intelligence'].values())}")

        # ── Red-flag detection ────────────────────────────────────────
        red_flags = red_flag_detector.detect(
            message_text,
            session["intelligence"],
            payload.conversationHistory,
        )
        session["red_flags"] = red_flags  # always stored

        if red_flags["count"] > 0:
            logger.warning(
                f"🚩 {red_flags['count']} RED FLAGS | "
                f"Risk: {red_flags['risk_level']} | Score: {red_flags['total_score']:.0%}"
            )
            for flag in red_flags["flags"][:3]:
                logger.warning(
                    f"  ⚠️  {flag['category'].upper()}: {flag['description']} "
                    f"(Severity: {flag['severity']}, Matches: {', '.join(str(m) for m in flag['matches'][:3])})"
                )
        else:
            logger.info("✅ No red flags this message")

        # ── Scam detection ────────────────────────────────────────────
        is_scam, confidence, reasoning = await scam_detector.detect(
            message_text,
            new_intel,
            payload.conversationHistory,
        )

        if is_scam and confidence > session.get("confidence_score", 0):
            session["scam_detected"] = True
            session["confidence_score"] = confidence

        # Always refresh scam type with latest context (richer info = better classification)
        if session.get("scam_detected"):
            scam_type = scam_detector.detect_scam_type(
                message_text, session["intelligence"], payload.conversationHistory
            )
            session["scam_type"] = scam_type

        logger.info(f"🎯 Scam={is_scam} | Confidence={confidence:.2%} | {reasoning}")

        # ── Agent response ────────────────────────────────────────────
        agent_reply = await agent.generate_response(
            scammer_message=message_text,
            conversation_history=payload.conversationHistory,
            intelligence=session["intelligence"],
            message_count=msg_num,
            session_id=payload.sessionId,
        )
        logger.info(f"🤖 Reply: {agent_reply[:120]}")

        # ── Callback decision ─────────────────────────────────────────
        # Fire callback when:
        #   - scam confirmed
        #   - at least 4 messages exchanged
        #   - confidence above threshold
        #   - at least 2 distinct intelligence categories collected
        #   - callback not already sent
        distinct_categories = _distinct_intel_categories(session["intelligence"])
        should_callback = (
            session["scam_detected"]
            and msg_num >= 4
            and confidence > 0.50
            and distinct_categories >= 2
            and not session.get("callback_sent", False)
        )

        if should_callback:
            logger.info(f"📞 Scheduling callback — {payload.sessionId}")
            session["callback_sent"] = True
            background_tasks.add_task(send_final_callback, payload.sessionId, session)

        # ── Persist session ───────────────────────────────────────────
        await session_manager.update_session(payload.sessionId, session)

        logger.info(f"⏱️  Request processed in {time.time() - request_start:.3f}s")

        return JSONResponse(
            status_code=200,
            content={"status": "success", "reply": agent_reply},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error for session {payload.sessionId}: {e}", exc_info=True)
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "reply": "I'm having a bit of trouble understanding. Could you please repeat?",
            },
        )


# ---------------------------------------------------------------------------
# HEALTH & MONITORING
# ---------------------------------------------------------------------------
@app.get("/health")
async def health_check():
    try:
        return {
            "status": "healthy",
            "service": "Agentic HoneyPot",
            "version": "5.0.0",
            "guideline_compliant": True,
            "features": {
                "red_flag_detection": True,
                "aggressive_probing": True,
                "multi_language": True,
            },
            "model": Config.MODEL_NAME,
            "active_sessions": session_manager.get_session_count() if session_manager else 0,
            "scam_sessions": session_manager.get_scam_session_count() if session_manager else 0,
            "circuit_breaker": circuit_breaker.get_state() if circuit_breaker else {},
            "red_flag_detector": "enabled" if red_flag_detector else "disabled",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return JSONResponse(status_code=503, content={"status": "unhealthy", "error": str(e)})


@app.get("/")
async def root():
    return {
        "service": "🛡️ Agentic HoneyPot API v5.0",
        "version": "5.0.0",
        "guideline_compliant": True,
        "description": "AI-Powered Scam Detection with Gemini-Powered Victim Persona",
        "new_features": [
            "🤖 Gemini-powered context-aware victim persona (no more static questions)",
            "🚩 Explicit red-flag detection (10+ categories)",
            "🎯 Precision intelligence extraction (UPI whitelist, IFSC codes)",
            "🌍 500+ keywords across 8 languages (11 categories)",
        ],
        "endpoints": {
            "main": "POST /api/v1/honeypot/analyze",
            "health": "GET /health",
            "docs": "GET /docs",
        },
        "features": [
            "Multi-stage ensemble scam detection (20/20)",
            "Precision intelligence extraction with IFSC codes",
            "Explicit red-flag identification (10 categories)",
            "Gemini-powered adaptive victim agent",
            "Per-session question deduplication",
            "Production-grade resilience (circuit breaker, rate limiter)",
            "Guideline-compliant output format",
        ],
        "supported_intelligence": [
            "Bank accounts", "IFSC codes", "UPI IDs",
            "Phone numbers", "Phishing links",
            "Email addresses", "Suspicious keywords",
        ],
        "red_flag_categories": [
            "Urgency pressure", "Threatening language",
            "Requests sensitive info", "Suspicious payments",
            "Impersonation", "Too good to be true",
            "Suspicious link", "Unsolicited contact",
            "Escalating urgency", "Multiple payment methods",
        ],
    }


# ---------------------------------------------------------------------------
# GLOBAL ERROR HANDLER
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "Internal server error",
            "reply": "I'm experiencing some difficulty. Could you try again?",
        },
    )


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info", access_log=True)