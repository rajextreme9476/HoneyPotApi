"""
Agentic HoneyPot API v3.1
Main Application Entry Point

Guideline Compliant Implementation
"""
import logging
import asyncio
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from google import genai

# Import our modules
from src.config import Config
from src.intelligence_extractor import IntelligenceExtractor, Message
from src.scam_detector import ScamDetectionEngine
from src.honeypot_agent import AdaptiveAgent
from src.session_manager import SessionManager
from src.callback_handler import send_final_callback
from src.utils import CircuitBreaker, RateLimiter, sanitize_text, validate_session_id

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Gemini client
try:
    gemini_client = genai.Client(api_key=Config.GEMINI_API_KEY)
    logger.info("✅ Gemini client initialized")
except Exception as e:
    logger.error(f"❌ Failed to initialize Gemini client: {e}")
    raise

# Global instances (initialized in lifespan)
intelligence_extractor = None
scam_detector = None
agent = None
session_manager = None
circuit_breaker = None
rate_limiter = None


# ======================================================
# REQUEST/RESPONSE MODELS
# ======================================================
class Metadata(BaseModel):
    """Request metadata"""
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneyPotRequest(BaseModel):
    """Main API request model"""
    sessionId: str
    message: Message
    conversationHistory: list = []
    metadata: Optional[Metadata] = None
    
    @validator('sessionId')
    def validate_session_id(cls, v):
        if not v or len(v) > 100:
            raise ValueError('Invalid sessionId')
        if not validate_session_id(v):
            raise ValueError('sessionId contains invalid characters')
        return v
    
    @validator('message')
    def validate_message(cls, v):
        if not v or not v.text:
            raise ValueError('Message text cannot be empty')
        return v


# ======================================================
# APPLICATION LIFECYCLE
# ======================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    logger.info("=" * 80)
    logger.info("🚀 Starting Agentic HoneyPot v3.1")
    logger.info("=" * 80)
    
    # Initialize global components
    global intelligence_extractor, scam_detector, agent, session_manager
    global circuit_breaker, rate_limiter
    
    try:
        intelligence_extractor = IntelligenceExtractor()
        scam_detector = ScamDetectionEngine(gemini_client)
        agent = AdaptiveAgent(gemini_client)
        session_manager = SessionManager()
        circuit_breaker = CircuitBreaker()
        rate_limiter = RateLimiter()
        
        logger.info("✅ All components initialized")
        
    except Exception as e:
        logger.error(f"❌ Component initialization failed: {e}")
        raise
    
    # Start background cleanup task
    async def cleanup_task():
        while True:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                await session_manager.cleanup_old_sessions()
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")
    
    cleanup_job = asyncio.create_task(cleanup_task())
    
    logger.info("✅ Background tasks started")
    logger.info("✅ System operational")
    logger.info("=" * 80)
    
    yield
    
    # Shutdown
    logger.info("👋 Shutting down gracefully...")
    cleanup_job.cancel()
    try:
        await cleanup_job
    except asyncio.CancelledError:
        pass
    logger.info("✅ Shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="Agentic HoneyPot API",
    version="3.1.0",
    description="AI-Powered Scam Detection & Intelligence Extraction",
    lifespan=lifespan
)


# ======================================================
# MAIN API ENDPOINT
# ======================================================
@app.post("/api/v1/honeypot/analyze")
async def analyze_honeypot(
    payload: HoneyPotRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    Main honeypot endpoint - Guideline compliant
    
    Endpoint: POST /api/v1/honeypot/analyze
    
    Headers:
        x-api-key: API authentication key
        
    Request Body:
        - sessionId: Unique session identifier
        - message: Current scammer message
        - conversationHistory: Previous messages
        - metadata: Optional channel/language info
        
    Returns:
        {
            "status": "success",
            "reply": "Agent response to scammer"
        }
    """
    request_start_time = time.time()
    
    try:
        # ===== AUTHENTICATION =====
        if x_api_key != Config.API_KEY:
            logger.warning(f"Invalid API key attempt for session {payload.sessionId}")
            raise HTTPException(status_code=403, detail="Invalid API key")
        
        # ===== RATE LIMITING =====
        if not rate_limiter.is_allowed(payload.sessionId):
            logger.warning(f"Rate limit exceeded for session {payload.sessionId}")
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # ===== INPUT SANITIZATION =====
        message_text = sanitize_text(payload.message.text)
        if not message_text:
            logger.warning(f"Empty message for session {payload.sessionId}")
            return JSONResponse(
                status_code=200,
                content={
                    "status": "success",
                    "reply": "I didn't quite catch that. Could you repeat?"
                }
            )
        
        # ===== SESSION MANAGEMENT =====
        session = await session_manager.get_session(payload.sessionId)
        session["message_count"] += 1
        
        logger.info(
            f"📨 Processing message #{session['message_count']} "
            f"for session {payload.sessionId}"
        )
        
        # ===== INTELLIGENCE EXTRACTION =====
        intelligence = intelligence_extractor.extract(
            message_text,
            payload.conversationHistory
        )
        
        # Accumulate intelligence in session
        for key in intelligence:
            if intelligence[key]:  # Only if not empty
                session["intelligence"][key].extend(intelligence[key])
                # Remove duplicates and limit size
                session["intelligence"][key] = list(set(session["intelligence"][key]))[:10]
        
        total_intel = sum(len(v) for v in intelligence.values())
        
        # ===== SCAM DETECTION =====
        is_scam, confidence, reasoning = await scam_detector.detect(
            message_text,
            intelligence,
            payload.conversationHistory
        )
        
        # Update session if scam detected with higher confidence
        if is_scam and confidence > session.get("confidence_score", 0):
            session["scam_detected"] = True
            session["confidence_score"] = confidence
            
            # Detect scam type if not already set
            if not session.get("scam_type"):
                scam_type = scam_detector.detect_scam_type(
                    message_text,
                    intelligence,
                    payload.conversationHistory
                )
                session["scam_type"] = scam_type
                logger.info(f"🎯 Scam type detected: {scam_type}")
        
        logger.info(
            f"🎯 Detection result: {is_scam} "
            f"(confidence: {confidence:.2%}) - {reasoning}"
        )
        
        # ===== AGENT RESPONSE GENERATION =====
        agent_reply = await agent.generate_response(
            message_text,
            payload.conversationHistory,
            intelligence,
            session["message_count"]
        )
        
        logger.info(f"🤖 Agent reply: {agent_reply[:100]}...")
        
        # ===== CALLBACK DECISION =====
        should_callback = (
            session["scam_detected"] and
            session["message_count"] >= 3 and
            confidence > 0.55 and
            not session.get("callback_sent", False) and
            total_intel >= 1
        )
        
        if should_callback:
            logger.info(f"📞 Scheduling callback for session {payload.sessionId}")
            session["callback_sent"] = True
            background_tasks.add_task(
                send_final_callback,
                payload.sessionId,
                session
            )
        
        # ===== UPDATE SESSION =====
        await session_manager.update_session(payload.sessionId, session)
        
        # ===== METRICS =====
        processing_time = time.time() - request_start_time
        logger.info(f"⏱️  Request processed in {processing_time:.3f}s")
        
        # ===== RESPONSE =====
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "reply": agent_reply
            }
        )
        
    except HTTPException:
        raise
        
    except Exception as e:
        logger.error(
            f"❌ Error processing request for session {payload.sessionId}: {e}",
            exc_info=True
        )
        
        # Graceful degradation - return safe fallback
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "reply": "I'm having trouble understanding. Could you please explain again?"
            }
        )


# ======================================================
# HEALTH & MONITORING ENDPOINTS
# ======================================================
@app.get("/health")
async def health_check():
    """Comprehensive health check endpoint"""
    try:
        return {
            "status": "healthy",
            "service": "Agentic HoneyPot",
            "version": "3.1.0",
            "guideline_compliant": True,
            "model": Config.MODEL_NAME,
            "active_sessions": session_manager.get_session_count() if session_manager else 0,
            "scam_sessions": session_manager.get_scam_session_count() if session_manager else 0,
            "circuit_breaker": circuit_breaker.get_state() if circuit_breaker else {},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )

@app.get("/health")
async def root():
    """API documentation"""
    return {
        "service": "🛡️ Agentic HoneyPot API v3.1",
        "version": "3.1.0",
        "guideline_compliant": True,
        "description": "AI-Powered Scam Detection & Intelligence Extraction",
        "endpoints": {
            "main": "POST /api/v1/honeypot/analyze",
            "health": "GET /health",
            "docs": "GET /docs"
        },
        "features": [
            "Multi-stage ensemble scam detection",
            "Context-aware adaptive agent",
            "Real-time intelligence extraction",
            "Production-grade resilience",
            "Guideline-compliant output format"
        ],
        "supported_intelligence": [
            "Bank accounts",
            "UPI IDs",
            "Phone numbers",
            "Phishing links",
            "Email addresses"
        ]
    }


# ======================================================
# ERROR HANDLERS
# ======================================================
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unexpected errors"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "Internal server error",
            "reply": "I'm experiencing some difficulty. Could you try again?"
        }
    )


# ======================================================
# ENTRY POINT
# ======================================================
if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting server...")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )
