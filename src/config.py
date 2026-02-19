"""
Configuration Module
Loads and validates environment variables
"""
import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


class Config:
    """Application configuration from environment variables"""
    
    # API Keys - Read directly from environment
    API_KEY = os.getenv("API_KEY")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")

    # Model Configuration
    MODEL_NAME = os.getenv("MODEL_NAME") or os.environ.get("MODEL_NAME", "gemini-2.5-flash")

    # Callback URL
    FINAL_CALLBACK_URL = os.getenv("FINAL_CALLBACK_URL") or os.environ.get(
        "FINAL_CALLBACK_URL",
        "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    )

    # Production Settings
    MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "100"))
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "25"))
    CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))
    MAX_RETRIES = int(os.getenv("MAX_RETRIES", "2"))
    
    # Circuit Breaker Settings
    CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "5"))
    CIRCUIT_BREAKER_TIMEOUT = int(os.getenv("CIRCUIT_BREAKER_TIMEOUT", "60"))
    
    # Rate Limiter Settings
    RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "100"))
    RATE_LIMIT_TIME_WINDOW = int(os.getenv("RATE_LIMIT_TIME_WINDOW", "60"))
    
    # Session Settings
    SESSION_TTL = int(os.getenv("SESSION_TTL", "3600"))
    
    @classmethod
    def validate(cls):
        """Validate critical configuration"""
        errors = []
        
        if not cls.GEMINI_API_KEY:
            errors.append("GEMINI_API_KEY is required")
        
        if not cls.API_KEY:
            errors.append("API_KEY is required")
        
        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.info("✅ Configuration validated successfully")
        logger.info(f"📦 Using model: {cls.MODEL_NAME}")
        logger.info(f"🔗 Callback URL: {cls.FINAL_CALLBACK_URL}")
        
        return True


# Validate on import
Config.validate()
