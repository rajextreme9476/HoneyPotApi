"""
Utilities Module
Circuit breaker, rate limiter, and other utilities
"""
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Callable, Any

from .config import Config

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """Circuit breaker pattern for API resilience"""
    
    def __init__(
        self, 
        failure_threshold: int = None,
        timeout: int = None
    ):
        self.failure_threshold = failure_threshold or Config.CIRCUIT_BREAKER_THRESHOLD
        self.timeout = timeout or Config.CIRCUIT_BREAKER_TIMEOUT
        self.failures = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection
        
        Args:
            func: Function to execute
            *args, **kwargs: Function arguments
            
        Returns:
            Function result
            
        Raises:
            Exception if circuit is OPEN
        """
        try:
            # Check circuit state
            if self.state == "OPEN":
                if self.last_failure_time:
                    elapsed = datetime.now() - self.last_failure_time
                    if elapsed > timedelta(seconds=self.timeout):
                        self.state = "HALF_OPEN"
                        logger.info("Circuit breaker entering HALF_OPEN state")
                    else:
                        raise Exception(
                            f"Circuit breaker is OPEN "
                            f"(retry in {self.timeout - elapsed.seconds}s)"
                        )
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Success - reset if in HALF_OPEN
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
                self.failures = 0
                logger.info("Circuit breaker CLOSED after successful call")
            
            return result
            
        except Exception as e:
            # Failure - increment counter
            self.failures += 1
            self.last_failure_time = datetime.now()
            
            # Open circuit if threshold reached
            if self.failures >= self.failure_threshold:
                self.state = "OPEN"
                logger.error(
                    f"Circuit breaker OPENED after {self.failures} failures"
                )
            
            raise e
    
    def get_state(self) -> dict:
        """Get current circuit breaker state"""
        return {
            "state": self.state,
            "failures": self.failures,
            "threshold": self.failure_threshold
        }


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(
        self,
        max_requests: int = None,
        time_window: int = None
    ):
        self.max_requests = max_requests or Config.RATE_LIMIT_MAX_REQUESTS
        self.time_window = time_window or Config.RATE_LIMIT_TIME_WINDOW
        self.requests = defaultdict(list)
    
    def is_allowed(self, key: str) -> bool:
        """
        Check if request is allowed under rate limit
        
        Args:
            key: Identifier for rate limiting (e.g., session_id, IP)
            
        Returns:
            True if request is allowed, False otherwise
        """
        try:
            if not key:
                return True  # Allow if no key provided
            
            now = time.time()
            
            # Clean old requests outside time window
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if now - req_time < self.time_window
            ]
            
            # Check if under limit
            if len(self.requests[key]) < self.max_requests:
                self.requests[key].append(now)
                return True
            
            logger.warning(
                f"Rate limit exceeded for {key}: "
                f"{len(self.requests[key])}/{self.max_requests} "
                f"in {self.time_window}s"
            )
            return False
            
        except Exception as e:
            logger.error(f"Rate limiter error: {e}")
            return True  # Allow on error to avoid blocking
    
    def get_remaining(self, key: str) -> int:
        """Get remaining requests for key"""
        try:
            if not key or key not in self.requests:
                return self.max_requests
            
            now = time.time()
            recent = [
                req for req in self.requests[key]
                if now - req < self.time_window
            ]
            return max(0, self.max_requests - len(recent))
            
        except Exception:
            return self.max_requests
    
    def reset(self, key: str):
        """Reset rate limit for specific key"""
        try:
            if key in self.requests:
                del self.requests[key]
        except Exception as e:
            logger.error(f"Error resetting rate limit: {e}")


def sanitize_text(text: str, max_length: int = 10000) -> str:
    """
    Sanitize text input
    
    Args:
        text: Input text
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    try:
        if not text:
            return ""
        
        # Convert to string
        text = str(text)
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length]
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        return text.strip()
        
    except Exception as e:
        logger.error(f"Text sanitization error: {e}")
        return ""


def validate_session_id(session_id: str) -> bool:
    """
    Validate session ID format
    
    Args:
        session_id: Session identifier
        
    Returns:
        True if valid, False otherwise
    """
    try:
        if not session_id:
            return False
        
        # Check length
        if len(session_id) > 100:
            return False
        
        # Check for valid characters (alphanumeric, hyphens, underscores)
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Session ID validation error: {e}")
        return False
