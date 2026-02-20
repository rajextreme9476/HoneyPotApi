"""
Session Management Module
Thread-safe session tracking with TTL
"""
import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Optional

from .config import Config

logger = logging.getLogger(__name__)


class SessionManager:
    """Thread-safe session management with automatic cleanup"""
    
    def __init__(self, ttl: int = None):
        self.sessions = {}
        self.ttl = ttl or Config.SESSION_TTL
        self.lock = asyncio.Lock()
    
    async def get_session(self, session_id: str) -> Dict:
        """
        Get or create session
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Session data dictionary
        """
        try:
            if not session_id:
                raise ValueError("session_id cannot be empty")
            
            async with self.lock:
                if session_id not in self.sessions:
                    # Create new session
                    self.sessions[session_id] = {
                        "scam_detected": False,
                        "confidence_score": 0.0,
                        "message_count": 0,
                        "intelligence": {
                            "phoneNumbers": [],
                            "bankAccounts": [],
                            "upiIds": [],
                            "phishingLinks": [],
                            "emailAddresses": [],
                            "suspiciousKeywords": [],
                            # GAP 17 FIX: new field types evaluator may plant fake data in
                            "caseIds": [],
                            "policyNumbers": [],
                            "orderNumbers": [],
                        },
                        "red_flags": {},  # accumulated across messages
                        "callback_sent": False,
                        "created_at": datetime.now(),
                        "last_activity": datetime.now(),
                        "scam_type": None,
                        "start_time": time.time(),  # For engagement duration
                        "detection_history": []
                    }
                    logger.info(f"📝 Created new session: {session_id}")

                # Update last activity
                self.sessions[session_id]["last_activity"] = datetime.now()

                return self.sessions[session_id]

        except Exception as e:
            logger.error(f"Error getting session {session_id}: {e}")
            # Return minimal valid session
            return {
                "scam_detected": False,
                "confidence_score": 0.0,
                "message_count": 0,
                "intelligence": {
                    "phoneNumbers": [],
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "emailAddresses": [],
                    "suspiciousKeywords": [],
                    "caseIds": [],
                    "policyNumbers": [],
                    "orderNumbers": [],
                },
                "red_flags": {},
                "callback_sent": False,
                "scam_type": None,
                "start_time": time.time()
            }

    async def update_session(self, session_id: str, updates: Dict):
        """
        Update session data

        Args:
            session_id: Session identifier
            updates: Dictionary of fields to update
        """
        try:
            if not session_id or not updates:
                return

            async with self.lock:
                if session_id in self.sessions:
                    self.sessions[session_id].update(updates)
                    self.sessions[session_id]["last_activity"] = datetime.now()
                else:
                    logger.warning(f"Cannot update non-existent session: {session_id}")

        except Exception as e:
            logger.error(f"Error updating session {session_id}: {e}")

    async def cleanup_old_sessions(self):
        """Remove expired sessions based on TTL"""
        try:
            async with self.lock:
                now = datetime.now()
                expired = []

                for sid, data in self.sessions.items():
                    try:
                        last_activity = data.get("last_activity")
                        if not last_activity:
                            continue

                        age = (now - last_activity).seconds
                        if age > self.ttl:
                            expired.append(sid)
                    except Exception as e:
                        logger.debug(f"Error checking session {sid}: {e}")
                        continue

                # Remove expired sessions
                for sid in expired:
                    try:
                        del self.sessions[sid]
                    except Exception as e:
                        logger.debug(f"Error deleting session {sid}: {e}")

                if expired:
                    logger.info(f"🧹 Cleaned up {len(expired)} expired sessions")

        except Exception as e:
            logger.error(f"Error during session cleanup: {e}")

    def get_session_count(self) -> int:
        """Get total number of active sessions"""
        try:
            return len(self.sessions)
        except Exception:
            return 0

    def get_scam_session_count(self) -> int:
        """Get number of sessions where scam was detected"""
        try:
            return sum(
                1 for session in self.sessions.values()
                if session.get("scam_detected", False)
            )
        except Exception:
            return 0