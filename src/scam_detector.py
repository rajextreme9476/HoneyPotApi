"""
Scam Detection Module
Multi-stage scam detection with AI and rules
"""
import re
import hashlib
import logging
import asyncio
from typing import Dict, List, Tuple, Optional
from google import genai

from .config import Config
from .intelligence_extractor import Message

logger = logging.getLogger(__name__)


class ScamTypeDetector:
    """Detect specific scam types"""
    
    def detect_scam_type(
        self,
        text: str,
        intelligence: Dict,
        conversation_history: Optional[List[Message]] = None
    ) -> str:
        """
        Detect scam type based on content
        
        Returns: bank_fraud, upi_fraud, phishing, lottery_scam, etc.
        """
        try:
            if not text:
                return "scam_detected"
            
            text_lower = text.lower()
            
            # Build full context
            full_context = text_lower
            if conversation_history:
                try:
                    history_text = " ".join(
                        msg.text.lower() for msg in conversation_history 
                        if hasattr(msg, 'text') and msg.text
                    )
                    full_context = f"{history_text} {text_lower}"
                except Exception as e:
                    logger.debug(f"Error building context: {e}")
            
            # Bank fraud indicators
            bank_keywords = ['bank', 'account blocked', 'account suspended', 
                           'sbi', 'hdfc', 'icici', 'account compromised', 
                           'kyc', 'pan', 'aadhaar']
            if sum(1 for k in bank_keywords if k in full_context) >= 2:
                return "bank_fraud"
            
            # UPI fraud indicators
            upi_keywords = ['upi', 'paytm', 'phonepe', 'gpay', 'cashback', 'refund']
            if any(k in full_context for k in upi_keywords):
                if intelligence.get('upiIds'):
                    return "upi_fraud"
            
            # Phishing link indicators
            if intelligence.get('phishingLinks'):
                return "phishing"
            
            # Lottery/Prize scam
            lottery_keywords = ['won', 'winner', 'prize', 'lottery', 
                              'congratulations', 'claim', 'reward']
            if sum(1 for k in lottery_keywords if k in text_lower) >= 2:
                return "lottery_scam"
            
            # Investment scam
            investment_keywords = ['investment', 'trading', 'profit', 
                                 'returns', 'crypto', 'stock']
            if any(k in full_context for k in investment_keywords):
                return "investment_scam"
            
            # Default
            return "scam_detected"
            
        except Exception as e:
            logger.error(f"Scam type detection error: {e}")
            return "scam_detected"


class ScamDetectionEngine:
    """Ensemble-based scam detection"""
    
    def __init__(self, gemini_client):
        self.client = gemini_client
        self.detection_cache = {}
        self.scam_type_detector = ScamTypeDetector()
    
    async def detect(
        self,
        text: str,
        intelligence: Dict,
        conversation_history: Optional[List[Message]] = None
    ) -> Tuple[bool, float, str]:
        """
        Multi-stage scam detection
        
        Returns: (is_scam, confidence_score, reasoning)
        """
        try:
            if not text:
                return False, 0.0, "empty_message"
            
            # Check cache
            cache_key = hashlib.md5(text.encode()).hexdigest()
            if cache_key in self.detection_cache:
                return self.detection_cache[cache_key]
            
            # Rule-based detection
            rule_score, rule_reasoning = self._rule_based_detection(text, intelligence)
            
            # AI-powered detection
            ai_score, ai_reasoning = await self._ai_detection(text)
            
            # Ensemble voting with adaptive weights
            if ai_score >= 0.9:
                weights = {'rule': 0.30, 'ai': 0.70}
            elif ai_score <= 0.1:
                weights = {'rule': 0.70, 'ai': 0.30}
            else:
                weights = {'rule': 0.50, 'ai': 0.50}
            
            final_score = (
                rule_score * weights['rule'] + 
                ai_score * weights['ai']
            )
            
            # Decision threshold
            is_scam = final_score > 0.55
            
            reasoning = f"Rule:{rule_score:.2f},AI:{ai_score:.2f}"
            
            # Cache result
            result = (is_scam, final_score, reasoning)
            self.detection_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Scam detection error: {e}", exc_info=True)
            # Safe fallback
            return False, 0.5, f"error:{str(e)[:50]}"
    
    def _rule_based_detection(self, text: str, intelligence: Dict) -> Tuple[float, str]:
        """Rule-based scam scoring"""
        try:
            if not text or not intelligence:
                return 0.0, "no_data"
            
            score = 0.0
            reasons = []
            text_lower = text.lower()
            
            # Intelligence-based scoring (high confidence)
            if intelligence.get('bankAccounts'):
                score += 0.30
                reasons.append('bank_accounts')
            
            if intelligence.get('upiIds'):
                score += 0.30
                reasons.append('upi_ids')
            
            if intelligence.get('phishingLinks'):
                score += 0.25
                reasons.append('phishing_links')
            
            if intelligence.get('phoneNumbers'):
                score += 0.20
                reasons.append('phone_numbers')
            
            if intelligence.get('emailAddresses'):
                score += 0.15
                reasons.append('emails')
            
            # Keyword-based scoring
            urgency_words = ['urgent', 'immediately', 'now', 'asap', 'fast']
            if any(word in text_lower for word in urgency_words):
                score += 0.15
                reasons.append('urgency')
            
            threat_words = ['block', 'suspend', 'expire', 'legal action', 'arrest']
            if any(word in text_lower for word in threat_words):
                score += 0.20
                reasons.append('threats')
            
            # Lottery/prize scam
            lottery_words = ['won', 'prize', 'lottery', 'winner', 'claim']
            if sum(1 for word in lottery_words if word in text_lower) >= 2:
                score += 0.40
                reasons.append('lottery_scam')
            
            # Payment request
            payment_words = ['pay', 'payment', 'fee', 'transfer', 'send money']
            if any(word in text_lower for word in payment_words):
                score += 0.25
                reasons.append('payment_request')
            
            return min(score, 1.0), ','.join(reasons) if reasons else 'no_indicators'
            
        except Exception as e:
            logger.error(f"Rule-based detection error: {e}")
            return 0.0, f"error:{str(e)[:30]}"
    
    async def _ai_detection(self, text: str) -> Tuple[float, str]:
        """AI-powered scam detection"""
        try:
            if not text:
                return 0.5, 'empty_text'
            
            prompt = f"""Is this message a scam? Analyze carefully.

Message: "{text}"

Respond with ONLY ONE WORD: SCAM or NOT_SCAM

Your answer:"""
            
            response = await asyncio.to_thread(
                self.client.models.generate_content,
                model=Config.MODEL_NAME,
                contents=prompt
            )
            
            if not response or not response.text:
                return 0.5, 'ai_no_response'
            
            verdict = response.text.strip().upper()
            verdict = re.sub(r'```.*?```', '', verdict, flags=re.DOTALL).strip()
            
            if 'SCAM' in verdict and 'NOT_SCAM' not in verdict:
                return 1.0, 'ai_detected_scam'
            elif 'NOT_SCAM' in verdict:
                return 0.0, 'ai_detected_safe'
            else:
                return 0.5, 'ai_uncertain'
                
        except asyncio.TimeoutError:
            logger.warning("AI detection timeout")
            return 0.5, 'ai_timeout'
        except Exception as e:
            logger.error(f"AI detection error: {e}")
            return 0.5, f'ai_error:{str(e)[:30]}'
    
    def detect_scam_type(
        self,
        text: str,
        intelligence: Dict,
        conversation_history: Optional[List[Message]] = None
    ) -> str:
        """Wrapper for scam type detection"""
        try:
            return self.scam_type_detector.detect_scam_type(
                text, intelligence, conversation_history
            )
        except Exception as e:
            logger.error(f"Scam type detection wrapper error: {e}")
            return "scam_detected"
