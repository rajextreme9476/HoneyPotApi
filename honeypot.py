"""
Agentic HoneyPot v3.0 - Production Grade Multi-Lingual Scam Detection
National Hackathon Final Round Submission

Architecture:
- Async FastAPI with connection pooling
- Multi-stage scam detection with ensemble voting
- Context-aware agent with memory
- Advanced intelligence extraction
- Production monitoring and resilience
"""

from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any, Tuple
from google import genai
from contextlib import asynccontextmanager
import requests
import re
import json
import logging
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import hashlib
from functools import lru_cache
import time

# ======================================================
# CONFIGURATION
# ======================================================
API_KEY = "123456789"
MODEL_NAME = "gemini-2.5-flash"
GEMINI_API_KEY = "AIzaSyDa9oLfEYr53eJ36_HfHE0lKm9kSa5TfSc"
FINAL_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Production settings
MAX_CONCURRENT_REQUESTS = 100
REQUEST_TIMEOUT = 25  # seconds
CACHE_TTL = 3600  # 1 hour
MAX_RETRIES = 2
CIRCUIT_BREAKER_THRESHOLD = 5
CIRCUIT_BREAKER_TIMEOUT = 60

# Initialize Gemini client
client = genai.Client(api_key=GEMINI_API_KEY)

# Enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
logger = logging.getLogger(__name__)


# ======================================================
# PRODUCTION UTILITIES
# ======================================================
class CircuitBreaker:
    """Circuit breaker pattern for API resilience"""

    def __init__(self, failure_threshold: int = CIRCUIT_BREAKER_THRESHOLD, timeout: int = CIRCUIT_BREAKER_TIMEOUT):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failures = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def call(self, func, *args, **kwargs):
        if self.state == "OPEN":
            if datetime.now() - self.last_failure_time > timedelta(seconds=self.timeout):
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
                self.failures = 0
            return result
        except Exception as e:
            self.failures += 1
            self.last_failure_time = datetime.now()
            if self.failures >= self.failure_threshold:
                self.state = "OPEN"
                logger.error(f"Circuit breaker opened after {self.failures} failures")
            raise e


class RateLimiter:
    """Token bucket rate limiter"""

    def __init__(self, max_requests: int = 100, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        # Clean old requests
        self.requests[key] = [req_time for req_time in self.requests[key]
                              if now - req_time < self.time_window]

        if len(self.requests[key]) < self.max_requests:
            self.requests[key].append(now)
            return True
        return False


# Global instances
circuit_breaker = CircuitBreaker()
rate_limiter = RateLimiter()


# ======================================================
# ENHANCED DATA MODELS
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

    @validator('sessionId')
    def validate_session_id(cls, v):
        if not v or len(v) > 100:
            raise ValueError('Invalid sessionId')
        return v


# ======================================================
# ADVANCED INTELLIGENCE EXTRACTION
# ======================================================
class IntelligenceExtractor:
    """Advanced multi-modal intelligence extraction"""

    def __init__(self):
        # Pre-compiled regex patterns for performance
        self.patterns = {
            'bank_account': [
                re.compile(r'\b\d{9,18}\b'),
                re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4,10}\b'),
                re.compile(r'account\s*(?:number|no|num)?[:\s]+(\d{9,18})', re.IGNORECASE),
                re.compile(r'A/?C[:\s]+(\d{9,18})', re.IGNORECASE),
                re.compile(r'खाता\s*संख्या[:\s]+(\d{9,18})'),  # Hindi
            ],
            'upi': [
                re.compile(r'\b[\w.-]+@(?:paytm|ybl|okhdfcbank|okicici|axl|ibl|fbl|pytm|gpay|phonepe|upi)'),
                re.compile(r'\b\d{10}@[\w.-]+'),
                re.compile(r'[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+(?=\s|$)'),
            ],
            'phone': [
                re.compile(r'\+91[-\s]?[6-9]\d{9}\b'),
                re.compile(r'\b[6-9]\d{9}\b'),
                re.compile(r'\b91[6-9]\d{9}\b'),
            ],
            'url': [
                re.compile(r'https?://[^\s]+'),
                re.compile(r'\b(?:bit\.ly|tinyurl|goo\.gl|t\.co|cutt\.ly)/[^\s]+'),
                re.compile(r'www\.[^\s]+\.(?:com|net|org|in)[^\s]*'),
            ],
            'ifsc': [
                re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'),  # Indian IFSC codes
            ],
            'pan': [
                re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),  # PAN format
            ],
            'aadhaar': [
                re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),  # Aadhaar format
            ]
        }

        # Suspicious keyword database (multi-lingual)
        self.suspicious_keywords = self._load_suspicious_keywords()

        # Context-aware extraction cache
        self.extraction_cache = {}

    def _load_suspicious_keywords(self) -> Dict[str, List[str]]:
        """Load comprehensive suspicious keyword database"""
        return {
            'urgency': [
                'urgent', 'urgently', 'immediately', 'asap', 'right now', 'turant', 'abhi',
                'jaldi', 'तुरंत', 'अभी', 'जल्दी', 'உடனடியாக', 'తక్షణం'
            ],
            'threat': [
                'blocked', 'suspended', 'expire', 'deactivate', 'close', 'block ho jayega',
                'band', 'बंद', 'ब्लॉक', 'निलंबित', 'முடக்கப்பட்டது'
            ],
            'verification': [
                'verify', 'confirm', 'update', 'kyc', 'pan', 'aadhaar', 'aadhar',
                'verify karo', 'confirm karo', 'सत्यापित', 'உறுதிப்படுத்து'
            ],
            'financial': [
                'account', 'bank', 'card', 'cvv', 'pin', 'otp', 'password', 'upi',
                'transfer', 'refund', 'payment', 'khata', 'खाता', 'கணக்கு', 'బ్యాంకు'
            ],
            'impersonation': [
                'rbi', 'reserve bank', 'police', 'cyber cell', 'government', 'uidai',
                'income tax', 'custom', 'courier', 'fedex', 'dhl', 'सरकार', 'पुलिस'
            ],
            'reward': [
                'prize', 'won', 'lottery', 'winner', 'claim', 'reward', 'cashback',
                'jeet', 'इनाम', 'पुरस्कार', 'பரிசு'
            ],
            'action': [
                'click', 'link', 'download', 'install', 'share', 'forward',
                'click karo', 'link kholo', 'क्लिक', 'இணைப்பு'
            ]
        }

    def extract(self, text: str, conversation_history: List[Message] = None) -> Dict[str, Any]:
        """
        Extract comprehensive intelligence with context awareness
        Returns enhanced intelligence dictionary
        """
        # Build full context
        full_text = self._build_context(text, conversation_history)
        cache_key = hashlib.md5(full_text.encode()).hexdigest()

        # Check cache
        if cache_key in self.extraction_cache:
            return self.extraction_cache[cache_key]

        intelligence = {
            "bankAccounts": self._extract_bank_accounts(full_text),
            "upiIds": self._extract_upi_ids(full_text),
            "phishingLinks": self._extract_urls(full_text),
            "phoneNumbers": self._extract_phone_numbers(full_text),
            "ifscCodes": self._extract_pattern(full_text, 'ifsc'),
            "panNumbers": self._extract_pattern(full_text, 'pan'),
            "aadhaarNumbers": self._extract_pattern(full_text, 'aadhaar'),
            "suspiciousKeywords": self._extract_suspicious_keywords(full_text),
            "scamTactics": self._identify_scam_tactics(full_text),
            "languageDetection": self._detect_language(text),
            "sentimentScore": self._analyze_sentiment(text)
        }

        # Cache result
        self.extraction_cache[cache_key] = intelligence

        return intelligence

    def _build_context(self, current_text: str, history: List[Message] = None) -> str:
        """Build full conversation context"""
        if not history:
            return current_text

        context_parts = [msg.text for msg in history[-10:]]  # Last 10 messages
        context_parts.append(current_text)
        return " ".join(context_parts)

    def _extract_bank_accounts(self, text: str) -> List[str]:
        """Extract and validate bank account numbers"""
        accounts = set()
        for pattern in self.patterns['bank_account']:
            for match in pattern.findall(text):
                clean = re.sub(r'[-\s]', '', str(match))
                if 9 <= len(clean) <= 18 and clean.isdigit():
                    # Validate: not all same digit, not sequential
                    if len(set(clean)) > 1 and not self._is_sequential(clean):
                        accounts.add(clean)
        return sorted(list(accounts))[:10]

    def _extract_upi_ids(self, text: str) -> List[str]:
        """Extract and validate UPI IDs"""
        upis = set()
        for pattern in self.patterns['upi']:
            for match in pattern.findall(text):
                if '@' in match and len(match) > 5 and len(match) < 100:
                    # Additional validation
                    parts = match.split('@')
                    if len(parts) == 2 and parts[0] and parts[1]:
                        upis.add(match.lower())
        return sorted(list(upis))[:10]

    def _extract_urls(self, text: str) -> List[str]:
        """Extract suspicious URLs"""
        urls = set()
        for pattern in self.patterns['url']:
            urls.update(pattern.findall(text))

        # Filter suspicious URLs
        suspicious_urls = []
        for url in urls:
            if self._is_suspicious_url(url):
                suspicious_urls.append(url)

        return suspicious_urls[:10]

    def _extract_phone_numbers(self, text: str) -> List[str]:
        """Extract phone numbers"""
        phones = set()
        for pattern in self.patterns['phone']:
            phones.update(pattern.findall(text))
        return sorted(list(phones))[:10]

    def _extract_pattern(self, text: str, pattern_type: str) -> List[str]:
        """Generic pattern extraction"""
        results = set()
        for pattern in self.patterns.get(pattern_type, []):
            results.update(pattern.findall(text))
        return sorted(list(results))[:10]

    def _extract_suspicious_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords with categorization"""
        text_lower = text.lower()
        found_keywords = []

        for category, keywords in self.suspicious_keywords.items():
            for keyword in keywords:
                if keyword.lower() in text_lower:
                    found_keywords.append(f"{category}:{keyword}")

        return found_keywords[:30]

    def _identify_scam_tactics(self, text: str) -> List[str]:
        """Identify scam tactics using pattern matching"""
        tactics = []
        text_lower = text.lower()

        tactic_patterns = {
            'urgency_pressure': ['urgent', 'immediately', 'within', 'hours', 'expire'],
            'authority_impersonation': ['rbi', 'bank', 'police', 'government', 'official'],
            'fear_mongering': ['blocked', 'suspended', 'legal action', 'arrest', 'fine'],
            'too_good_to_be_true': ['won', 'prize', 'lottery', 'free', 'cashback'],
            'information_harvesting': ['verify', 'confirm', 'update', 'kyc', 'details'],
            'payment_request': ['pay', 'transfer', 'send money', 'upi', 'account number'],
            'link_phishing': ['click', 'link', 'url', 'website', 'download']
        }

        for tactic, indicators in tactic_patterns.items():
            if any(indicator in text_lower for indicator in indicators):
                tactics.append(tactic)

        return tactics

    def _detect_language(self, text: str) -> str:
        """Detect primary language"""
        # Simple heuristic-based detection
        if re.search(r'[\u0900-\u097F]', text):  # Devanagari
            return 'hindi'
        elif re.search(r'[\u0B80-\u0BFF]', text):  # Tamil
            return 'tamil'
        elif re.search(r'[\u0C00-\u0C7F]', text):  # Telugu
            return 'telugu'
        elif re.search(r'[\u0D00-\u0D7F]', text):  # Malayalam
            return 'malayalam'
        else:
            # Check for Hinglish patterns
            hinglish_patterns = ['karo', 'karna', 'hai', 'hoga', 'aapka', 'apka']
            if any(pattern in text.lower() for pattern in hinglish_patterns):
                return 'hinglish'
            return 'english'

    def _analyze_sentiment(self, text: str) -> float:
        """Simple sentiment analysis (0-1, higher = more suspicious)"""
        suspicious_count = sum(1 for keyword_list in self.suspicious_keywords.values()
                               for keyword in keyword_list if keyword.lower() in text.lower())
        total_words = len(text.split())
        return min(suspicious_count / max(total_words, 1), 1.0)

    def _is_sequential(self, num_str: str) -> bool:
        """Check if number is sequential"""
        if len(num_str) < 4:
            return False
        for i in range(len(num_str) - 3):
            if int(num_str[i:i + 4]) in range(1234, 9877):  # Basic sequential check
                if all(int(num_str[j + 1]) - int(num_str[j]) == 1 for j in range(i, i + 3)):
                    return True
        return False

    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious"""
        suspicious_indicators = [
            'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'cutt.ly',  # URL shorteners
            'click', 'secure', 'verify', 'update', 'login',  # Common phishing terms
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
            'dropbox', 'mediafire', 'drive.google',  # File sharing (often abused)
        ]
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in suspicious_indicators)


# ======================================================
# MULTI-STAGE SCAM DETECTION ENGINE
# ======================================================
class ScamDetectionEngine:
    """Ensemble-based multi-stage scam detection"""

    def __init__(self):
        self.detection_cache = {}
        self.false_positive_patterns = self._load_false_positive_patterns()

    def _load_false_positive_patterns(self) -> List[str]:
        """Patterns that indicate legitimate communication"""
        return [
            # E-commerce & Shopping
            'thank you for your purchase',
            'your order has been confirmed',
            'order shipped',
            'out for delivery',
            'delivery scheduled',
            'tracking number',
            'successfully delivered',

            # Banking & Financial (Legitimate)
            'your transaction of',
            'credited to your account',
            'debited from your account',
            'transaction successful',
            'statement for',
            'minimum balance',

            # Appointments & Bookings
            'appointment confirmed',
            'booking confirmed',
            'reservation confirmed',
            'reminder for your appointment',

            # Password & Security (Legitimate)
            'password reset requested by you',
            'password changed successfully',
            'login from new device',
            'security alert: you logged in',

            # OTP & Verification (Legitimate)
            'your otp is',
            'verification code',
            'one-time password',
            'do not share this otp',
            'valid for 10 minutes',

            # Notifications (Legitimate)
            'your subscription',
            'renewal reminder',
            'payment received',
            'invoice attached',

            # Customer Service (Legitimate)
            'thank you for contacting',
            'your ticket number',
            'we have received your request',
            'customer support'
        ]

    async def detect(self, text: str, intelligence: Dict, conversation_history: List[Message] = None) -> Tuple[
        bool, float, str]:
        """
        Multi-stage scam detection with confidence scoring
        Returns: (is_scam, confidence_score, reasoning)
        """
        cache_key = hashlib.md5(text.encode()).hexdigest()
        if cache_key in self.detection_cache:
            return self.detection_cache[cache_key]

        # Stage 1: Rule-based detection
        rule_score, rule_reasoning = self._rule_based_detection(text, intelligence)

        # Stage 2: AI-powered detection
        ai_score, ai_reasoning = await self._ai_detection(text)

        # Stage 3: Context analysis
        context_score, context_reasoning = self._context_analysis(conversation_history, intelligence)

        # Ensemble voting with ADAPTIVE weighted average
        # Adjust weights based on detection confidence and context

        # Base weights (balanced approach)
        base_weights = {'rule': 0.40, 'ai': 0.40, 'context': 0.20}

        # Adaptive adjustment: Trust AI more when it's confident
        if ai_score >= 0.9:  # AI is very confident
            weights = {'rule': 0.30, 'ai': 0.50, 'context': 0.20}
            logger.info(f"🤖 AI highly confident ({ai_score:.0%}) - increasing AI weight to 50%")
        elif ai_score == 0.0 and rule_score >= 0.7:  # AI uncertain but rules are clear
            weights = {'rule': 0.60, 'ai': 0.20, 'context': 0.20}
            logger.info(f"📏 Rules clear ({rule_score:.0%}), AI uncertain - increasing rule weight to 60%")
        elif context_score >= 0.8:  # Strong contextual evidence
            weights = {'rule': 0.30, 'ai': 0.40, 'context': 0.30}
            logger.info(f"📚 Strong context ({context_score:.0%}) - increasing context weight to 30%")
        else:  # Balanced approach when no strong signal
            weights = base_weights
            logger.info(f"⚖️  Balanced weighting: Rule=40%, AI=40%, Context=20%")

        final_score = (
                rule_score * weights['rule'] +
                ai_score * weights['ai'] +
                context_score * weights['context']
        )

        logger.info(
            f"📊 Ensemble calculation: ({rule_score:.2f} × {weights['rule']:.0%}) + ({ai_score:.2f} × {weights['ai']:.0%}) + ({context_score:.2f} × {weights['context']:.0%}) = {final_score:.2f}")

        # Check for false positives (context-aware)
        if self._is_false_positive(text, intelligence):
            logger.info(f"⚠️  False positive detected - reducing confidence by 70%")
            logger.info(f"   Original score: {final_score:.2%}")
            final_score *= 0.3
            logger.info(f"   Adjusted score: {final_score:.2%}")

        # CRITICAL: Lower threshold for better detection
        # Previous: 0.65, New: 0.55 (catches more scams)
        is_scam = final_score > 0.55

        reasoning = f"Rule:{rule_score:.2f} AI:{ai_score:.2f} Context:{context_score:.2f} | {rule_reasoning} {ai_reasoning}"

        result = (is_scam, final_score, reasoning)
        self.detection_cache[cache_key] = result

        return result

    def _rule_based_detection(self, text: str, intelligence: Dict) -> Tuple[float, str]:
        """Rule-based scam scoring"""
        score = 0.0
        reasons = []
        text_lower = text.lower()

        # Intelligence-based scoring (HIGH CONFIDENCE)
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
        if len(intelligence.get('scamTactics', [])) >= 3:
            score += 0.25
            reasons.append('multiple_tactics')
        elif len(intelligence.get('scamTactics', [])) >= 2:
            score += 0.15
            reasons.append('dual_tactics')

        # CRITICAL: Lottery/Prize scam detection
        lottery_indicators = ['won', 'winner', 'prize', 'lottery', 'congratulations',
                              'claim', 'reward', 'jackpot', 'lakh', 'crore']
        if sum(1 for word in lottery_indicators if word in text_lower) >= 2:
            score += 0.50  # VERY HIGH - lottery scams are obvious
            reasons.append('lottery_scam')

        # Payment request detection
        payment_words = ['pay', 'payment', 'fee', 'processing fee', 'transfer',
                         'send money', 'deposit', 'advance']
        if any(word in text_lower for word in payment_words):
            score += 0.40  # Payment requests are HIGH risk
            reasons.append('payment_request')

        # Keyword-based scoring
        urgency_words = ['urgent', 'immediately', 'now', 'asap', 'turant', 'abhi', 'जल्दी']
        urgency_count = sum(1 for word in urgency_words if word in text_lower)
        if urgency_count >= 2:
            score += 0.20
            reasons.append('high_urgency')
        elif urgency_count >= 1:
            score += 0.10
            reasons.append('urgency')

        threat_words = ['block', 'blocked', 'suspend', 'expire', 'deactivate',
                        'legal action', 'arrest', 'fine', 'penalty']
        if any(word in text_lower for word in threat_words):
            score += 0.25
            reasons.append('threats')

        # Sensitive info requests
        sensitive = ['otp', 'pin', 'password', 'cvv', 'card number', 'pan',
                     'aadhaar', 'aadhar', 'account number']
        if any(word in text_lower for word in sensitive):
            score += 0.40
            reasons.append('sensitive_info_request')

        return min(score, 1.0), ','.join(reasons)

    async def _ai_detection(self, text: str) -> Tuple[float, str]:
        """AI-powered scam detection with retry logic"""
        prompt = f"""Analyze this message for scam indicators. 

CRITICAL SCAM PATTERNS TO DETECT:
1. LOTTERY/PRIZE SCAMS: Any "you won" + "pay fee" = 100% SCAM
2. PAYMENT REQUESTS: Asking for money/fees upfront = SCAM
3. URGENCY + THREATS: "immediately" + "blocked" = SCAM  
4. SENSITIVE INFO: Requesting OTP/PIN/password = SCAM
5. IMPERSONATION: Claiming to be bank/RBI/police = SCAM
6. MULTIPLE PAYMENT METHODS: Providing UPI + bank account = SCAM

Message to analyze: "{text}"

Rules:
- If message mentions winning prize AND asks for payment/fee → SCAM
- If message provides payment details (UPI/account) → SCAM
- If message threatens account blocking → SCAM
- If message requests OTP/PIN/password → SCAM

Respond with ONLY ONE WORD: SCAM or NOT_SCAM

Your answer:"""

        try:
            response = await asyncio.to_thread(
                circuit_breaker.call,
                client.models.generate_content,
                model=MODEL_NAME,
                contents=prompt
            )

            verdict = response.text.strip().upper()
            verdict = re.sub(r'```.*?```', '', verdict, flags=re.DOTALL).strip()

            if 'SCAM' in verdict and 'NOT_SCAM' not in verdict:
                return 1.0, 'ai_detected_scam'
            elif 'NOT_SCAM' in verdict:
                return 0.0, 'ai_detected_safe'
            else:
                return 0.5, 'ai_uncertain'

        except Exception as e:
            logger.error(f"AI detection failed: {e}")
            return 0.5, 'ai_fallback'

    def _context_analysis(self, history: List[Message], intelligence: Dict) -> Tuple[float, str]:
        """Analyze conversation context for scam patterns"""
        if not history or len(history) < 1:
            return 0.3, 'minimal_context'  # Changed from 0.5 to 0.3

        score = 0.0

        # Build recent message text for analysis
        recent_messages = [msg.text.lower() for msg in history[-10:]]
        full_context = ' '.join(recent_messages)

        # Pattern 1: Escalating requests (prize → payment → details)
        prize_mentioned = any('won' in msg or 'prize' in msg or 'lottery' in msg
                              or 'congratulations' in msg for msg in recent_messages)
        payment_requested = any('pay' in msg or 'fee' in msg or 'transfer' in msg
                                or 'send money' in msg for msg in recent_messages)
        details_requested = any('upi' in msg or 'account' in msg or 'bank' in msg
                                for msg in recent_messages)

        if prize_mentioned and payment_requested:
            score += 0.60  # Classic lottery scam pattern
        if payment_requested and details_requested:
            score += 0.40  # Payment + account details = HIGH RISK

        # Pattern 2: Repeated urgency
        urgency_count = sum(1 for msg in recent_messages
                            if any(word in msg for word in ['urgent', 'immediately', 'now', 'asap']))
        if urgency_count >= 3:
            score += 0.30
        elif urgency_count >= 2:
            score += 0.20

        # Pattern 3: Information gathering escalation
        question_count = sum(msg.count('?') for msg in recent_messages)
        if question_count >= 4:
            score += 0.20

        # Pattern 4: Multiple payment methods (UPI + bank + phone)
        payment_methods = 0
        if intelligence.get('upiIds'):
            payment_methods += 1
        if intelligence.get('bankAccounts'):
            payment_methods += 1
        if intelligence.get('phoneNumbers'):
            payment_methods += 1

        if payment_methods >= 2:
            score += 0.40  # Multiple payment methods = HIGH RISK
        elif payment_methods >= 1:
            score += 0.20

        # Pattern 5: Sentiment trajectory (getting more aggressive)
        if intelligence.get('sentimentScore', 0) > 0.7:
            score += 0.25
        elif intelligence.get('sentimentScore', 0) > 0.5:
            score += 0.15

        # Pattern 6: Scam tactics evolution
        tactics_count = len(intelligence.get('scamTactics', []))
        if tactics_count >= 4:
            score += 0.35
        elif tactics_count >= 3:
            score += 0.25
        elif tactics_count >= 2:
            score += 0.15

        return min(score, 1.0), f'context_score_{int(score * 100)}'

    def _is_false_positive(self, text: str, intelligence: Dict = None) -> bool:
        """Check for false positive patterns with context awareness"""
        text_lower = text.lower()

        # Check if message matches legitimate patterns
        has_legit_pattern = any(pattern in text_lower for pattern in self.false_positive_patterns)

        if not has_legit_pattern:
            return False  # No legitimate pattern found

        # Context-aware check: Does it also have strong scam indicators?
        if intelligence:
            has_strong_scam = (
                    len(intelligence.get('upiIds', [])) > 0 or  # Has payment IDs
                    len(intelligence.get('bankAccounts', [])) > 0 or  # Has bank accounts
                    len(intelligence.get('phishingLinks', [])) > 0 or  # Has suspicious links
                    len(intelligence.get('scamTactics', [])) >= 3  # Multiple tactics (3+)
            )

            # If has legitimate pattern BUT also strong scam indicators
            # → Likely a scam pretending to be legitimate
            if has_strong_scam:
                logger.info(f"⚠️  Legitimate pattern found BUT strong scam indicators present")
                logger.info(f"   → Not treating as false positive (likely scam pretending)")
                return False

        # Has legitimate pattern, no strong scam indicators
        # → Likely actually legitimate
        logger.info(f"✅ False positive pattern detected: legitimate message")
        return True


# ======================================================
# ADAPTIVE AGENT PERSONA
# ======================================================
class AdaptiveAgent:
    """Context-aware agent with personality and memory"""

    def __init__(self):
        self.response_cache = {}
        self.persona_templates = self._load_personas()

    def _load_personas(self) -> Dict[str, Dict]:
        """Load different persona templates based on context"""
        return {
            'confused_elderly': {
                'traits': 'elderly, confused, technology-challenged, worried about money',
                'phrases': [
                    "I don't understand technology very well",
                    "Please help me, I'm worried",
                    "What should I do?",
                    "Is everything okay with my account?"
                ]
            },
            'busy_professional': {
                'traits': 'busy, wants quick resolution, slightly skeptical',
                'phrases': [
                    "I'm in a meeting, can you clarify?",
                    "What exactly do you need?",
                    "Is this really necessary?",
                    "How long will this take?"
                ]
            },
            'cautious_youth': {
                'traits': 'young, somewhat tech-savvy, cautious but curious',
                'phrases': [
                    "Wait, why do you need this?",
                    "Can you explain more?",
                    "Is this legitimate?",
                    "How do I verify this?"
                ]
            }
        }

    async def generate_response(
            self,
            scammer_message: str,
            conversation_history: List[Message],
            intelligence: Dict,
            detected_language: str = 'english'
    ) -> str:
        """Generate contextually appropriate agent response"""

        # Select persona based on conversation stage
        message_count = len(conversation_history)
        persona = self._select_persona(message_count, intelligence)

        # Build conversation context
        conversation = self._build_conversation_context(conversation_history, scammer_message)

        # Generate response with persona
        prompt = self._build_agent_prompt(conversation, persona, detected_language, message_count)

        try:
            response = await asyncio.to_thread(
                circuit_breaker.call,
                client.models.generate_content,
                model=MODEL_NAME,
                contents=prompt
            )

            agent_reply = response.text.strip()
            agent_reply = re.sub(r'```.*?```', '', agent_reply, flags=re.DOTALL).strip()

            # Safety check: ensure agent didn't break character
            if self._breaks_character(agent_reply):
                agent_reply = self._get_fallback_response(detected_language, message_count)

            # Ensure response length is appropriate
            if len(agent_reply) > 200:
                agent_reply = agent_reply[:197] + '...'

            return agent_reply

        except Exception as e:
            logger.error(f"Agent generation failed: {e}")
            return self._get_fallback_response(detected_language, message_count)

    def _select_persona(self, message_count: int, intelligence: Dict) -> str:
        """Select appropriate persona based on context"""
        if message_count < 3:
            return 'confused_elderly'
        elif message_count < 6:
            return 'busy_professional'
        else:
            return 'cautious_youth'

    def _build_conversation_context(self, history: List[Message], current: str) -> str:
        """Build structured conversation context"""
        context = ""
        for msg in history[-8:]:  # Last 8 messages for context
            role = "Scammer" if msg.sender == "scammer" else "You"
            context += f"{role}: {msg.text}\n"
        context += f"Scammer: {current}\n"
        return context

    def _build_agent_prompt(self, conversation: str, persona: str, language: str, message_count: int) -> str:
        """Build sophisticated agent prompt with persona"""
        persona_info = self.persona_templates[persona]

        language_instructions = {
            'hindi': 'Respond ONLY in Hindi (Devanagari script)',
            'hinglish': 'Respond in Hinglish (mixed Hindi-English like "Mujhe samajh nahi aa raha")',
            'tamil': 'Respond ONLY in Tamil',
            'telugu': 'Respond ONLY in Telugu',
            'malayalam': 'Respond ONLY in Malayalam',
            'english': 'Respond in simple English'
        }

        stage_guidance = ""
        if message_count < 3:
            stage_guidance = "Show initial confusion. Ask basic clarifying questions."
        elif message_count < 6:
            stage_guidance = "Show some concern. Ask for more details about the verification."
        else:
            stage_guidance = "Show increasing worry. Ask specific questions about the process."

        return f"""You are playing the role of a {persona_info['traits']}.

CRITICAL RULES:
- {language_instructions.get(language, 'Respond in the SAME language as the scammer')}
- Keep response to 1-2 SHORT sentences (max 25 words)
- You do NOT know this is a scam - you believe it's real
- Show appropriate emotion: confusion, worry, concern
- Ask simple, natural questions
- NEVER use these words: scam, fraud, police, fake, report, suspicious, cheat
- NEVER accuse or warn
- Sound natural and human

Stage Guidance: {stage_guidance}

Recent conversation:
{conversation}

Generate your response as a worried person who believes this message.
Response:"""

    def _breaks_character(self, response: str) -> bool:
        """Check if agent broke character"""
        forbidden = ['scam', 'fraud', 'police', 'rbi', 'fake', 'cheat', 'report',
                     'suspicious', 'phishing', 'cyber', 'complaint']
        response_lower = response.lower()
        return any(word in response_lower for word in forbidden)

    def _get_fallback_response(self, language: str, message_count: int) -> str:
        """Get safe fallback response"""
        fallbacks = {
            'english': [
                "I'm not sure I understand. Can you explain?",
                "What do you need me to do exactly?",
                "I'm confused. Is this important?"
            ],
            'hindi': [
                "मुझे समझ नहीं आ रहा। कृपया समझाएं।",
                "क्या करना होगा मुझे?",
                "यह ज़रूरी है क्या?"
            ],
            'hinglish': [
                "Mujhe samajh nahi aa raha. Please explain.",
                "Kya karna hoga exactly?",
                "Main confused hoon. Important hai kya?"
            ]
        }

        responses = fallbacks.get(language, fallbacks['english'])
        return responses[message_count % len(responses)]


# ======================================================
# SESSION MANAGEMENT
# ======================================================
class SessionManager:
    """Thread-safe session management with TTL"""

    def __init__(self, ttl: int = 3600):
        self.sessions = {}
        self.ttl = ttl
        self.lock = asyncio.Lock()

    async def get_session(self, session_id: str) -> Dict:
        """Get or create session"""
        async with self.lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    "scam_detected": False,
                    "confidence_score": 0.0,
                    "message_count": 0,
                    "intelligence": {
                        "bankAccounts": [],
                        "upiIds": [],
                        "phishingLinks": [],
                        "phoneNumbers": [],
                        "ifscCodes": [],
                        "panNumbers": [],
                        "aadhaarNumbers": [],
                        "suspiciousKeywords": [],
                        "scamTactics": []
                    },
                    "callback_sent": False,
                    "created_at": datetime.now(),
                    "last_activity": datetime.now(),
                    "agent_persona": None,
                    "detection_history": []
                }

            # Update last activity
            self.sessions[session_id]["last_activity"] = datetime.now()
            return self.sessions[session_id]

    async def update_session(self, session_id: str, updates: Dict):
        """Update session data"""
        async with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].update(updates)

    async def cleanup_old_sessions(self):
        """Remove expired sessions"""
        async with self.lock:
            now = datetime.now()
            expired = [
                sid for sid, data in self.sessions.items()
                if (now - data["last_activity"]).seconds > self.ttl
            ]
            for sid in expired:
                del self.sessions[sid]
            if expired:
                logger.info(f"Cleaned up {len(expired)} expired sessions")


# ======================================================
# CALLBACK HANDLER
# ======================================================
async def send_final_callback(session_id: str, session_data: Dict):
    """Send final callback with retry logic"""
    payload = {
        "sessionId": session_id,
        "scamDetected": session_data["scam_detected"],
        "totalMessagesExchanged": session_data["message_count"],
        "extractedIntelligence": session_data["intelligence"],
        "confidenceScore": round(session_data["confidence_score"], 3),
        "detectionTimeline": session_data.get("detection_history", []),
        "agentNotes": (
            f"Multi-stage scam detection completed with {session_data['confidence_score']:.1%} confidence. "
            f"Detected tactics: {', '.join(session_data['intelligence'].get('scamTactics', []))}. "
            f"Engagement duration: {session_data['message_count']} messages."
        )
    }

    # ===== DETAILED CALLBACK LOGGING =====
    logger.info(f"{'=' * 80}")
    logger.info(f"📞 PREPARING CALLBACK FOR SESSION: {session_id}")
    logger.info(f"{'=' * 80}")
    logger.info(f"🌐 HTTP REQUEST DETAILS:")
    logger.info(f"  Method: POST")
    logger.info(f"  URL: {FINAL_CALLBACK_URL}")
    logger.info(f"  Content-Type: application/json")
    logger.info(f"  Timeout: 15 seconds")
    logger.info(f"")
    logger.info(f"📦 COMPLETE REQUEST BODY (JSON):")
    logger.info(f"{'-' * 80}")
    logger.info(json.dumps(payload, indent=2, ensure_ascii=False))
    logger.info(f"{'-' * 80}")
    logger.info(f"")
    logger.info(f"🔍 EXTRACTED INTELLIGENCE BREAKDOWN:")
    logger.info(f"{'-' * 80}")

    # Bank Accounts
    bank_accounts = payload['extractedIntelligence'].get('bankAccounts', [])
    logger.info(f"  📊 Bank Accounts: {len(bank_accounts)} extracted")
    if bank_accounts:
        for idx, account in enumerate(bank_accounts, 1):
            logger.info(f"      [{idx}] {account}")
    else:
        logger.info(f"      (none detected)")
    logger.info(f"")

    # UPI IDs
    upi_ids = payload['extractedIntelligence'].get('upiIds', [])
    logger.info(f"  💳 UPI IDs: {len(upi_ids)} extracted")
    if upi_ids:
        for idx, upi in enumerate(upi_ids, 1):
            logger.info(f"      [{idx}] {upi}")
    else:
        logger.info(f"      (none detected)")
    logger.info(f"")

    # Phone Numbers
    phones = payload['extractedIntelligence'].get('phoneNumbers', [])
    logger.info(f"  📞 Phone Numbers: {len(phones)} extracted")
    if phones:
        for idx, phone in enumerate(phones, 1):
            logger.info(f"      [{idx}] {phone}")
    else:
        logger.info(f"      (none detected)")
    logger.info(f"")

    # Phishing Links
    links = payload['extractedIntelligence'].get('phishingLinks', [])
    logger.info(f"  🔗 Phishing Links: {len(links)} extracted")
    if links:
        for idx, link in enumerate(links, 1):
            logger.info(f"      [{idx}] {link}")
    else:
        logger.info(f"      (none detected)")
    logger.info(f"")

    # IFSC Codes
    ifsc = payload['extractedIntelligence'].get('ifscCodes', [])
    logger.info(f"  🏦 IFSC Codes: {len(ifsc)} extracted")
    if ifsc:
        for idx, code in enumerate(ifsc, 1):
            logger.info(f"      [{idx}] {code}")
    else:
        logger.info(f"      (none detected)")
    logger.info(f"")

    # PAN Numbers
    pan = payload['extractedIntelligence'].get('panNumbers', [])
    logger.info(f"  🆔 PAN Numbers: {len(pan)} extracted")
    if pan:
        for idx, number in enumerate(pan, 1):
            logger.info(f"      [{idx}] {number}")
    else:
        logger.info(f"      (none detected)")
    logger.info(f"")

    # Aadhaar Numbers
    aadhaar = payload['extractedIntelligence'].get('aadhaarNumbers', [])
    logger.info(f"  🪪 Aadhaar Numbers: {len(aadhaar)} extracted")
    if aadhaar:
        for idx, number in enumerate(aadhaar, 1):
            logger.info(f"      [{idx}] {number}")
    else:
        logger.info(f"      (none detected)")
    logger.info(f"")

    # Suspicious Keywords
    keywords = payload['extractedIntelligence'].get('suspiciousKeywords', [])
    logger.info(f"  🚩 Suspicious Keywords: {len(keywords)} extracted")
    if keywords:
        for idx, keyword in enumerate(keywords, 1):
            logger.info(f"      [{idx}] {keyword}")
    else:
        logger.info(f"      (none detected)")
    logger.info(f"")

    # Scam Tactics
    tactics = payload['extractedIntelligence'].get('scamTactics', [])
    logger.info(f"  ⚠️  Scam Tactics: {len(tactics)} identified")
    if tactics:
        for idx, tactic in enumerate(tactics, 1):
            logger.info(f"      [{idx}] {tactic}")
    else:
        logger.info(f"      (none detected)")

    logger.info(f"{'-' * 80}")
    logger.info(f"")
    logger.info(f"📈 DETECTION METRICS:")
    logger.info(f"  • Session ID: {payload['sessionId']}")
    logger.info(f"  • Scam Detected: {payload['scamDetected']}")
    logger.info(f"  • Confidence Score: {payload['confidenceScore']} ({payload['confidenceScore']:.1%})")
    logger.info(f"  • Total Messages Exchanged: {payload['totalMessagesExchanged']}")
    logger.info(f"  • Detection Timeline: {len(payload.get('detectionTimeline', []))} checkpoints")
    for checkpoint in payload.get('detectionTimeline', []):
        logger.info(f"      Message #{checkpoint['message_num']}: {checkpoint['confidence']:.1%} confidence")
    logger.info(f"")
    logger.info(f"📝 Agent Summary:")
    logger.info(f"  {payload['agentNotes']}")
    logger.info(f"")
    logger.info(f"🚀 SENDING REQUEST TO CALLBACK URL...")
    logger.info(f"{'-' * 80}")
    logger.info(f"")

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = await asyncio.to_thread(
                requests.post,
                FINAL_CALLBACK_URL,
                json=payload,
                timeout=15
            )

            if response.status_code == 200:
                logger.info(f"")
                logger.info(f"{'=' * 80}")
                logger.info(f"✅ CALLBACK SENT SUCCESSFULLY")
                logger.info(f"{'=' * 80}")
                logger.info(f"")
                logger.info(f"📡 HTTP RESPONSE DETAILS:")
                logger.info(f"  • Session ID: {session_id}")
                logger.info(f"  • Status Code: {response.status_code} (OK)")
                logger.info(f"  • Response Time: {response.elapsed.total_seconds():.3f}s")
                logger.info(f"  • Response Headers:")
                for header, value in response.headers.items():
                    if header.lower() in ['content-type', 'content-length', 'date', 'server']:
                        logger.info(f"      {header}: {value}")
                logger.info(f"")
                logger.info(f"📥 RESPONSE BODY:")
                logger.info(f"{'-' * 80}")
                try:
                    response_data = response.json()
                    logger.info(json.dumps(response_data, indent=2, ensure_ascii=False))
                except:
                    logger.info(response.text)
                logger.info(f"{'-' * 80}")
                logger.info(f"")
                logger.info(f"📊 INTELLIGENCE SUBMISSION SUMMARY:")
                logger.info(f"{'-' * 80}")
                intel_summary = payload['extractedIntelligence']
                total_items = sum(len(v) if isinstance(v, list) else 0 for v in intel_summary.values())
                logger.info(f"  ✅ Total Intelligence Items Sent: {total_items}")
                logger.info(f"")
                logger.info(f"  Breakdown by Category:")
                logger.info(f"    • Bank Accounts: {len(intel_summary.get('bankAccounts', []))} items")
                if intel_summary.get('bankAccounts'):
                    logger.info(f"      → {intel_summary.get('bankAccounts')}")
                logger.info(f"    • UPI IDs: {len(intel_summary.get('upiIds', []))} items")
                if intel_summary.get('upiIds'):
                    logger.info(f"      → {intel_summary.get('upiIds')}")
                logger.info(f"    • Phone Numbers: {len(intel_summary.get('phoneNumbers', []))} items")
                if intel_summary.get('phoneNumbers'):
                    logger.info(f"      → {intel_summary.get('phoneNumbers')}")
                logger.info(f"    • Phishing Links: {len(intel_summary.get('phishingLinks', []))} items")
                if intel_summary.get('phishingLinks'):
                    logger.info(f"      → {intel_summary.get('phishingLinks')}")
                logger.info(f"    • IFSC Codes: {len(intel_summary.get('ifscCodes', []))} items")
                logger.info(f"    • PAN Numbers: {len(intel_summary.get('panNumbers', []))} items")
                logger.info(f"    • Aadhaar Numbers: {len(intel_summary.get('aadhaarNumbers', []))} items")
                logger.info(f"    • Suspicious Keywords: {len(intel_summary.get('suspiciousKeywords', []))} items")
                logger.info(f"    • Scam Tactics: {len(intel_summary.get('scamTactics', []))} items")
                logger.info(f"")
                logger.info(f"  ✅ Confidence Score: {payload['confidenceScore']:.1%}")
                logger.info(f"  ✅ Messages Exchanged: {payload['totalMessagesExchanged']}")
                logger.info(f"{'-' * 80}")
                logger.info(f"")
                logger.info(f"🎉 CALLBACK SUCCESSFULLY DELIVERED TO EVALUATION SERVER")
                logger.info(f"{'=' * 80}")
                logger.info(f"")
                return True
            else:
                logger.warning(f"Callback returned {response.status_code}, attempt {attempt + 1}/{max_retries}")

        except Exception as e:
            logger.error(f"Callback attempt {attempt + 1} failed: {e}")

        if attempt < max_retries - 1:
            await asyncio.sleep(2 ** attempt)  # Exponential backoff

    logger.error(f"✗ All callback attempts failed for session {session_id}")
    return False


# ======================================================
# APPLICATION INITIALIZATION
# ======================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    logger.info("🚀 Starting Agentic HoneyPot v3.0")

    # Initialize components
    global intelligence_extractor, scam_detector, agent, session_manager
    intelligence_extractor = IntelligenceExtractor()
    scam_detector = ScamDetectionEngine()
    agent = AdaptiveAgent()
    session_manager = SessionManager()

    # Start background tasks
    async def cleanup_task():
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            await session_manager.cleanup_old_sessions()

    cleanup_job = asyncio.create_task(cleanup_task())

    logger.info("✓ All systems operational")

    yield

    # Cleanup
    cleanup_job.cancel()
    logger.info("👋 Shutting down gracefully")


app = FastAPI(
    title="Agentic HoneyPot v3.0 - Production Grade",
    version="3.0.0",
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
    Main honeypot endpoint - Production grade with full error handling
    """
    start_time = time.time()

    # ===== AUTH =====
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")

    # ===== RATE LIMITING =====
    if not rate_limiter.is_allowed(payload.sessionId):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        # ===== SESSION MANAGEMENT =====
        session = await session_manager.get_session(payload.sessionId)
        session["message_count"] += 1

        logger.info(f"📨 Processing message #{session['message_count']} for session {payload.sessionId}")

        # ===== INTELLIGENCE EXTRACTION =====
        intelligence = intelligence_extractor.extract(
            payload.message.text,
            payload.conversationHistory
        )

        # Accumulate intelligence
        for key in intelligence:
            if isinstance(intelligence[key], list):
                session["intelligence"][key].extend(intelligence[key])
                session["intelligence"][key] = list(set(session["intelligence"][key]))[:20]

        total_intel = sum(len(v) for v in intelligence.values() if isinstance(v, list))
        logger.info(f"🔍 Extracted {total_intel} intelligence items")
        logger.info(f"    Banks: {len(intelligence.get('bankAccounts', []))}, "
                    f"UPI: {len(intelligence.get('upiIds', []))}, "
                    f"Phones: {len(intelligence.get('phoneNumbers', []))}, "
                    f"Links: {len(intelligence.get('phishingLinks', []))}, "
                    f"Keywords: {len(intelligence.get('suspiciousKeywords', []))}")
        if intelligence.get('bankAccounts'):
            logger.info(f"    → Bank Accounts: {intelligence.get('bankAccounts')}")
        if intelligence.get('upiIds'):
            logger.info(f"    → UPI IDs: {intelligence.get('upiIds')}")
        if intelligence.get('phoneNumbers'):
            logger.info(f"    → Phone Numbers: {intelligence.get('phoneNumbers')}")
        if intelligence.get('phishingLinks'):
            logger.info(f"    → Phishing Links: {intelligence.get('phishingLinks')}")

        # ===== SCAM DETECTION =====
        is_scam, confidence, reasoning = await scam_detector.detect(
            payload.message.text,
            intelligence,
            payload.conversationHistory
        )

        # Update session
        if is_scam and confidence > session.get("confidence_score", 0):
            session["scam_detected"] = True
            session["confidence_score"] = confidence
            session["detection_history"].append({
                "message_num": session["message_count"],
                "confidence": round(confidence, 3),
                "reasoning": reasoning
            })

        logger.info(f"🎯 Scam detection: {is_scam} (confidence: {confidence:.2%}) - {reasoning}")

        # ===== AGENT RESPONSE GENERATION =====
        detected_language = intelligence.get("languageDetection", "english")
        agent_reply = await agent.generate_response(
            payload.message.text,
            payload.conversationHistory,
            intelligence,
            detected_language
        )

        logger.info(f"🤖 Agent reply ({detected_language}): {agent_reply[:80]}...")

        # ===== CALLBACK DECISION =====
        should_callback = (
                session["scam_detected"] and
                session["message_count"] >= 3 and  # Wait for sufficient engagement
                confidence > 0.55 and  # Reduced from 0.7
                not session["callback_sent"] and
                sum(len(v) for k, v in session["intelligence"].items() if isinstance(v, list)) >= 1  # Reduced from 2
        )

        if should_callback:
            logger.info(f"")
            logger.info(f"{'=' * 80}")
            logger.info(f"📞 CALLBACK TRIGGER CONDITIONS MET")
            logger.info(f"{'=' * 80}")
            logger.info(f"Session ID: {payload.sessionId}")
            logger.info(f"Scam Detected: {session['scam_detected']}")
            logger.info(f"Message Count: {session['message_count']} (threshold: ≥3)")
            logger.info(f"Confidence: {confidence:.2%} (threshold: ≥55%)")
            total_intel = sum(len(v) for k, v in session["intelligence"].items() if isinstance(v, list))
            logger.info(f"Intelligence Items: {total_intel} (threshold: ≥1)")
            logger.info(f"Callback Already Sent: {session.get('callback_sent', False)}")
            logger.info(f"")
            logger.info(f"✅ Scheduling callback in background task...")
            logger.info(f"{'=' * 80}")
            logger.info(f"")
            session["callback_sent"] = True
            background_tasks.add_task(send_final_callback, payload.sessionId, session)

        # ===== UPDATE SESSION =====
        await session_manager.update_session(payload.sessionId, session)

        # ===== METRICS =====
        processing_time = time.time() - start_time
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
        logger.error(f"❌ Critical error: {str(e)}", exc_info=True)

        # Graceful degradation
        fallback_reply = "I'm having trouble understanding. Could you please explain again?"
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "reply": fallback_reply
            }
        )


# ======================================================
# HEALTH & MONITORING ENDPOINTS
# ======================================================
@app.get("/health")
async def health_check():
    """Comprehensive health check"""
    return {
        "status": "healthy",
        "service": "Agentic HoneyPot",
        "version": "3.0.0",
        "model": MODEL_NAME,
        "active_sessions": len(session_manager.sessions),
        "circuit_breaker": circuit_breaker.state,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/status")
async def status():
    """Detailed status with metrics"""
    total_messages = sum(s["message_count"] for s in session_manager.sessions.values())
    scam_sessions = sum(1 for s in session_manager.sessions.values() if s["scam_detected"])

    return {
        "service": "Agentic Honeypot v3.0",
        "status": "operational",
        "version": "3.0.0",
        "model": MODEL_NAME,
        "metrics": {
            "active_sessions": len(session_manager.sessions),
            "total_messages_processed": total_messages,
            "scam_sessions_detected": scam_sessions,
            "detection_rate": f"{scam_sessions / max(len(session_manager.sessions), 1) * 100:.1f}%"
        },
        "system": {
            "circuit_breaker_state": circuit_breaker.state,
            "cache_size": len(intelligence_extractor.extraction_cache)
        }
    }


@app.get("/")
async def root():
    """API documentation"""
    return {
        "service": "🛡️ Agentic HoneyPot v3.0 - Production Grade Multi-Lingual Scam Detection",
        "version": "3.0.0",
        "model": MODEL_NAME,
        "capabilities": [
            "Multi-stage ensemble scam detection",
            "Context-aware adaptive agent persona",
            "Advanced multi-lingual intelligence extraction",
            "Production-grade resilience (circuit breaker, rate limiting)",
            "Async processing with graceful degradation",
            "Comprehensive monitoring and metrics"
        ],
        "endpoints": {
            "analyze": "POST /api/v1/honeypot/analyze",
            "health": "GET /health",
            "status": "GET /status"
        },
        "supported_languages": [
            "English", "Hindi", "Hinglish", "Tamil", "Telugu", "Malayalam"
        ]
    }


# ======================================================
# ERROR HANDLERS
# ======================================================
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for resilience"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "Internal server error - system remains operational",
            "reply": "I'm having some difficulty. Could you try again?"
        }
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )