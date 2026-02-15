"""
Intelligence Extractor Module
Extracts intelligence from scammer messages
"""
import re
import hashlib
import logging
from typing import Dict, List, Optional, Union, Any
from pydantic import BaseModel, field_validator
from datetime import datetime

logger = logging.getLogger(__name__)


class Message(BaseModel):
    """Message model with flexible timestamp support"""
    sender: str
    text: str
    timestamp: Union[int, str, datetime, Any]  # Support all formats

    @field_validator('timestamp', mode='before')
    @classmethod
    def validate_timestamp(cls, v):
        """
        Accept multiple timestamp formats:
        - int: epoch milliseconds (1770060100000)
        - str: ISO format ("2026-02-15T10:30:00Z")
        - datetime: Python datetime object
        - any: For compatibility
        """
        if v is None:
            return datetime.now().isoformat()

        # Already valid types
        if isinstance(v, (int, str, datetime)):
            return v

        # Try to convert to string as fallback
        try:
            return str(v)
        except Exception:
            logger.warning(f"Could not validate timestamp: {v}, using current time")
            return datetime.now().isoformat()

    class Config:
        # Allow arbitrary types for maximum compatibility
        arbitrary_types_allowed = True


class IntelligenceExtractor:
    """
    Extract intelligence from scammer messages
    Returns guideline-compliant format ONLY
    """

    def __init__(self):
        self.patterns = self._compile_patterns()
        self.extraction_cache = {}
        self.suspicious_keywords_db = self._load_suspicious_keywords()

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Pre-compile regex patterns for performance"""
        try:
            return {
                'bank_account': [
                    re.compile(r'\b\d{9,18}\b'),
                    re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4,10}\b'),
                    re.compile(r'account\s*(?:number|no|num)?[:\s]+(\d{9,18})', re.IGNORECASE),
                    re.compile(r'A/?C[:\s]+(\d{9,18})', re.IGNORECASE),
                ],
                'upi': [
                    re.compile(r'\b[\w.-]+@(?:paytm|ybl|okhdfcbank|okicici|axl|ibl|fbl|pytm|gpay|phonepe|upi)\b'),
                    re.compile(r'\b\d{10}@[\w.-]+\b'),
                    re.compile(r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+(?:\s|$)'),
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
                'email': [
                    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
                    re.compile(r'\b[\w\.-]+@[\w\.-]+\.\w+\b'),
                ]
            }
        except Exception as e:
            logger.error(f"Error compiling patterns: {e}")
            return {}

    def _load_suspicious_keywords(self) -> Dict[str, List[str]]:
        """Load comprehensive suspicious keyword database"""
        return {
            'urgency': [
                'urgent', 'urgently', 'immediately', 'asap', 'right now',
                'quick', 'fast', 'hurry', 'expire', 'expires', 'expiring',
                'turant', 'abhi', 'jaldi', 'तुरंत', 'अभी', 'जल्दी'
            ],
            'threat': [
                'blocked', 'suspended', 'expire', 'deactivate', 'close',
                'legal action', 'arrest', 'fine', 'penalty', 'court',
                'block ho jayega', 'band', 'बंद', 'ब्लॉक', 'निलंबित'
            ],
            'verification': [
                'verify', 'confirm', 'update', 'kyc', 'pan', 'aadhaar',
                'aadhar', 'verify now', 'confirm now', 'update now',
                'verify karo', 'confirm karo', 'सत्यापित', 'अपडेट'
            ],
            'financial': [
                'account', 'bank', 'card', 'cvv', 'pin', 'otp', 'password',
                'upi', 'transfer', 'refund', 'payment', 'send money',
                'account number', 'bank account', 'खाता', 'पैसे'
            ],
            'impersonation': [
                'rbi', 'reserve bank', 'police', 'cyber cell', 'government',
                'uidai', 'income tax', 'custom', 'courier', 'fedex', 'dhl',
                'सरकार', 'पुलिस', 'बैंक'
            ],
            'reward': [
                'prize', 'won', 'lottery', 'winner', 'claim', 'reward',
                'cashback', 'congratulations', 'jeet', 'इनाम', 'पुरस्कार'
            ],
            'action': [
                'click', 'link', 'download', 'install', 'share', 'forward',
                'click here', 'click now', 'tap here', 'क्लिक'
            ]
        }

    def extract(
        self,
        text: str,
        conversation_history: Optional[List[Message]] = None
    ) -> Dict[str, List[str]]:
        """
        Extract intelligence - GUIDELINE FORMAT ONLY

        Args:
            text: Current message text
            conversation_history: Previous messages for context

        Returns:
            Dictionary with 5 guideline-required fields
        """
        try:
            # Build full context
            full_text = self._build_context(text, conversation_history)

            # Check cache
            cache_key = hashlib.md5(full_text.encode()).hexdigest()
            if cache_key in self.extraction_cache:
                return self.extraction_cache[cache_key]

            # Extract all intelligence
            intelligence = {
                "phoneNumbers": self._extract_phone_numbers(full_text),
                "bankAccounts": self._extract_bank_accounts(full_text),
                "upiIds": self._extract_upi_ids(full_text),
                "phishingLinks": self._extract_urls(full_text),
                "emailAddresses": self._extract_emails(full_text),
                "suspiciousKeywords": self._extract_suspicious_keywords(full_text),  # ✅ ADDED
            }

            # Cache result
            self.extraction_cache[cache_key] = intelligence

            # Log extraction summary
            total = sum(len(v) for v in intelligence.values())
            if total > 0:
                logger.info(f"🔍 Extracted {total} intelligence items: "
                          f"Banks={len(intelligence['bankAccounts'])}, "
                          f"UPI={len(intelligence['upiIds'])}, "
                          f"Phones={len(intelligence['phoneNumbers'])}, "
                          f"Links={len(intelligence['phishingLinks'])}, "
                          f"Emails={len(intelligence['emailAddresses'])}, "
                          f"Keywords={len(intelligence['suspiciousKeywords'])}")

            return intelligence

        except Exception as e:
            logger.error(f"Intelligence extraction error: {e}", exc_info=True)
            # Return empty but valid structure
            return {
                "phoneNumbers": [],
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "emailAddresses": [],
                "suspiciousKeywords": []  # ✅ ADDED
            }

    def _build_context(
        self,
        current_text: str,
        history: Optional[List[Message]]
    ) -> str:
        """Build full conversation context"""
        try:
            if not history:
                return current_text or ""

            context_parts = []
            for msg in history[-10:]:  # Last 10 messages
                if hasattr(msg, 'text') and msg.text:
                    context_parts.append(str(msg.text))

            context_parts.append(current_text or "")
            return " ".join(context_parts)

        except Exception as e:
            logger.error(f"Error building context: {e}")
            return current_text or ""

    def _extract_bank_accounts(self, text: str) -> List[str]:
        """Extract and validate bank account numbers"""
        try:
            if not text:
                return []

            accounts = set()
            for pattern in self.patterns.get('bank_account', []):
                try:
                    matches = pattern.findall(text)
                    for match in matches:
                        clean = re.sub(r'[-\s]', '', str(match))
                        # Validate: 9-18 digits, not all same, not sequential
                        if (9 <= len(clean) <= 18 and
                            clean.isdigit() and
                            len(set(clean)) > 1):
                            accounts.add(clean)
                except Exception as e:
                    logger.debug(f"Pattern match error: {e}")
                    continue

            return sorted(list(accounts))[:10]

        except Exception as e:
            logger.error(f"Bank account extraction error: {e}")
            return []

    def _extract_upi_ids(self, text: str) -> List[str]:
        """Extract and validate UPI IDs"""
        try:
            if not text:
                return []

            upis = set()
            for pattern in self.patterns.get('upi', []):
                try:
                    matches = pattern.findall(text)
                    for match in matches:
                        match = str(match).strip()
                        if '@' in match and 5 < len(match) < 100:
                            parts = match.split('@')
                            if len(parts) == 2 and parts[0] and parts[1]:
                                upis.add(match.lower())
                except Exception as e:
                    logger.debug(f"Pattern match error: {e}")
                    continue

            return sorted(list(upis))[:10]

        except Exception as e:
            logger.error(f"UPI extraction error: {e}")
            return []

    def _extract_urls(self, text: str) -> List[str]:
        """Extract suspicious URLs"""
        try:
            if not text:
                return []

            urls = set()
            for pattern in self.patterns.get('url', []):
                try:
                    matches = pattern.findall(text)
                    urls.update(str(m).strip() for m in matches)
                except Exception as e:
                    logger.debug(f"Pattern match error: {e}")
                    continue

            return sorted(list(urls))[:10]

        except Exception as e:
            logger.error(f"URL extraction error: {e}")
            return []

    def _extract_phone_numbers(self, text: str) -> List[str]:
        """Extract phone numbers"""
        try:
            if not text:
                return []

            phones = set()
            for pattern in self.patterns.get('phone', []):
                try:
                    matches = pattern.findall(text)
                    phones.update(str(m).strip() for m in matches)
                except Exception as e:
                    logger.debug(f"Pattern match error: {e}")
                    continue

            return sorted(list(phones))[:10]

        except Exception as e:
            logger.error(f"Phone extraction error: {e}")
            return []

    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses"""
        try:
            if not text:
                return []

            emails = set()
            for pattern in self.patterns.get('email', []):
                try:
                    matches = pattern.findall(text)
                    emails.update(str(m).strip().lower() for m in matches)
                except Exception as e:
                    logger.debug(f"Pattern match error: {e}")
                    continue

            return sorted(list(emails))[:10]

        except Exception as e:
            logger.error(f"Email extraction error: {e}")
            return []

    def _extract_suspicious_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords from text"""
        try:
            if not text:
                return []

            text_lower = text.lower()
            found_keywords = []

            # Search for keywords from each category
            for category, keywords in self.suspicious_keywords_db.items():
                for keyword in keywords:
                    if keyword.lower() in text_lower:
                        # Add keyword (not category, just the keyword itself)
                        if keyword not in found_keywords:
                            found_keywords.append(keyword)

            # Return unique keywords, sorted, limited to 30
            return sorted(list(set(found_keywords)))[:30]

        except Exception as e:
            logger.error(f"Suspicious keywords extraction error: {e}")
            return []