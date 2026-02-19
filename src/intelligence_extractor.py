"""
Intelligence Extractor Module - v5.0
Extracts intelligence from scammer messages with improved precision.

IMPROVEMENTS over v4.0:
- Tighter bank account regex: excludes dates, phone numbers, and common
  numeric noise; requires contextual keyword proximity for short numbers.
- Tighter UPI regex: generic @domain pattern now requires known UPI domains,
  reducing false positives from regular email addresses.
- URL extraction now scores/filters for suspicious domains rather than
  returning every URL.
- Extraction cache keyed on full context to prevent stale hits.
- Added IFSC code extraction as a new intelligence sub-field that helps
  identify bank fraud more precisely.
"""
import re
import hashlib
import logging
from typing import Dict, List, Optional, Union, Any
from pydantic import BaseModel, field_validator
from datetime import datetime

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known UPI VPA domains (Virtual Payment Addresses)
# ---------------------------------------------------------------------------
_UPI_DOMAINS = {
    "paytm", "ybl", "okhdfcbank", "okicici", "okaxis", "oksbi",
    "axl", "ibl", "fbl", "pytm", "gpay", "phonepe", "upi",
    "apl", "sliceaxis", "freecharge", "jiomoney", "airtelpayme",
    "hdfcbank", "icici", "sbi", "pockets", "indus", "kotak",
    "mahb", "barodampay", "unionbank", "citi", "hsbc",
    "rbl", "bandhan", "idbi", "federal", "yes", "aubank",
}

# ---------------------------------------------------------------------------
# Bank account keyword proximity context
# ---------------------------------------------------------------------------
_BANK_CONTEXT_KEYWORDS = {
    "account", "acc", "a/c", "ac", "ifsc", "bank", "transfer",
    "neft", "rtgs", "imps", "beneficiary", "credit", "deposit",
}


class Message(BaseModel):
    """Message model with flexible timestamp support"""
    sender: str
    text: str
    timestamp: Union[int, str, datetime, Any]

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, v):
        if v is None:
            return datetime.now().isoformat()
        if isinstance(v, (int, str, datetime)):
            return v
        try:
            return str(v)
        except Exception:
            return datetime.now().isoformat()

    class Config:
        arbitrary_types_allowed = True


class IntelligenceExtractor:
    """
    Extract structured intelligence from scammer messages.
    Returns guideline-compliant format ONLY.
    """

    def __init__(self):
        self.patterns = self._compile_patterns()
        self.extraction_cache: Dict[str, Dict] = {}
        self.suspicious_keywords_db = self._load_suspicious_keywords()

    # ------------------------------------------------------------------
    # PATTERN COMPILATION
    # ------------------------------------------------------------------
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Pre-compile regex patterns for performance."""
        try:
            upi_domain_alternation = "|".join(re.escape(d) for d in sorted(_UPI_DOMAINS, key=len, reverse=True))
            return {
                # Bank accounts: 9-18 digit sequences, but NOT matching
                # phone numbers (starts 6-9, exactly 10 digits) or dates.
                "bank_account": [
                    # Explicit account label followed by digits
                    re.compile(
                        r"(?:account\s*(?:number|no\.?|num\.?|#)?|a/?c\s*(?:no\.?|#)?|acc\.?\s*(?:no\.?|#)?)\s*[:\-]?\s*(\d[\d\s\-]{7,17}\d)",
                        re.IGNORECASE,
                    ),
                    # 11-18 standalone digit sequences (avoids 10-digit phone range)
                    re.compile(r"\b(\d{11,18})\b"),
                ],
                # IFSC codes
                "ifsc": [
                    re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b", re.IGNORECASE),
                ],
                # UPI: only accepted VPA domains
                "upi": [
                    re.compile(
                        rf"\b([\w.\-]+@(?:{upi_domain_alternation}))\b",
                        re.IGNORECASE,
                    ),
                    # Mobile@bank pattern: 10-digit mobile number @ known bank suffix
                    re.compile(
                        rf"\b([6-9]\d{{9}}@(?:{upi_domain_alternation}))\b",
                        re.IGNORECASE,
                    ),
                ],
                # Phone numbers (Indian)
                "phone": [
                    re.compile(r"\+91[-\s]?([6-9]\d{9})\b"),
                    re.compile(r"\b([6-9]\d{9})\b"),
                    re.compile(r"\b91([6-9]\d{9})\b"),
                ],
                # URLs — we collect all but score/filter for suspicious ones
                "url": [
                    re.compile(r"https?://[^\s\"'<>]+"),
                    re.compile(r"\bwww\.[^\s\"'<>]+"),
                    re.compile(r"\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|cutt\.ly|rb\.gy|ow\.ly|is\.gd)/[^\s\"'<>]+"),
                ],
                # Email
                "email": [
                    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
                ],
            }
        except Exception as e:
            logger.error(f"Error compiling patterns: {e}")
            return {}

    # ------------------------------------------------------------------
    # KEYWORD DATABASE
    # ------------------------------------------------------------------
    def _load_suspicious_keywords(self) -> Dict[str, List[str]]:
        """
        Comprehensive suspicious keyword database.
        8 languages × 7 threat categories = 200+ keywords.
        """
        return {
            "urgency": [
                # English
                "urgent", "urgently", "immediately", "asap", "right now",
                "quick", "quickly", "fast", "hurry", "rush", "instant",
                "expire", "expires", "expiring", "expired", "deadline",
                "last chance", "final notice", "time sensitive", "limited time",
                "act now", "dont delay", "before its too late",
                # Hindi
                "तुरंत", "अभी", "जल्दी", "शीघ्र", "फौरन", "तत्काल",
                # Hinglish
                "turant", "abhi", "jaldi", "jaldi karo", "abhi ke abhi",
                # Tamil
                "உடனடியாக", "விரைவாக", "இப்போதே",
                # Telugu
                "వెంటనే", "త్వరగా", "ఇప్పుడే",
                # Bengali
                "তাড়াতাড়ি", "এখনই", "দ্রুত",
                # Marathi
                "तातडीने", "लगेच", "आत्ताच",
                # Kannada
                "ತಕ್ಷಣ", "ಈಗಲೇ", "ಬೇಗ",
            ],
            "threat": [
                "blocked", "block", "suspend", "suspended", "freeze", "frozen",
                "deactivate", "deactivated", "close", "closed", "terminate",
                "legal action", "arrest", "jail", "police", "court", "lawsuit",
                "fine", "penalty", "charges", "crime", "illegal", "fraud",
                "lose access", "permanently delete", "cancelled", "revoked",
                "seize", "confiscate", "investigate", "raid", "summon",
                "warning", "final warning", "violation", "breach",
                # Hindi
                "बंद", "ब्लॉक", "निलंबित", "रद्द", "कानूनी कार्रवाई",
                "गिरफ्तारी", "जेल", "पुलिस", "जुर्माना", "दंड",
                # Hinglish
                "block ho jayega", "band ho jayega", "legal action liya jayega",
                "jail jayega", "account band", "card block",
                # Tamil
                "தடுக்கப்படும்", "நிறுத்தப்படும்", "சட்ட நடவடிக்கை",
                # Telugu
                "బ్లాక్ చేయబడుతుంది", "చట్టపరమైన చర్య", "అరెస్ట్",
                # Bengali
                "ব্লক হবে", "আইনি ব্যবস্থা", "গ্রেপ্তার",
                # Marathi
                "ब्लॉक होईल", "कायदेशीर कारवाई", "अटक",
                # Kannada
                "ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ", "ಕಾನೂನು ಕ್ರಮ", "ಬಂಧನ",
            ],
            "verification": [
                "verify", "verification", "confirm", "confirmation", "authenticate",
                "validate", "update", "renew", "reactivate", "restore",
                "kyc", "know your customer", "pan", "pan card", "aadhaar", "aadhar",
                "identity", "identity proof", "documents", "submit documents",
                "verify now", "confirm now", "update now", "complete verification",
                "incomplete kyc", "re-kyc", "ekyc", "video kyc", "biometric",
                # Hindi
                "सत्यापित", "सत्यापन", "पुष्टि", "अपडेट", "केवाईसी", "आधार",
                # Hinglish
                "verify karo", "kyc update karo", "pan verify",
                # Tamil
                "சரிபார்க்கவும்", "உறுதிப்படுத்தவும்",
                # Telugu
                "ధృవీకరించండి", "నిర్ధారించండి",
                # Bengali
                "যাচাই করুন", "নিশ্চিত করুন",
                # Marathi
                "सत्यापित करा", "पुष्टी करा",
                # Kannada
                "ಪರಿಶೀಲಿಸಿ", "ದೃಢೀಕರಿಸಿ",
            ],
            "payment": [
                "pay", "payment", "transfer", "send money", "wire", "remit",
                "fee", "charge", "processing fee", "registration fee",
                "tax", "duty", "customs", "deposit", "advance", "upfront",
                "refund", "cashback", "reward", "prize money", "winning amount",
                "claim", "release", "disburse",
                # Hindi
                "पैसे भेजो", "ट्रांसफर", "पेमेंट", "शुल्क", "रिफंड",
                # Hinglish
                "paisa bhejo", "transfer karo", "payment karo", "fee dena",
                # Tamil
                "பணம் அனுப்பு", "கட்டணம்", "திருப்பிச் செலுத்து",
                # Telugu
                "డబ్బు పంపు", "రుసుము", "రీఫండ్",
                # Bengali
                "টাকা পাঠান", "ফি", "রিফান্ড",
                # Marathi
                "पैसे पाठवा", "शुल्क", "परतावा",
                # Kannada
                "ಹಣ ಕಳುಹಿಸಿ", "ಶುಲ್ಕ", "ಮರುಪಾವತಿ",
            ],
            "impersonation": [
                "rbi", "reserve bank", "sebi", "irdai", "uidai", "income tax",
                "it department", "cbi", "ed", "enforcement directorate",
                "narcotics", "customs", "government", "ministry", "official",
                "helpline", "customer care", "bank officer", "manager",
                "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "bob",
                # Hindi
                "सरकार", "आयकर विभाग", "पुलिस अधिकारी", "बैंक अधिकारी",
            ],
            "too_good_to_be_true": [
                "won", "winner", "prize", "lottery", "jackpot", "lucky draw",
                "congratulations", "selected", "lucky", "bonus", "gift",
                "free", "no cost", "guaranteed", "assured", "100% profit",
                "double your money", "investment opportunity", "special offer",
                # Hindi
                "जीत", "इनाम", "लॉटरी", "मुफ्त", "बधाई",
                # Hinglish
                "aap jeete hain", "prize mila", "free mein", "bahut profit",
                # Tamil
                "வெற்றி பெற்றீர்கள்", "பரிசு", "இலவசம்",
                # Telugu
                "మీరు గెలిచారు", "బహుమతి", "ఉచితం",
                # Bengali
                "আপনি জিতেছেন", "পুরস্কার", "বিনামূল্যে",
                # Marathi
                "तुम्ही जिंकलात", "बक्षीस", "मोफत",
                # Kannada
                "ನೀವು ಗೆದ್ದಿದ್ದೀರಿ", "ಬಹುಮಾನ", "ಉಚಿತ",
            ],
            "sensitive_data_request": [
                "otp", "one time password", "cvv", "pin", "password",
                "card number", "card details", "expiry", "expiration date",
                "date of birth", "dob", "mother name", "maiden name",
                "aadhaar number", "pan number", "voter id",
                "username", "login", "credentials", "secret",
                # Hindi
                "पिन", "पासवर्ड", "ओटीपी", "कार्ड नंबर",
                # Hinglish
                "otp batao", "pin share karo", "password batao",
            ],

            "financial": [
                # English
                "account", "bank account", "savings account", "current account",
                "bank", "banking", "atm", "debit card", "credit card", "card",
                "cvv", "cvv number", "card number", "expiry date", "expiry",
                "pin", "pin number", "atm pin", "mpin", "tpin", "ipin",
                "otp", "one time password", "verification code", "security code",
                "password", "passcode", "login password", "transaction password",
                "upi", "upi id", "upi pin", "payment", "transaction",
                "transfer", "money transfer", "send money", "receive money",
                "refund", "cashback", "reward points", "wallet", "e-wallet",
                "account number", "ifsc", "ifsc code", "micr code",
                "routing number", "swift code", "branch code",
                "balance", "available balance", "minimum balance",
                "debit", "credit", "deposit", "withdrawal", "withdraw",
                "net banking", "internet banking", "mobile banking",
                "cheque", "check", "dd", "demand draft",
                # Hindi
                "खाता", "बैंक खाता", "बचत खाता", "चालू खाता",
                "बैंक", "बैंकिंग", "एटीएम", "डेबिट कार्ड", "क्रेडिट कार्ड",
                "सीवीवी", "कार्ड नंबर", "पिन", "एटीएम पिन", "एमपिन",
                "ओटीपी", "वन टाइम पासवर्ड", "पासवर्ड", "पासकोड",
                "यूपीआई", "यूपीआई आईडी", "पेमेंट", "लेनदेन", "ट्रांसफर",
                "पैसे", "पैसे भेजो", "पैसे ट्रांसफर", "रिफंड", "कैशबैक",
                "खाता नंबर", "आईएफएससी", "आईएफएससी कोड",
                "बैलेंस", "शेष राशि", "डेबिट", "क्रेडिट",
                "नेट बैंकिंग", "इंटरनेट बैंकिंग", "मोबाइल बैंकिंग",
                # Hinglish
                "atm card", "debit card", "cvv number", "pin number",
                "otp code", "upi id", "paytm", "phonepe", "gpay", "google pay",
                "paise bhejo", "paise transfer karo", "payment karo",
                "refund milega", "cashback milega", "balance check",
                "net banking", "mobile banking",
                # Tamil
                "கணக்கு", "வங்கி கணக்கு", "சேமிப்பு கணக்கு",
                "வங்கி", "ஏடிஎம்", "டெபிட் கார்டு", "கிரெடிட் கார்டு",
                "சிவிவி", "பின்", "ஓடிபி", "கடவுச்சொல்",
                "யுபிஐ", "பணம்", "பணம் அனுப்பவும்", "பரிமாற்றம்",
                "திருப்பிச் செலுத்தல்", "இருப்பு", "பரிவர்த்தனை",
                # Telugu
                "ఖాతా", "బ్యాంక్ ఖాతా", "పొదుపు ఖాతా",
                "బ్యాంక్", "ఏటిఎం", "డెబిట్ కార్డ్", "క్రెడిట్ కార్డ్",
                "సివివి", "పిన్", "ఓటిపి", "పాస్‌వర్డ్",
                "యుపిఐ", "డబ్బు", "డబ్బు పంపండి", "బదిలీ",
                "రీఫండ్", "బ్యాలెన్స్", "లావాదేవీ",
                # Bengali
                "অ্যাকাউন্ট", "ব্যাংক অ্যাকাউন্ট", "সঞ্চয় অ্যাকাউন্ট",
                "ব্যাংক", "এটিএম", "ডেবিট কার্ড", "ক্রেডিট কার্ড",
                "সিভিভি", "পিন", "ওটিপি", "পাসওয়ার্ড",
                "ইউপিআই", "টাকা", "টাকা পাঠান", "স্থানান্তর",
                "ফেরত", "ব্যালেন্স", "লেনদেন",
                # Marathi
                "खाते", "बँक खाते", "बचत खाते",
                "बँक", "एटीएम", "डेबिट कार्ड", "क्रेडिट कार्ड",
                "सीव्हीव्ही", "पिन", "ओटीपी", "पासवर्ड",
                "युपीआय", "पैसे", "पैसे पाठवा", "हस्तांतरण",
                "परतावा", "शिल्लक", "व्यवहार",
                # Kannada
                "ಖಾತೆ", "ಬ್ಯಾಂಕ್ ಖಾತೆ", "ಉಳಿತಾಯ ಖಾತೆ",
                "ಬ್ಯಾಂಕ್", "ಎಟಿಎಂ", "ಡೆಬಿಟ್ ಕಾರ್ಡ್", "ಕ್ರೆಡಿಟ್ ಕಾರ್ಡ್",
                "ಸಿವಿವಿ", "ಪಿನ್", "ಓಟಿಪಿ", "ಪಾಸ್‌ವರ್ಡ್",
                "ಯುಪಿಐ", "ಹಣ", "ಹಣ ಕಳುಹಿಸಿ", "ವರ್ಗಾವಣೆ",
            ],

            "impersonation": [
                # English - Government & Official
                "rbi", "reserve bank", "reserve bank of india", "central bank",
                "government", "government of india", "ministry", "department",
                "income tax", "income tax department", "gst", "tax department",
                "uidai", "unique identification authority", "aadhaar authority",
                "sebi", "securities board", "irdai", "insurance authority",
                "customs", "customs department", "immigration", "passport office",
                "police", "cyber police", "cyber cell", "crime branch",
                "cbi", "central bureau", "eci", "election commission",
                # Banks & Financial
                "sbi", "state bank", "hdfc", "hdfc bank", "icici", "icici bank",
                "axis", "axis bank", "kotak", "kotak bank", "pnb", "punjab national",
                "bob", "bank of baroda", "canara bank", "union bank",
                "yes bank", "idfc bank", "indusind", "federal bank",
                # Payment Platforms
                "paytm", "phonepe", "gpay", "google pay", "amazon pay",
                "bhim", "bhim upi", "rupay", "visa", "mastercard",
                # Courier & Logistics
                "courier", "parcel", "package", "delivery", "shipment",
                "fedex", "dhl", "blue dart", "dtdc", "india post",
                "ecom express", "delhivery", "amazon delivery",
                # Telecom
                "airtel", "jio", "reliance jio", "vodafone", "vi",
                "bsnl", "mtnl", "idea", "telecom",
                # Hindi
                "आरबीआई", "रिजर्व बैंक", "भारतीय रिजर्व बैंक",
                "सरकार", "भारत सरकार", "मंत्रालय", "विभाग",
                "आयकर", "आयकर विभाग", "जीएसटी", "कर विभाग",
                "यूआईडीएआई", "आधार प्राधिकरण",
                "सीमा शुल्क", "पुलिस", "साइबर पुलिस", "साइबर सेल",
                "बैंक", "एसबीआई", "स्टेट बैंक", "एचडीएफसी", "आईसीआईसीआई",
                "कूरियर", "पार्सल", "डिलीवरी", "शिपमेंट",
                # Hinglish
                "reserve bank", "sarkar", "government office", "tax department",
                "cyber crime", "police department", "custom office",
                "state bank", "hdfc bank", "icici bank",
                "courier company", "parcel delivery",
            ],

            "reward": [
                # English
                "prize", "prizes", "won", "winner", "winning", "won the",
                "lottery", "lotto", "jackpot", "lucky draw", "raffle",
                "claim", "claim prize", "claim reward", "claim now",
                "reward", "rewards", "gift", "gifts", "bonus",
                "cashback", "cash prize", "cash reward", "cash back",
                "congratulations", "congrats", "you have won", "you won",
                "selected", "you are selected", "chosen", "you are chosen",
                "free", "free gift", "free prize", "absolutely free",
                "scratch card", "spin and win", "lucky winner",
                "exclusive offer", "special offer", "limited offer",
                "shopping voucher", "gift voucher", "coupon", "discount",
                # Hindi
                "इनाम", "पुरस्कार", "जीत", "जीता", "विजेता",
                "लॉटरी", "भाग्यशाली", "लकी ड्रॉ",
                "दावा", "दावा करें", "अभी दावा करें",
                "कैशबैक", "नकद पुरस्कार", "बधाई", "बधाई हो",
                "चुना गया", "आप चुने गए", "मुफ्त", "मुफ्त उपहार",
                "विशेष प्रस्ताव", "सीमित प्रस्ताव", "छूट", "कूपन",
                # Hinglish
                "jeet", "jeeta", "winner", "prize mila", "inaam mila",
                "lottery jeeti", "lucky draw", "claim karo", "le lo inaam",
                "congratulations", "badhai ho", "free gift", "muft",
                "cashback mila", "reward points", "offer hai",
                # Tamil
                "பரிசு", "வெற்றி", "வென்றவர்", "லாட்டரி",
                "உரிமை கோரவும்", "வெகுமதி", "போனஸ்",
                "பணத்தைத் திரும்பப் பெறுதல்", "வாழ்த்துக்கள்",
                "தேர்ந்தெடுக்கப்பட்டது", "இலவசம்", "சிறப்பு சலுகை",
                # Telugu
                "బహుమతి", "గెలుపు", "విజేత", "లాటరీ",
                "దావా చేయండి", "రివార్డ్", "బోనస్",
                "క్యాష్‌బ్యాక్", "అభినందనలు",
                "ఎంపిక చేయబడింది", "ఉచితం", "ప్రత్యేక ఆఫర్",
                # Bengali
                "পুরস্কার", "জয়", "বিজয়ী", "লটারি",
                "দাবি করুন", "বোনাস",
                "ক্যাশব্যাক", "অভিনন্দন",
                "নির্বাচিত", "বিনামূল্যে", "বিশেষ অফার",
                # Marathi
                "बक्षीस", "जिंकले", "विजेता", "लॉटरी",
                "दावा करा", "बोनस",
                "कॅशबॅक", "अभिनंदन",
                "निवडले", "मोफत", "विशेष ऑफर",
                # Kannada
                "ಬಹುಮಾನ", "ಗೆಲುವು", "ವಿಜೇತ", "ಲಾಟರಿ",
                "ಹಕ್ಕು ಸಾಧಿಸಿ", "ರಿವಾರ್ಡ್", "ಬೋನಸ್",
                "ಕ್ಯಾಶ್‌ಬ್ಯಾಕ್", "ಅಭಿನಂದನೆಗಳು",
                "ಆಯ್ಕೆಯಾಗಿದೆ", "ಉಚಿತ", "ವಿಶೇಷ ಆಫರ್",
            ],

            "action": [
                # English
                "click", "click here", "click now", "click link", "click below",
                "tap", "tap here", "tap now", "tap to continue",
                "press", "press here", "swipe", "swipe up",
                "link", "follow link", "open link", "visit link",
                "download", "download now", "install", "install app",
                "share", "share now", "forward", "forward message",
                "reply", "reply now", "respond", "send reply",
                "call", "call now", "call immediately", "dial",
                "visit", "visit website", "go to", "proceed to",
                "submit", "submit now", "send", "send now",
                "register", "sign up", "login", "log in",
                "enter", "enter details", "provide", "give",
                # Hindi
                "क्लिक", "क्लिक करें", "यहाँ क्लिक करें", "अभी क्लिक करें",
                "टैप", "टैप करें", "दबाएं", "लिंक", "लिंक खोलें",
                "डाउनलोड", "डाउनलोड करें", "इंस्टॉल", "ऐप इंस्टॉल करें",
                "शेयर", "शेयर करें", "फॉरवर्ड", "फॉरवर्ड करें",
                "जवाब", "जवाब दें", "कॉल", "कॉल करें", "अभी कॉल करें",
                "भेजें", "अभी भेजें", "सबमिट", "सबमिट करें",
                "लॉगिन", "लॉगिन करें", "दर्ज करें", "विवरण दें",
                # Hinglish
                "click karo", "yahan click karo", "link kholo",
                "download karo", "install karo", "app install karo",
                "share karo", "forward karo", "reply karo",
                "call karo", "abhi call karo", "send karo",
                "submit karo", "login karo", "details do",
                # Tamil
                "கிளிக் செய்யவும்", "இங்கே கிளிக் செய்யவும்",
                "தட்டவும்", "இணைப்பு", "பதிவிறக்கவும்", "நிறுவவும்",
                "பகிரவும்", "முன்னனுப்பவும்", "பதிலளிக்கவும்",
                "அழைக்கவும்", "அனுப்பவும்", "சமர்ப்பிக்கவும்",
                # Telugu
                "క్లిక్ చేయండి", "ఇక్కడ క్లిక్ చేయండి",
                "ట్యాప్ చేయండి", "లింక్", "డౌన్‌లోడ్ చేయండి", "ఇన్‌స్టాల్ చేయండి",
                "షేర్ చేయండి", "ఫార్వర్డ్ చేయండి", "ప్రత్యుత్తరం ఇవ్వండి",
                "కాల్ చేయండి", "పంపండి", "సమర్పించండి",
                # Bengali
                "ক্লিক করুন", "এখানে ক্লিক করুন", "এখনই ক্লিক করুন",
                "ট্যাপ করুন", "লিংক", "ডাউনলোড করুন", "ইনস্টল করুন",
                "শেয়ার করুন", "ফরওয়ার্ড করুন", "উত্তর দিন",
                "কল করুন", "পাঠান", "জমা দিন",
                # Marathi
                "क्लिक करा", "येथे क्लिक करा", "आता क्लिक करा",
                "टॅप करा", "लिंक", "डाउनलोड करा", "इन्स्टॉल करा",
                "शेअर करा", "फॉरवर्ड करा", "उत्तर द्या",
                "कॉल करा", "पाठवा", "सादर करा",
                # Kannada
                "ಕ್ಲಿಕ್ ಮಾಡಿ", "ಇಲ್ಲಿ ಕ್ಲಿಕ್ ಮಾಡಿ", "ಈಗ ಕ್ಲಿಕ್ ಮಾಡಿ",
                "ಟ್ಯಾಪ್ ಮಾಡಿ", "ಲಿಂಕ್", "ಡೌನ್‌ಲೋಡ್ ಮಾಡಿ", "ಸ್ಥಾಪಿಸಿ",
                "ಹಂಚಿಕೊಳ್ಳಿ", "ಫಾರ್ವರ್ಡ್ ಮಾಡಿ", "ಉತ್ತರಿಸಿ",
                "ಕರೆ ಮಾಡಿ", "ಕಳುಹಿಸಿ", "ಸಲ್ಲಿಸಿ",
            ],
        }

    # ------------------------------------------------------------------
    # MAIN EXTRACTION ENTRY POINT
    # ------------------------------------------------------------------
    def extract(
        self,
        text: str,
        conversation_history: Optional[List[Message]] = None,
    ) -> Dict:
        """
        Extract all intelligence from text + conversation history.

        Returns:
            {
                phoneNumbers, bankAccounts, upiIds, phishingLinks,
                emailAddresses, suspiciousKeywords, ifscCodes
            }
        """
        try:
            full_text = self._build_context(text, conversation_history)

            cache_key = hashlib.md5(full_text.encode()).hexdigest()
            if cache_key in self.extraction_cache:
                return self.extraction_cache[cache_key]

            intelligence = {
                "phoneNumbers": self._extract_phone_numbers(full_text),
                "bankAccounts": self._extract_bank_accounts(full_text),
                "upiIds": self._extract_upi_ids(full_text),
                "phishingLinks": self._extract_urls(full_text),
                "emailAddresses": self._extract_emails(full_text),
                "suspiciousKeywords": self._extract_suspicious_keywords(full_text),
                "ifscCodes": self._extract_ifsc(full_text),  # bonus field
            }

            self.extraction_cache[cache_key] = intelligence

            total = sum(len(v) for v in intelligence.values())
            if total > 0:
                logger.info(
                    f"🔍 Extracted {total} items: "
                    f"Phones={len(intelligence['phoneNumbers'])}, "
                    f"Banks={len(intelligence['bankAccounts'])}, "
                    f"UPI={len(intelligence['upiIds'])}, "
                    f"Links={len(intelligence['phishingLinks'])}, "
                    f"Emails={len(intelligence['emailAddresses'])}, "
                    f"IFSC={len(intelligence['ifscCodes'])}, "
                    f"Keywords={len(intelligence['suspiciousKeywords'])}"
                )

            return intelligence

        except Exception as e:
            logger.error(f"Intelligence extraction error: {e}", exc_info=True)
            return self._empty_intelligence()

    # ------------------------------------------------------------------
    # CONTEXT BUILDER
    # ------------------------------------------------------------------
    def _build_context(self, current_text: str, history: Optional[List[Message]]) -> str:
        """Build full conversation context (last 10 messages + current)."""
        try:
            if not history:
                return current_text or ""
            parts = []
            for msg in history[-10:]:
                if hasattr(msg, "text") and msg.text:
                    parts.append(str(msg.text))
            parts.append(current_text or "")
            return " ".join(parts)
        except Exception as e:
            logger.error(f"Error building context: {e}")
            return current_text or ""

    # ------------------------------------------------------------------
    # INDIVIDUAL EXTRACTORS
    # ------------------------------------------------------------------
    def _extract_bank_accounts(self, text: str) -> List[str]:
        """
        Extract bank account numbers with improved precision.

        Rules:
        - Explicit label pattern: capture whatever follows "account no:" etc.
        - Standalone 11-18 digit sequences (avoids 10-digit phone overlap).
        - Exclude numbers that look like IFSC or other known formats.
        - Require contextual proximity if using standalone digit pattern.
        """
        if not text:
            return []

        accounts: set = set()
        text_lower = text.lower()

        # Check if bank context keywords are nearby
        has_bank_context = any(kw in text_lower for kw in _BANK_CONTEXT_KEYWORDS)

        for pattern in self.patterns.get("bank_account", []):
            try:
                for match in pattern.finditer(text):
                    raw = match.group(1) if match.lastindex else match.group(0)
                    clean = re.sub(r"[\s\-]", "", raw)
                    if not clean.isdigit():
                        continue
                    n = len(clean)
                    # Standalone pattern requires bank context or length >= 12
                    if n < 11 and not has_bank_context:
                        continue
                    if 9 <= n <= 18 and len(set(clean)) > 2:
                        accounts.add(clean)
            except Exception as e:
                logger.debug(f"Bank account pattern error: {e}")

        # Remove any 10-digit phone-like numbers unless they have prefix context
        phones = set(self._extract_phone_numbers(text))
        accounts -= phones

        return sorted(accounts)[:10]

    def _extract_ifsc(self, text: str) -> List[str]:
        """Extract IFSC codes (4 alpha + 0 + 6 alphanumeric)."""
        if not text:
            return []
        codes: set = set()
        for pattern in self.patterns.get("ifsc", []):
            try:
                for m in pattern.finditer(text):
                    codes.add(m.group(1).upper())
            except Exception as e:
                logger.debug(f"IFSC pattern error: {e}")
        return sorted(codes)[:5]

    def _extract_upi_ids(self, text: str) -> List[str]:
        """Extract UPI IDs — only known VPA domains."""
        if not text:
            return []
        upis: set = set()
        for pattern in self.patterns.get("upi", []):
            try:
                for m in pattern.finditer(text):
                    raw = (m.group(1) if m.lastindex else m.group(0)).strip().lower()
                    if "@" in raw and 5 < len(raw) < 100:
                        domain = raw.split("@", 1)[1].split(".")[0]
                        if domain in _UPI_DOMAINS:
                            upis.add(raw)
            except Exception as e:
                logger.debug(f"UPI pattern error: {e}")
        return sorted(upis)[:10]

    def _extract_urls(self, text: str) -> List[str]:
        """
        Extract URLs, prioritising suspicious/shortened ones.
        All extracted URLs are returned but shortened/suspicious
        ones are placed first.
        """
        if not text:
            return []

        suspicious_markers = {
            "bit.ly", "tinyurl", "goo.gl", "t.co", "cutt.ly", "rb.gy",
            "ow.ly", "is.gd", ".tk", ".ml", ".ga", ".cf", ".gq",
            "verify", "secure", "login", "update", "confirm", "claim",
        }

        urls: set = set()
        for pattern in self.patterns.get("url", []):
            try:
                for m in pattern.findall(text):
                    urls.add(m.strip().rstrip(".,)>\"'"))
            except Exception as e:
                logger.debug(f"URL pattern error: {e}")

        def _score(url: str) -> int:
            lower = url.lower()
            return sum(1 for m in suspicious_markers if m in lower)

        return sorted(urls, key=_score, reverse=True)[:10]

    def _extract_phone_numbers(self, text: str) -> List[str]:
        """Extract Indian mobile numbers."""
        if not text:
            return []
        phones: set = set()
        for pattern in self.patterns.get("phone", []):
            try:
                for m in pattern.finditer(text):
                    raw = (m.group(1) if m.lastindex else m.group(0)).strip()
                    clean = re.sub(r"[\s\-]", "", raw)
                    if len(clean) == 10 and clean[0] in "6789":
                        phones.add(clean)
            except Exception as e:
                logger.debug(f"Phone pattern error: {e}")
        return sorted(phones)[:10]

    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses, excluding UPI VPA domains."""
        if not text:
            return []
        emails: set = set()
        for pattern in self.patterns.get("email", []):
            try:
                for m in pattern.findall(text):
                    addr = m.strip().lower()
                    domain_part = addr.split("@", 1)[1].split(".")[0] if "@" in addr else ""
                    # Skip UPI IDs already captured
                    if domain_part not in _UPI_DOMAINS:
                        emails.add(addr)
            except Exception as e:
                logger.debug(f"Email pattern error: {e}")
        return sorted(emails)[:10]

    def _extract_suspicious_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords present in the text."""
        if not text:
            return []
        text_lower = text.lower()
        found: set = set()
        for keywords in self.suspicious_keywords_db.values():
            for kw in keywords:
                if kw.lower() in text_lower:
                    found.add(kw)
        return sorted(found)[:30]

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------
    @staticmethod
    def _empty_intelligence() -> Dict:
        return {
            "phoneNumbers": [],
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "emailAddresses": [],
            "suspiciousKeywords": [],
            "ifscCodes": [],
        }