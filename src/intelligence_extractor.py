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
        """
        Load comprehensive suspicious keyword database

        Supports 6+ languages:
        - English
        - Hindi (हिंदी)
        - Hinglish (Roman Hindi)
        - Tamil (தமிழ்)
        - Telugu (తెలుగు)
        - Bengali (বাংলা)
        - Marathi (मराठी)
        - Kannada (ಕನ್ನಡ)

        200+ keywords across 7 threat categories
        """
        return {
            'urgency': [
                # English
                'urgent', 'urgently', 'immediately', 'asap', 'right now', 'now',
                'quick', 'quickly', 'fast', 'hurry', 'rush', 'instant',
                'expire', 'expires', 'expiring', 'expired', 'expiration',
                'deadline', 'last chance', 'final notice', 'time sensitive',
                'limited time', 'act now', 'dont delay', 'before its too late',

                # Hindi (हिंदी)
                'तुरंत', 'अभी', 'जल्दी', 'शीघ्र', 'फौरन', 'तत्काल',
                'जल्दी करो', 'देर मत करो', 'समय नहीं', 'आखिरी मौका',

                # Hinglish
                'turant', 'abhi', 'jaldi', 'jaldi karo', 'der mat karo',
                'time nahi hai', 'last chance', 'abhi ke abhi',

                # Tamil (தமிழ்)
                'உடனடியாக', 'விரைவாக', 'இப்போதே', 'தாமதம் வேண்டாம்',
                'கடைசி வாய்ப்பு', 'நேரம் இல்லை',

                # Telugu (తెలుగు)
                'వెంటనే', 'త్వరగా', 'ఇప్పుడే', 'ఆలస్యం చేయకండి',
                'చివరి అవకాశం', 'సమయం లేదు',

                # Bengali (বাংলা)
                'তাড়াতাড়ি', 'এখনই', 'দ্রুত', 'দেরি করবেন না',
                'শেষ সুযোগ', 'সময় নেই',

                # Marathi (मराठी)
                'तातडीने', 'लगेच', 'आत्ताच', 'उशीर करू नका',
                'शेवटची संधी', 'वेळ नाही',

                # Kannada (ಕನ್ನಡ)
                'ತಕ್ಷಣ', 'ಈಗಲೇ', 'ಬೇಗ', 'ತಡಮಾಡಬೇಡಿ',
                'ಕೊನೆಯ ಅವಕಾಶ',
            ],

            'threat': [
                # English
                'blocked', 'block', 'suspend', 'suspended', 'freeze', 'frozen',
                'deactivate', 'deactivated', 'close', 'closed', 'terminate',
                'legal action', 'arrest', 'jail', 'police', 'court', 'lawsuit',
                'fine', 'penalty', 'charges', 'crime', 'illegal', 'fraud',
                'lose access', 'permanently delete', 'cancelled', 'revoked',
                'seize', 'confiscate', 'investigate', 'raid', 'summon',
                'warning', 'final warning', 'violation', 'breach',

                # Hindi (हिंदी)
                'बंद', 'ब्लॉक', 'निलंबित', 'रद्द', 'समाप्त',
                'कानूनी कार्रवाई', 'गिरफ्तारी', 'जेल', 'पुलिस', 'अदालत',
                'जुर्माना', 'दंड', 'आरोप', 'अपराध', 'गैरकानूनी',
                'जब्त', 'छापा', 'चेतावनी', 'उल्लंघन',

                # Hinglish
                'block ho jayega', 'band ho jayega', 'suspend ho jayega',
                'legal action liya jayega', 'police case hoga', 'jail jayega',
                'fine lagega', 'account band', 'card block',

                # Tamil (தமிழ்)
                'தடுக்கப்படும்', 'நிறுத்தப்படும்', 'ரத்து செய்யப்படும்',
                'சட்ட நடவடிக்கை', 'கைது', 'காவல்துறை', 'நீதிமன்றம்',
                'அபராதம்', 'குற்றம்', 'சட்டவிரோதம்',

                # Telugu (తెలుగు)
                'బ్లాక్ చేయబడుతుంది', 'నిలిపివేయబడుతుంది', 'రద్దు చేయబడుతుంది',
                'చట్టపరమైన చర్య', 'అరెస్ట్', 'పోలీసు', 'కోర్టు',
                'జరిమానా', 'నేరం', 'చట్టవిరుద్ధం',

                # Bengali (বাংলা)
                'ব্লক হবে', 'স্থগিত হবে', 'বন্ধ হবে', 'বাতিল হবে',
                'আইনি ব্যবস্থা', 'গ্রেপ্তার', 'পুলিশ', 'আদালত',
                'জরিমানা', 'অপরাধ', 'অবৈধ',

                # Marathi (मराठी)
                'ब्लॉक होईल', 'बंद होईल', 'निलंबित होईल', 'रद्द होईल',
                'कायदेशीर कारवाई', 'अटक', 'पोलीस', 'न्यायालय',
                'दंड', 'गुन्हा', 'बेकायदेशीर',

                # Kannada (ಕನ್ನಡ)
                'ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ', 'ಸ್ಥಗಿತಗೊಳಿಸಲಾಗುತ್ತದೆ', 'ರದ್ದುಗೊಳಿಸಲಾಗುತ್ತದೆ',
                'ಕಾನೂನು ಕ್ರಮ', 'ಬಂಧನ', 'ಪೊಲೀಸ್', 'ನ್ಯಾಯಾಲಯ',
            ],

            'verification': [
                # English
                'verify', 'verification', 'confirm', 'confirmation', 'authenticate',
                'validate', 'update', 'renew', 'reactivate', 'restore',
                'kyc', 'know your customer', 'pan', 'pan card', 'aadhaar', 'aadhar',
                'identity', 'identity proof', 'documents', 'submit documents',
                'verify now', 'confirm now', 'update now', 'verify immediately',
                'complete verification', 'pending verification', 'failed verification',
                'incomplete kyc', 're-kyc', 'ekyc', 'video kyc',
                'biometric', 'fingerprint', 'face verification',

                # Hindi (हिंदी)
                'सत्यापित', 'सत्यापन', 'पुष्टि', 'अपडेट', 'नवीनीकरण',
                'केवाईसी', 'पैन कार्ड', 'आधार', 'आधार कार्ड',
                'पहचान', 'पहचान प्रमाण', 'दस्तावेज', 'सबमिट करें',
                'अभी सत्यापित करें', 'अभी पुष्टि करें', 'अभी अपडेट करें',
                'अधूरा केवाईसी', 'सत्यापन लंबित', 'बायोमेट्रिक',

                # Hinglish
                'verify karo', 'confirm karo', 'update karo', 'kyc complete karo',
                'pan update', 'aadhaar link', 'documents submit karo',
                'verification pending', 'rekyc karna hai', 'ekyc karo',

                # Tamil (தமிழ்)
                'சரிபார்க்கவும்', 'உறுதிப்படுத்தவும்', 'புதுப்பிக்கவும்',
                'கேவைசி', 'பான் கார்டு', 'ஆதார்', 'அடையாள சான்று',
                'ஆவணங்கள்', 'சமர்ப்பிக்கவும்', 'இப்போது சரிபார்க்கவும்',

                # Telugu (తెలుగు)
                'ధృవీకరించండి', 'నిర్ధారించండి', 'నవీకరించండి',
                'కేవైసీ', 'పాన్ కార్డ్', 'ఆధార్', 'గుర్తింపు రుజువు',
                'పత్రాలు', 'సమర్పించండి', 'ఇప్పుడు ధృవీకరించండి',

                # Bengali (বাংলা)
                'যাচাই করুন', 'নিশ্চিত করুন', 'আপডেট করুন',
                'কেওয়াইসি', 'প্যান কার্ড', 'আধার', 'পরিচয় প্রমাণ',
                'নথিপত্র', 'জমা দিন', 'এখনই যাচাই করুন',

                # Marathi (मराठी)
                'सत्यापित करा', 'पुष्टी करा', 'अद्यतनित करा',
                'केवायसी', 'पॅन कार्ड', 'आधार', 'ओळख पुरावा',
                'कागदपत्रे', 'सादर करा', 'आता सत्यापित करा',

                # Kannada (ಕನ್ನಡ)
                'ಪರಿಶೀಲಿಸಿ', 'ದೃಢೀಕರಿಸಿ', 'ನವೀಕರಿಸಿ',
                'ಕೆವೈಸಿ', 'ಪ್ಯಾನ್ ಕಾರ್ಡ್', 'ಆಧಾರ್', 'ಗುರುತಿನ ಪುರಾವೆ',
            ],

            'financial': [
                # English
                'account', 'bank account', 'savings account', 'current account',
                'bank', 'banking', 'atm', 'debit card', 'credit card', 'card',
                'cvv', 'cvv number', 'card number', 'expiry date', 'expiry',
                'pin', 'pin number', 'atm pin', 'mpin', 'tpin', 'ipin',
                'otp', 'one time password', 'verification code', 'security code',
                'password', 'passcode', 'login password', 'transaction password',
                'upi', 'upi id', 'upi pin', 'payment', 'transaction',
                'transfer', 'money transfer', 'send money', 'receive money',
                'refund', 'cashback', 'reward points', 'wallet', 'e-wallet',
                'account number', 'ifsc', 'ifsc code', 'micr code',
                'routing number', 'swift code', 'branch code',
                'balance', 'available balance', 'minimum balance',
                'debit', 'credit', 'deposit', 'withdrawal', 'withdraw',
                'net banking', 'internet banking', 'mobile banking',
                'cheque', 'check', 'dd', 'demand draft',

                # Hindi (हिंदी)
                'खाता', 'बैंक खाता', 'बचत खाता', 'चालू खाता',
                'बैंक', 'बैंकिंग', 'एटीएम', 'डेबिट कार्ड', 'क्रेडिट कार्ड',
                'सीवीवी', 'कार्ड नंबर', 'पिन', 'एटीएम पिन', 'एमपिन',
                'ओटीपी', 'वन टाइम पासवर्ड', 'पासवर्ड', 'पासकोड',
                'यूपीआई', 'यूपीआई आईडी', 'पेमेंट', 'लेनदेन', 'ट्रांसफर',
                'पैसे', 'पैसे भेजो', 'पैसे ट्रांसफर', 'रिफंड', 'कैशबैक',
                'खाता नंबर', 'आईएफएससी', 'आईएफएससी कोड',
                'बैलेंस', 'शेष राशि', 'डेबिट', 'क्रेडिट',
                'नेट बैंकिंग', 'इंटरनेट बैंकिंग', 'मोबाइल बैंकिंग',

                # Hinglish
                'account number', 'bank account', 'atm card', 'debit card',
                'cvv number', 'pin number', 'otp code', 'password',
                'upi id', 'paytm', 'phonepe', 'gpay', 'google pay',
                'paise bhejo', 'paise transfer karo', 'payment karo',
                'refund milega', 'cashback milega', 'balance check',
                'net banking', 'mobile banking',

                # Tamil (தமிழ்)
                'கணக்கு', 'வங்கி கணக்கு', 'சேமிப்பு கணக்கு',
                'வங்கி', 'ஏடிஎம்', 'டெபிட் கார்டு', 'கிரெடிட் கார்டு',
                'சிவிவி', 'பின்', 'ஓடிபி', 'கடவுச்சொல்',
                'யுபிஐ', 'பணம்', 'பணம் அனுப்பவும்', 'பரிமாற்றம்',
                'திருப்பிச் செலுத்தல்', 'இருப்பு', 'பரிவர்த்தனை',

                # Telugu (తెలుగు)
                'ఖాతా', 'బ్యాంక్ ఖాతా', 'పొదుపు ఖాతా',
                'బ్యాంక్', 'ఏటిఎం', 'డెబిట్ కార్డ్', 'క్రెడిట్ కార్డ్',
                'సివివి', 'పిన్', 'ఓటిపి', 'పాస్‌వర్డ్',
                'యుపిఐ', 'డబ్బు', 'డబ్బు పంపండి', 'బదిలీ',
                'రీఫండ్', 'బ్యాలెన్స్', 'లావాదేవీ',

                # Bengali (বাংলা)
                'অ্যাকাউন্ট', 'ব্যাংক অ্যাকাউন্ট', 'সঞ্চয় অ্যাকাউন্ট',
                'ব্যাংক', 'এটিএম', 'ডেবিট কার্ড', 'ক্রেডিট কার্ড',
                'সিভিভি', 'পিন', 'ওটিপি', 'পাসওয়ার্ড',
                'ইউপিআই', 'টাকা', 'টাকা পাঠান', 'স্থানান্তর',
                'ফেরত', 'ব্যালেন্স', 'লেনদেন',

                # Marathi (मराठी)
                'खाते', 'बँक खाते', 'बचत खाते',
                'बँक', 'एटीएम', 'डेबिट कार्ड', 'क्रेडिट कार्ड',
                'सीव्हीव्ही', 'पिन', 'ओटीपी', 'पासवर्ड',
                'युपीआय', 'पैसे', 'पैसे पाठवा', 'हस्तांतरण',
                'परतावा', 'शिल्लक', 'व्यवहार',

                # Kannada (ಕನ್ನಡ)
                'ಖಾತೆ', 'ಬ್ಯಾಂಕ್ ಖಾತೆ', 'ಉಳಿತಾಯ ಖಾತೆ',
                'ಬ್ಯಾಂಕ್', 'ಎಟಿಎಂ', 'ಡೆಬಿಟ್ ಕಾರ್ಡ್', 'ಕ್ರೆಡಿಟ್ ಕಾರ್ಡ್',
                'ಸಿವಿವಿ', 'ಪಿನ್', 'ಓಟಿಪಿ', 'ಪಾಸ್‌ವರ್ಡ್',
                'ಯುಪಿಐ', 'ಹಣ', 'ಹಣ ಕಳುಹಿಸಿ', 'ವರ್ಗಾವಣೆ',
            ],

            'impersonation': [
                # English - Government & Official
                'rbi', 'reserve bank', 'reserve bank of india', 'central bank',
                'government', 'government of india', 'ministry', 'department',
                'income tax', 'income tax department', 'gst', 'tax department',
                'uidai', 'unique identification authority', 'aadhaar authority',
                'sebi', 'securities board', 'irdai', 'insurance authority',
                'customs', 'customs department', 'immigration', 'passport office',
                'police', 'cyber police', 'cyber cell', 'crime branch',
                'cbi', 'central bureau', 'eci', 'election commission',

                # Banks & Financial
                'sbi', 'state bank', 'hdfc', 'hdfc bank', 'icici', 'icici bank',
                'axis', 'axis bank', 'kotak', 'kotak bank', 'pnb', 'punjab national',
                'bob', 'bank of baroda', 'canara bank', 'union bank',
                'yes bank', 'idfc bank', 'indusind', 'federal bank',

                # Payment Platforms
                'paytm', 'phonepe', 'gpay', 'google pay', 'amazon pay',
                'bhim', 'bhim upi', 'rupay', 'visa', 'mastercard',

                # Courier & Logistics
                'courier', 'parcel', 'package', 'delivery', 'shipment',
                'fedex', 'dhl', 'blue dart', 'dtdc', 'india post',
                'ecom express', 'delhivery', 'amazon delivery',

                # Telecom
                'airtel', 'jio', 'reliance jio', 'vodafone', 'vi',
                'bsnl', 'mtnl', 'idea', 'telecom',

                # Hindi (हिंदी)
                'आरबीआई', 'रिजर्व बैंक', 'भारतीय रिजर्व बैंक',
                'सरकार', 'भारत सरकार', 'मंत्रालय', 'विभाग',
                'आयकर', 'आयकर विभाग', 'जीएसटी', 'कर विभाग',
                'यूआईडीएआई', 'आधार प्राधिकरण',
                'सीमा शुल्क', 'पुलिस', 'साइबर पुलिस', 'साइबर सेल',
                'बैंक', 'एसबीआई', 'स्टेट बैंक', 'एचडीएफसी', 'आईसीआईसीआई',
                'कूरियर', 'पार्सल', 'डिलीवरी', 'शिपमेंट',

                # Hinglish
                'reserve bank', 'sarkar', 'government office', 'tax department',
                'cyber crime', 'police department', 'custom office',
                'state bank', 'hdfc bank', 'icici bank',
                'courier company', 'parcel delivery',
            ],

            'reward': [
                # English
                'prize', 'prizes', 'won', 'winner', 'winning', 'won the',
                'lottery', 'lotto', 'jackpot', 'lucky draw', 'raffle',
                'claim', 'claim prize', 'claim reward', 'claim now',
                'reward', 'rewards', 'gift', 'gifts', 'bonus',
                'cashback', 'cash prize', 'cash reward', 'cash back',
                'congratulations', 'congrats', 'you have won', 'you won',
                'selected', 'you are selected', 'chosen', 'you are chosen',
                'free', 'free gift', 'free prize', 'absolutely free',
                'scratch card', 'spin and win', 'lucky winner',
                'exclusive offer', 'special offer', 'limited offer',
                'shopping voucher', 'gift voucher', 'coupon', 'discount',

                # Hindi (हिंदी)
                'इनाम', 'पुरस्कार', 'जीत', 'जीता', 'विजेता',
                'लॉटरी', 'भाग्यशाली', 'लकी ड्रॉ',
                'दावा', 'दावा करें', 'अभी दावा करें',
                'कैशबैक', 'नकद पुरस्कार', 'बधाई', 'बधाई हो',
                'चुना गया', 'आप चुने गए', 'मुफ्त', 'मुफ्त उपहार',
                'विशेष प्रस्ताव', 'सीमित प्रस्ताव', 'छूट', 'कूपन',

                # Hinglish
                'jeet', 'jeeta', 'winner', 'prize mila', 'inaam mila',
                'lottery jeeti', 'lucky draw', 'claim karo', 'le lo inaam',
                'congratulations', 'badhai ho', 'free gift', 'muft',
                'cashback mila', 'reward points', 'offer hai',

                # Tamil (தமிழ்)
                'பரிசு', 'வெற்றி', 'வென்றவர்', 'லாட்டரி',
                'உரிமை கோரவும்', 'வெகுமதி', 'பரிசு', 'போனஸ்',
                'பணத்தைத் திரும்பப் பெறுதல்', 'வாழ்த்துக்கள்',
                'தேர்ந்தெடுக்கப்பட்டது', 'இலவசம்', 'சிறப்பு சலுகை',

                # Telugu (తెలుగు)
                'బహుమతి', 'గెలుపు', 'విజేత', 'లాటరీ',
                'దావా చేయండి', 'రివార్డ్', 'బోనస్',
                'క్యాష్‌బ్యాక్', 'అభినందనలు',
                'ఎంపిక చేయబడింది', 'ఉచితం', 'ప్రత్యేక ఆఫర్',

                # Bengali (বাংলা)
                'পুরস্কার', 'জয়', 'বিজয়ী', 'লটারি',
                'দাবি করুন', 'পুরস্কার', 'বোনাস',
                'ক্যাশব্যাক', 'অভিনন্দন',
                'নির্বাচিত', 'বিনামূল্যে', 'বিশেষ অফার',

                # Marathi (मराठी)
                'बक्षीस', 'जिंकले', 'विजेता', 'लॉटरी',
                'दावा करा', 'बक्षीस', 'बोनस',
                'कॅशबॅक', 'अभिनंदन',
                'निवडले', 'मोफत', 'विशेष ऑफर',

                # Kannada (ಕನ್ನಡ)
                'ಬಹುಮಾನ', 'ಗೆಲುವು', 'ವಿಜೇತ', 'ಲಾಟರಿ',
                'ಹಕ್ಕು ಸಾಧಿಸಿ', 'ರಿವಾರ್ಡ್', 'ಬೋನಸ್',
                'ಕ್ಯಾಶ್‌ಬ್ಯಾಕ್', 'ಅಭಿನಂದನೆಗಳು',
                'ಆಯ್ಕೆಯಾಗಿದೆ', 'ಉಚಿತ', 'ವಿಶೇಷ ಆಫರ್',
            ],

            'action': [
                # English
                'click', 'click here', 'click now', 'click link', 'click below',
                'tap', 'tap here', 'tap now', 'tap to continue',
                'press', 'press here', 'swipe', 'swipe up',
                'link', 'follow link', 'open link', 'visit link',
                'download', 'download now', 'install', 'install app',
                'share', 'share now', 'forward', 'forward message',
                'reply', 'reply now', 'respond', 'send reply',
                'call', 'call now', 'call immediately', 'dial',
                'visit', 'visit website', 'go to', 'proceed to',
                'submit', 'submit now', 'send', 'send now',
                'register', 'sign up', 'login', 'log in',
                'enter', 'enter details', 'provide', 'give',

                # Hindi (हिंदी)
                'क्लिक', 'क्लिक करें', 'यहाँ क्लिक करें', 'अभी क्लिक करें',
                'टैप', 'टैप करें', 'दबाएं', 'लिंक', 'लिंक खोलें',
                'डाउनलोड', 'डाउनलोड करें', 'इंस्टॉल', 'ऐप इंस्टॉल करें',
                'शेयर', 'शेयर करें', 'फॉरवर्ड', 'फॉरवर्ड करें',
                'जवाब', 'जवाब दें', 'कॉल', 'कॉल करें', 'अभी कॉल करें',
                'भेजें', 'अभी भेजें', 'सबमिट', 'सबमिट करें',
                'लॉगिन', 'लॉगिन करें', 'दर्ज करें', 'विवरण दें',

                # Hinglish
                'click karo', 'yahan click karo', 'link kholo',
                'download karo', 'install karo', 'app install karo',
                'share karo', 'forward karo', 'reply karo',
                'call karo', 'abhi call karo', 'send karo',
                'submit karo', 'login karo', 'details do',

                # Tamil (தமிழ்)
                'கிளிக் செய்யவும்', 'இங்கே கிளிக் செய்யவும்', 'இப்போது கிளிக் செய்யவும்',
                'தட்டவும்', 'இணைப்பு', 'பதிவிறக்கவும்', 'நிறுவவும்',
                'பகிரவும்', 'முன்னனுப்பவும்', 'பதிலளிக்கவும்',
                'அழைக்கவும்', 'அனுப்பவும்', 'சமர்ப்பிக்கவும்',

                # Telugu (తెలుగు)
                'క్లిక్ చేయండి', 'ఇక్కడ క్లిక్ చేయండి', 'ఇప్పుడు క్లిక్ చేయండి',
                'ట్యాప్ చేయండి', 'లింక్', 'డౌన్‌లోడ్ చేయండి', 'ఇన్‌స్టాల్ చేయండి',
                'షేర్ చేయండి', 'ఫార్వర్డ్ చేయండి', 'ప్రత్యుత్తరం ఇవ్వండి',
                'కాల్ చేయండి', 'పంపండి', 'సమర్పించండి',

                # Bengali (বাংলা)
                'ক্লিক করুন', 'এখানে ক্লিক করুন', 'এখনই ক্লিক করুন',
                'ট্যাপ করুন', 'লিংক', 'ডাউনলোড করুন', 'ইনস্টল করুন',
                'শেয়ার করুন', 'ফরওয়ার্ড করুন', 'উত্তর দিন',
                'কল করুন', 'পাঠান', 'জমা দিন',

                # Marathi (मराठी)
                'क्लिक करा', 'येथे क्लिक करा', 'आता क्लिक करा',
                'टॅप करा', 'लिंक', 'डाउनलोड करा', 'इन्स्टॉल करा',
                'शेअर करा', 'फॉरवर्ड करा', 'उत्तर द्या',
                'कॉल करा', 'पाठवा', 'सादर करा',

                # Kannada (ಕನ್ನಡ)
                'ಕ್ಲಿಕ್ ಮಾಡಿ', 'ಇಲ್ಲಿ ಕ್ಲಿಕ್ ಮಾಡಿ', 'ಈಗ ಕ್ಲಿಕ್ ಮಾಡಿ',
                'ಟ್ಯಾಪ್ ಮಾಡಿ', 'ಲಿಂಕ್', 'ಡೌನ್‌ಲೋಡ್ ಮಾಡಿ', 'ಸ್ಥಾಪಿಸಿ',
                'ಹಂಚಿಕೊಳ್ಳಿ', 'ಫಾರ್ವರ್ಡ್ ಮಾಡಿ', 'ಉತ್ತರಿಸಿ',
                'ಕರೆ ಮಾಡಿ', 'ಕಳುಹಿಸಿ', 'ಸಲ್ಲಿಸಿ',
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