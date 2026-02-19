"""
Red-Flag Detection Module
Explicit identification and scoring of scam indicators
"""
import logging
from typing import Dict, List, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class RedFlagDetector:
    """
    Detects and scores explicit red flags in scam messages
    Provides detailed breakdown of suspicious indicators
    """

    def detect(
            self,
            text: str,
            intelligence: Dict,
            conversation_history: List = None
    ) -> Dict:
        """
        Alias for detect_red_flags() — matches main.py interface.
        Returns format expected by main.py:
        { count, risk_level, total_score, flags[] }
        """
        raw = self.detect_red_flags(text, intelligence, conversation_history)

        # Remap keys to match what main.py expects
        return {
            'count': raw['flag_count'],
            'risk_level': raw['risk_level'],
            'total_score': raw['total_score'],
            'flags': [
                {
                    'category': f['type'],
                    'description': f['description'],
                    'severity': f['severity'],
                    'matches': f.get('matched_indicators', [])
                }
                for f in raw['flags_detected']
            ]
        }

    def __init__(self):
        self.red_flags = self._load_red_flag_rules()
    
    def _load_red_flag_rules(self) -> Dict:
        """Load comprehensive red-flag detection rules"""
        return {
            'urgency_pressure': {
                'weight': 0.15,
                'indicators': [
                    'urgent', 'immediately', 'asap', 'right now', 'hurry',
                    'expire', 'last chance', 'final notice', 'deadline',
                    'turant', 'abhi', 'jaldi', 'तुरंत', 'अभी'
                ],
                'description': 'Creates artificial time pressure'
            },
            'threatening_language': {
                'weight': 0.20,
                'indicators': [
                    'blocked', 'suspend', 'legal action', 'arrest', 'jail',
                    'fine', 'penalty', 'court', 'police', 'seize',
                    'ब्लॉक', 'बंद', 'गिरफ्तारी', 'जुर्माना'
                ],
                'description': 'Uses threats to intimidate victim'
            },
            'requests_sensitive_info': {
                'weight': 0.25,
                'indicators': [
                    'cvv', 'pin', 'password', 'otp', 'card number',
                    'account number', 'aadhaar', 'pan', 'dob',
                    'पिन', 'पासवर्ड', 'ओटीपी'
                ],
                'description': 'Requests sensitive financial/personal data'
            },
            'suspicious_payment': {
                'weight': 0.20,
                'indicators': [
                    'send money', 'transfer', 'payment', 'fee', 'charge',
                    'refund', 'cashback', 'reward', 'claim',
                    'पैसे भेजो', 'ट्रांसफर', 'पेमेंट'
                ],
                'description': 'Requests unusual payment or transfer'
            },
            'impersonation': {
                'weight': 0.20,
                'indicators': [
                    'bank', 'rbi', 'government', 'police', 'official',
                    'sbi', 'hdfc', 'icici', 'income tax', 'uidai',
                    'बैंक', 'सरकार', 'पुलिस'
                ],
                'description': 'Impersonates official organization'
            },
            'too_good_to_be_true': {
                'weight': 0.15,
                'indicators': [
                    'won', 'winner', 'prize', 'lottery', 'jackpot',
                    'free', 'congratulations', 'selected', 'lucky',
                    'जीत', 'इनाम', 'लॉटरी', 'मुफ्त'
                ],
                'description': 'Offers unrealistic rewards/prizes'
            },
            'suspicious_link': {
                'weight': 0.20,
                'indicators': [
                    'click here', 'click link', 'visit', 'download',
                    'bit.ly', 'tinyurl', 'shortened', 'suspicious domain'
                ],
                'description': 'Contains suspicious or shortened links'
            },
            'grammar_errors': {
                'weight': 0.10,
                'indicators': [
                    'multiple spelling errors', 'poor grammar',
                    'excessive caps', 'random numbers'
                ],
                'description': 'Poor language quality indicating fraud'
            },
            'unsolicited_contact': {
                'weight': 0.15,
                'indicators': [
                    'you have been selected', 'your account',
                    'we noticed', 'action required', 'verify now'
                ],
                'description': 'Unsolicited outreach claiming issues'
            },
            'requests_secrecy': {
                'weight': 0.15,
                'indicators': [
                    'don\'t tell', 'keep secret', 'confidential',
                    'don\'t share', 'between us', 'private'
                ],
                'description': 'Requests victim keep interaction secret'
            }
        }
    
    def detect_red_flags(
        self, 
        text: str, 
        intelligence: Dict,
        conversation_history: List = None
    ) -> Dict:
        """
        Detect all red flags in message
        
        Returns:
            {
                'total_score': float,
                'risk_level': str,
                'flags_detected': List[Dict],
                'flag_count': int,
                'recommendations': List[str]
            }
        """
        try:
            if not text:
                return self._empty_result()
            
            text_lower = text.lower()
            detected_flags = []
            total_score = 0.0
            
            # Check each red flag category
            for flag_type, rules in self.red_flags.items():
                matches = []
                
                for indicator in rules['indicators']:
                    if indicator.lower() in text_lower:
                        matches.append(indicator)
                
                if matches:
                    flag_score = rules['weight']
                    total_score += flag_score
                    
                    detected_flags.append({
                        'type': flag_type,
                        'severity': self._get_severity(flag_score),
                        'score': flag_score,
                        'description': rules['description'],
                        'matched_indicators': matches[:5],  # Top 5
                        'count': len(matches)
                    })
            
            # Check for intelligence-based red flags
            intel_flags = self._check_intelligence_red_flags(intelligence)
            detected_flags.extend(intel_flags)
            total_score += sum(f['score'] for f in intel_flags)
            
            # Check conversation pattern flags
            if conversation_history:
                pattern_flags = self._check_conversation_patterns(
                    text, 
                    conversation_history
                )
                detected_flags.extend(pattern_flags)
                total_score += sum(f['score'] for f in pattern_flags)
            
            # Cap at 1.0
            total_score = min(total_score, 1.0)
            
            # Determine risk level
            risk_level = self._get_risk_level(total_score)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                detected_flags, 
                risk_level
            )
            
            result = {
                'total_score': round(total_score, 3),
                'risk_level': risk_level,
                'flags_detected': detected_flags,
                'flag_count': len(detected_flags),
                'recommendations': recommendations
            }
            
            # Log red flags
            if detected_flags:
                logger.info(
                    f"🚩 {len(detected_flags)} red flags detected "
                    f"(Risk: {risk_level}, Score: {total_score:.2%})"
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Red flag detection error: {e}", exc_info=True)
            return self._empty_result()
    
    def _check_intelligence_red_flags(self, intelligence: Dict) -> List[Dict]:
        """Check for red flags based on extracted intelligence"""
        flags = []
        
        try:
            # Multiple payment methods = suspicious
            payment_methods = 0
            if intelligence.get('bankAccounts'):
                payment_methods += 1
            if intelligence.get('upiIds'):
                payment_methods += 1
            
            if payment_methods >= 2:
                flags.append({
                    'type': 'multiple_payment_methods',
                    'severity': 'HIGH',
                    'score': 0.20,
                    'description': 'Requests multiple payment methods',
                    'matched_indicators': ['bank_and_upi'],
                    'count': payment_methods
                })
            
            # Suspicious link patterns
            if intelligence.get('phishingLinks'):
                links = intelligence['phishingLinks']
                suspicious_patterns = [
                    'bit.ly', 'tinyurl', 'goo.gl', 't.co',
                    'cutt.ly', '.tk', '.ml', '.ga'
                ]
                
                suspicious_links = [
                    link for link in links
                    if any(pattern in link.lower() for pattern in suspicious_patterns)
                ]
                
                if suspicious_links:
                    flags.append({
                        'type': 'url_shortener_detected',
                        'severity': 'HIGH',
                        'score': 0.25,
                        'description': 'Uses URL shorteners to hide destination',
                        'matched_indicators': suspicious_links[:3],
                        'count': len(suspicious_links)
                    })
            
            # Too many phone numbers
            if intelligence.get('phoneNumbers') and len(intelligence['phoneNumbers']) > 2:
                flags.append({
                    'type': 'multiple_phone_numbers',
                    'severity': 'MEDIUM',
                    'score': 0.15,
                    'description': 'Provides multiple contact numbers',
                    'matched_indicators': intelligence['phoneNumbers'][:2],
                    'count': len(intelligence['phoneNumbers'])
                })
            
        except Exception as e:
            logger.error(f"Intelligence red flag check error: {e}")
        
        return flags
    
    def _check_conversation_patterns(
        self, 
        current_message: str,
        history: List
    ) -> List[Dict]:
        """Check for suspicious conversation patterns"""
        flags = []
        
        try:
            if not history or len(history) < 2:
                return flags
            
            # Helper: works for both Message objects and plain dicts
            def _get_text(msg) -> str:
                if isinstance(msg, dict):
                    return str(msg.get('text', '')).lower()
                return str(getattr(msg, 'text', '')).lower()

            # Rapid escalation check
            urgency_count = sum(
                1 for msg in history
                if any(word in _get_text(msg)
                      for word in ['urgent', 'immediately', 'now', 'hurry'])
            )

            if urgency_count >= 2:
                flags.append({
                    'type': 'escalating_urgency',
                    'severity': 'HIGH',
                    'score': 0.20,
                    'description': 'Repeatedly emphasizes urgency',
                    'matched_indicators': ['multiple_urgent_messages'],
                    'count': urgency_count
                })

            # Inconsistent story
            if len(history) >= 4:
                # Check if details change across messages
                first_msg = _get_text(history[0])
                recent_msgs = [_get_text(msg) for msg in history[-3:]]

                # Simple inconsistency check (can be enhanced)
                if 'bank' in first_msg and 'upi' in ' '.join(recent_msgs):
                    flags.append({
                        'type': 'inconsistent_narrative',
                        'severity': 'MEDIUM',
                        'score': 0.15,
                        'description': 'Story or details change across messages',
                        'matched_indicators': ['narrative_shift'],
                        'count': 1
                    })

        except Exception as e:
            logger.error(f"Pattern check error: {e}")

        return flags

    def _get_severity(self, score: float) -> str:
        """Get severity level from score"""
        if score >= 0.20:
            return 'CRITICAL'
        elif score >= 0.15:
            return 'HIGH'
        elif score >= 0.10:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _get_risk_level(self, score: float) -> str:
        """Determine overall risk level"""
        if score >= 0.70:
            return 'CRITICAL'
        elif score >= 0.55:
            return 'HIGH'
        elif score >= 0.40:
            return 'MEDIUM'
        elif score >= 0.25:
            return 'LOW'
        else:
            return 'MINIMAL'

    def _generate_recommendations(
        self,
        flags: List[Dict],
        risk_level: str
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        try:
            if risk_level in ['CRITICAL', 'HIGH']:
                recommendations.append(
                    "Do NOT proceed with any payment or information sharing"
                )
                recommendations.append(
                    "Report this message to cyber crime authorities"
                )

            # Specific recommendations based on flags
            flag_types = {f['type'] for f in flags}

            if 'requests_sensitive_info' in flag_types:
                recommendations.append(
                    "Never share CVV, PIN, OTP, or passwords via any channel"
                )

            if 'suspicious_link' in flag_types or 'url_shortener_detected' in flag_types:
                recommendations.append(
                    "Do NOT click on any links. Verify sender independently"
                )

            if 'impersonation' in flag_types:
                recommendations.append(
                    "Contact the organization directly using official channels"
                )

            if 'too_good_to_be_true' in flag_types:
                recommendations.append(
                    "Verify lottery/prize claims through official sources"
                )

            if not recommendations:
                recommendations.append(
                    "Verify sender identity before taking any action"
                )

        except Exception as e:
            logger.error(f"Recommendation generation error: {e}")

        return recommendations[:5]  # Top 5 recommendations

    def _empty_result(self) -> Dict:
        """Return empty result structure"""
        return {
            'total_score': 0.0,
            'risk_level': 'MINIMAL',
            'flags_detected': [],
            'flag_count': 0,
            'recommendations': []
        }