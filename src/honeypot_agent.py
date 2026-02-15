"""
Honeypot Agent Module
Generates contextual responses to scammers
"""
import re
import logging
import asyncio
from typing import Dict, List, Optional
from google import genai

from .config import Config
from .intelligence_extractor import Message

logger = logging.getLogger(__name__)


class AdaptiveAgent:
    """AI-powered adaptive honeypot agent"""
    
    def __init__(self, gemini_client):
        self.client = gemini_client
        self.response_cache = {}
    
    async def generate_response(
        self,
        scammer_message: str,
        conversation_history: List[Message],
        intelligence: Dict,
        message_count: int = 1
    ) -> str:
        """
        Generate contextual agent response
        
        Args:
            scammer_message: Current scammer message
            conversation_history: Previous messages
            intelligence: Extracted intelligence
            message_count: Number of messages in session
            
        Returns:
            Agent's response string
        """
        try:
            if not scammer_message:
                return self._get_fallback_response(message_count)
            
            # Build conversation context
            conversation = self._build_conversation_context(
                conversation_history, 
                scammer_message
            )
            
            # Generate response with AI
            prompt = self._build_agent_prompt(conversation, message_count)
            
            response = await asyncio.to_thread(
                self.client.models.generate_content,
                model=Config.MODEL_NAME,
                contents=prompt
            )
            
            if not response or not response.text:
                logger.warning("Empty AI response, using fallback")
                return self._get_fallback_response(message_count)
            
            agent_reply = response.text.strip()
            
            # Clean up response
            agent_reply = re.sub(r'```.*?```', '', agent_reply, flags=re.DOTALL).strip()
            
            # Validate response doesn't break character
            if self._breaks_character(agent_reply):
                logger.warning("Agent broke character, using fallback")
                return self._get_fallback_response(message_count)
            
            # Ensure appropriate length
            if len(agent_reply) > 200:
                agent_reply = agent_reply[:197] + '...'
            
            if not agent_reply:
                return self._get_fallback_response(message_count)
            
            return agent_reply
            
        except asyncio.TimeoutError:
            logger.error("Agent generation timeout")
            return self._get_fallback_response(message_count)
        except Exception as e:
            logger.error(f"Agent generation error: {e}", exc_info=True)
            return self._get_fallback_response(message_count)
    
    def _build_conversation_context(
        self, 
        history: List[Message], 
        current: str
    ) -> str:
        """Build structured conversation context"""
        try:
            context = ""
            
            # Add last 8 messages for context
            for msg in history[-8:]:
                try:
                    if not hasattr(msg, 'sender') or not hasattr(msg, 'text'):
                        continue
                    
                    role = "Scammer" if msg.sender == "scammer" else "You"
                    text = str(msg.text)[:500]  # Limit length
                    context += f"{role}: {text}\n"
                except Exception as e:
                    logger.debug(f"Error processing history message: {e}")
                    continue
            
            context += f"Scammer: {current}\n"
            return context
            
        except Exception as e:
            logger.error(f"Error building context: {e}")
            return f"Scammer: {current}\n"
    
    def _build_agent_prompt(self, conversation: str, message_count: int) -> str:
        """Build AI prompt for agent response"""
        try:
            # Determine conversation stage
            if message_count < 3:
                stage_guidance = "Show confusion. Ask basic clarifying questions."
            elif message_count < 6:
                stage_guidance = "Show concern. Ask for more details about verification."
            else:
                stage_guidance = "Show worry. Ask specific questions about the process."
            
            prompt = f"""You are a confused person who received this message.

CRITICAL RULES:
- Keep response SHORT: 1-2 sentences max (under 25 words)
- You DON'T know this is a scam - you believe it's real
- Show emotion: confusion, worry, concern
- Ask simple, natural questions
- NEVER use these words: scam, fraud, police, fake, report, suspicious, cheat
- NEVER accuse or warn
- Sound natural and human

Stage Guidance: {stage_guidance}

Recent conversation:
{conversation}

Generate your response as a worried person who believes this message.
Your response:"""
            
            return prompt
            
        except Exception as e:
            logger.error(f"Error building prompt: {e}")
            return "You are confused. Respond briefly asking for clarification."
    
    def _breaks_character(self, response: str) -> bool:
        """Check if agent broke character"""
        try:
            if not response:
                return True
            
            forbidden = [
                'scam', 'fraud', 'police', 'fake', 'cheat', 'report',
                'suspicious', 'phishing', 'cyber', 'complaint', 'warning'
            ]
            
            response_lower = response.lower()
            return any(word in response_lower for word in forbidden)
            
        except Exception as e:
            logger.error(f"Error checking character break: {e}")
            return False
    
    def _get_fallback_response(self, message_count: int) -> str:
        """Get safe fallback response"""
        try:
            fallbacks = [
                "I'm not sure I understand. Can you explain?",
                "What do you need me to do exactly?",
                "I'm confused. Is this important?",
                "Can you tell me more about this?",
                "I'm worried. What should I do?",
                "Is everything okay with my account?",
            ]
            
            index = message_count % len(fallbacks)
            return fallbacks[index]
            
        except Exception as e:
            logger.error(f"Error getting fallback: {e}")
            return "I don't understand. Please explain."
