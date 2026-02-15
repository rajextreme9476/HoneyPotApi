"""
Callback Handler Module
Sends final results to evaluation server
"""
import json
import time
import logging
import asyncio
from typing import Dict
import requests
from .config import Config

logger = logging.getLogger(__name__)


async def send_final_callback(session_id: str, session_data: Dict) -> bool:
    """
    Send final callback with SERVER-REQUIRED format

    Based on actual server error response:
    - Needs "sessionId" field
    - Needs "totalMessagesExchanged" at ROOT level

    Args:
        session_id: Session identifier
        session_data: Session data dictionary

    Returns:
        True if callback successful, False otherwise
    """
    try:
        if not session_id or not session_data:
            logger.error("Invalid callback parameters")
            return False

        # Calculate engagement duration
        start_time = session_data.get("start_time", time.time())
        engagement_duration = int(time.time() - start_time)

        # Build SERVER-COMPLIANT payload (based on official docs)
        payload = {
            "sessionId": session_id,
            "scamDetected": session_data.get("scam_detected", False),
            "totalMessagesExchanged": session_data.get("message_count", 0),
            "extractedIntelligence": {
                "bankAccounts": session_data.get("intelligence", {}).get("bankAccounts", []),
                "upiIds": session_data.get("intelligence", {}).get("upiIds", []),
                "phishingLinks": session_data.get("intelligence", {}).get("phishingLinks", []),
                "phoneNumbers": session_data.get("intelligence", {}).get("phoneNumbers", []),
                "suspiciousKeywords": session_data.get("intelligence", {}).get("suspiciousKeywords", [])  # ✅ ADDED
            },
            "agentNotes": _build_agent_notes(session_data, engagement_duration)
        }

        # Log callback details
        logger.info(f"{'=' * 80}")
        logger.info(f"📞 SENDING CALLBACK FOR SESSION: {session_id}")
        logger.info(f"{'=' * 80}")
        logger.info(f"URL: {Config.FINAL_CALLBACK_URL}")
        logger.info(f"Payload:")
        logger.info(json.dumps(payload, indent=2))
        logger.info(f"")

        # Send with retries
        max_retries = Config.MAX_RETRIES
        for attempt in range(max_retries):
            try:
                response = await asyncio.to_thread(
                    requests.post,
                    Config.FINAL_CALLBACK_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=15
                )

                if response.status_code == 200:
                    logger.info(f"✅ Callback successful for {session_id}")
                    logger.info(f"Response: {response.text}")
                    logger.info(f"{'=' * 80}")
                    return True
                else:
                    logger.warning(
                        f"Callback returned {response.status_code}, "
                        f"attempt {attempt + 1}/{max_retries}"
                    )
                    logger.warning(f"Response: {response.text}")

            except requests.exceptions.Timeout:
                logger.warning(f"Callback timeout, attempt {attempt + 1}/{max_retries}")
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error, attempt {attempt + 1}/{max_retries}: {e}")
            except Exception as e:
                logger.error(f"Callback error, attempt {attempt + 1}/{max_retries}: {e}")

            # Exponential backoff
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.info(f"Waiting {wait_time}s before retry...")
                await asyncio.sleep(wait_time)

        logger.error(f"❌ All callback attempts failed for {session_id}")
        return False

    except Exception as e:
        logger.error(f"Fatal callback error for {session_id}: {e}", exc_info=True)
        return False


def _build_agent_notes(session_data: Dict, duration: int) -> str:
    """Build agent notes for callback"""
    try:
        scam_type = session_data.get("scam_type", "unknown")
        confidence = session_data.get("confidence_score", 0.0)
        message_count = session_data.get("message_count", 0)

        # Get intelligence counts
        intel = session_data.get("intelligence", {})
        intel_counts = []
        if intel.get("bankAccounts"):
            intel_counts.append(f"{len(intel['bankAccounts'])} bank accounts")
        if intel.get("upiIds"):
            intel_counts.append(f"{len(intel['upiIds'])} UPI IDs")
        if intel.get("phoneNumbers"):
            intel_counts.append(f"{len(intel['phoneNumbers'])} phone numbers")
        if intel.get("phishingLinks"):
            intel_counts.append(f"{len(intel['phishingLinks'])} phishing links")
        if intel.get("emailAddresses"):
            intel_counts.append(f"{len(intel['emailAddresses'])} emails")

        intel_summary = ", ".join(intel_counts) if intel_counts else "no intelligence"

        notes = (
            f"Scam type: {scam_type}. "
            f"Detection confidence: {confidence:.1%}. "
            f"Extracted: {intel_summary}. "
            f"Engagement: {message_count} messages over {duration}s."
        )

        return notes

    except Exception as e:
        logger.error(f"Error building agent notes: {e}")
        return "Scam detection completed."