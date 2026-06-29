# actions/actions.py
import os
import time
import logging
from dotenv import load_dotenv
from typing import Any, Text, Dict, List

from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
from rasa_sdk.events import SlotSet

# optional: if you prefer logger instead of prints
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Load .env variables (GEMINI_API_KEY expected)
env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(dotenv_path=env_path)

print("DEBUG GEMINI KEY:", os.getenv("GEMINI_API_KEY"))

# configure google generative ai (if you use that library)
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
except Exception:
    GENAI_AVAILABLE = False
    logger.warning("google.generativeai not available or failed to import. GEMINI calls will fail until configured.")

class ActionChatGPTFallback(Action):
    def name(self) -> Text:
        return "action_chatgpt_fallback"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[Text, Any]
    ) -> List[Dict[Text, Any]]:

        user_message = tracker.latest_message.get("text", "")
        intent = tracker.latest_message.get("intent", {}).get("name", "nlu_fallback")
        last_topic = tracker.get_slot("last_topic")

        logger.info("🧠 Gemini Fallback Triggered. user: %s  intent: %s  last_topic: %s", user_message, intent, last_topic)

        # prepare events list (slot updates)
        topic_map = {
            "ask_phishing": "phishing",
            "ask_ransomware": "ransomware",
            "ask_malware": "malware",
            "ask_ddos": "ddos",
            "ask_password_safety": "password safety",
            "ask_cybercrime_reporting": "cybercrime reporting",
        }

        events = []
        if intent in topic_map:
            new_topic = topic_map[intent]
            logger.info("🔖 Setting last_topic slot -> %s", new_topic)
            events.append(SlotSet("last_topic", new_topic))

        # Reset context if user explicitly asks
        if user_message.strip().lower() in ["new chat", "restart", "start over", "clear chat"]:
            logger.info("♻️ Resetting context (new chat).")
            events.append(SlotSet("last_topic", None))
            dispatcher.utter_message(text="Got it — starting fresh. What would you like to learn about in cybersecurity?")
            return events

        # Build system prompt (keeps SentiVor voice)
        context_text = f"The user previously talked about '{last_topic}'." if last_topic else ""
        system_prompt = (
            "You are SentiVor, a concise professional cybersecurity assistant. "
            "Give a short beginner-friendly answer first (2–3 lines). If the user asks for 'detailed' or 'explain more', expand. "
            "Do not use casual greetings like 'Hey there!'. Keep responses factual and practical.\n\n"
            f"{context_text}"
        )

        # If genai lib is not available, return a safe message
        if not GENAI_AVAILABLE:
            logger.error("GenAI library not available or GEMINI_API_KEY not configured.")
            dispatcher.utter_message(text="I can't access my knowledge engine right now. Please try again shortly.")
            return events

        # Try calling Gemini (with a single retry)
        reply_text = None
        last_exception = None
        for attempt in range(2):  # 1 try + 1 retry
            try:
                # --- Adjust this call if your genai usage differs ---
                # Using the pattern you had: model.generate_content(...)
                model = genai.GenerativeModel("models/gemini-2.5-flash")
                prompt = f"{system_prompt}\n\nUser: {user_message}\nSentiVor:"
                logger.info("Calling Gemini (attempt %d). Prompt length: %d", attempt+1, len(prompt))
                response = model.generate_content(prompt)

                # Robust parsing for many possible response shapes
                text = None

                # common attr .text
                if hasattr(response, "text") and response.text:
                    text = response.text
                # some SDKs return .candidates or .output
                elif hasattr(response, "candidates") and response.candidates:
                    # join candidate texts if multiple
                    try:
                        cand_texts = []
                        for c in response.candidates:
                            if hasattr(c, "content"):
                                cand_texts.append(getattr(c, "content"))
                            elif isinstance(c, dict):
                                cand_texts.append(c.get("content") or c.get("text") or "")
                        text = "\n\n".join([t for t in cand_texts if t])
                    except Exception:
                        pass
                elif hasattr(response, "output") and response.output:
                    try:
                        # output might be a list of message dicts
                        contents = []
                        for item in response.output:
                            if isinstance(item, dict):
                                # common keys
                                contents.append(item.get("content") or item.get("text") or "")
                            elif hasattr(item, "content"):
                                contents.append(getattr(item, "content"))
                        text = "\n\n".join([c for c in contents if c])
                    except Exception:
                        pass
                elif isinstance(response, dict):
                    # generic dict parsing fallback
                    text = response.get("text") or response.get("answer") or None
                    if not text and "choices" in response and isinstance(response["choices"], list) and response["choices"]:
                        first = response["choices"][0]
                        text = (first.get("text") or (first.get("message") and first["message"].get("content")) or first.get("content") or None)

                # final guards
                if text:
                    reply_text = text.strip()
                    logger.info("✅ Gemini parsed reply length: %d", len(reply_text))
                    break
                else:
                    # nothing parsed — raise to go to exception handler and possibly retry
                    raise ValueError("No text found in Gemini response")

            except Exception as e:
                last_exception = e
                logger.exception("Error while calling/parsing Gemini (attempt %d): %s", attempt+1, e)
                # small backoff before retry
                time.sleep(1)

        # If after attempts we have no reply_text, send a graceful error message
        if not reply_text:
            logger.error("Failed to get a valid reply from Gemini after retries. Last exception: %s", last_exception)
            dispatcher.utter_message(text="I'm having trouble connecting to my knowledge engine right now. Please try again a little later.")
            return events

        # Send only one consolidated reply back to Rasa
        dispatcher.utter_message(text=reply_text)
        return events