# backend/chatbot_api.py
import os
import requests
import openai
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)
CORS(app)

openai.api_key = os.getenv("OPENAI_API_KEY")

# System prompt controls SentiVor tone and persona
SYSTEM_PROMPT = (
    "You are SentiVor — an expert cybersecurity assistant for the ShieldPatch platform. "
    "Answer in a clear, professional tone. Provide actionable steps when possible and safe guidance. "
    "If the user asks for code or commands, keep them accurate and minimal."
)

RASA_URL = "http://localhost:5005/webhooks/rest/webhook"

@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json() or {}
    user_msg = data.get("message", "").strip()
    if not user_msg:
        return jsonify({"reply": "Please type a message."}), 400

    # 1) Send to Rasa REST webhook
    try:
        r = requests.post(RASA_URL, json={"sender": "user", "message": user_msg}, timeout=5)
        r.raise_for_status()
        rasa_resp = r.json()
        # rasa_resp is a list of message objects; collect text fields
        texts = [m.get("text") for m in rasa_resp if m.get("text")]
        if texts:
            # return the joined reply from Rasa (SentiVor persona already in Rasa responses)
            return jsonify({"reply": " ".join(texts)})
    except Exception:
        # If Rasa not available or error, we'll fallback to GPT
        pass

    # 2) Fallback to OpenAI GPT
    try:
        completion = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg}
            ],
            temperature=0.2,
            max_tokens=700
        )
        answer = completion.choices[0].message.content.strip()
        return jsonify({"reply": answer})
    except Exception as e:
        # graceful error if OpenAI fails
        return jsonify({"reply": "Sorry, SentiVor is temporarily unavailable. Try again later."}), 503

if __name__ == "__main__":
    app.run(port=5000, debug=True)