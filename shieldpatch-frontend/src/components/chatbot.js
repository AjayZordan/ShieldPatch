import React, { useState, useRef, useEffect } from "react";
import "./chatbot.css";

function Chatbot() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    { sender: "bot", text: "👋 Hi, I’m SentiVor — your cybersecurity guide. What would you like to learn today?" },
  ]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef(null);

  // 🔄 Scroll to bottom on new message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const toggleChat = () => setIsOpen(!isOpen);

  const sendMessage = async () => {
    if (!input.trim()) return;

    const userMessage = input.trim();
    setMessages(prev => [...prev, { sender: "user", text: userMessage }]);
    setInput("");
    setIsTyping(true);

    try {
      const res = await fetch("http://localhost:5005/webhooks/rest/webhook", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sender: "user", message: userMessage }),
      });

      const data = await res.json();

      if (data && data.length > 0) {
        const replies = data.map((msg) => msg.text).filter(Boolean);
        for (const reply of replies) {
          setMessages(prev => [...prev, { sender: "bot", text: reply }]);
        }
      } else {
        setMessages(prev => [
          ...prev,
          { sender: "bot", text: "🤔 Hmm, I didn’t catch that. Try rephrasing!" },
        ]);
      }
    } catch (err) {
      setMessages(prev => [
        ...prev,
        { sender: "bot", text: "⚠️ Connection error. Please check if Rasa is running." },
      ]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter") sendMessage();
  };

  return (
    <div className="chatbot-container">
      {/* 💬 Floating Chat Button */}
      {!isOpen && (
        <button className="chatbot-toggle" onClick={toggleChat}>
          💬
        </button>
      )}

      {/* 🧠 Chat Window */}
      {isOpen && (
        <div className="chatbot-window">
          <div className="chatbot-header">
            <span>SentiVor Chatbot 🔐</span>
            <button className="close-btn" onClick={toggleChat}>✖</button>
          </div>

          <div className="chatbot-body">
            {messages.map((msg, i) => (
              <div
                key={i}
                className={`chat-message ${msg.sender === "user" ? "user-msg" : "bot-msg"}`}
              >
                {msg.text}
              </div>
            ))}
            {isTyping && <div className="typing">SentiVor is typing<span className="dots">...</span></div>}
            <div ref={messagesEndRef} />
          </div>

          <div className="chatbot-input">
            <input
              type="text"
              value={input}
              placeholder="Ask about cybersecurity..."
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyPress}
            />
            <button onClick={sendMessage}>Send</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default Chatbot;