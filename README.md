# 🛡️ ShieldPatch
### Predict . Protect . Prevail

AI-driven vulnerability detection and automated patch management platform that helps organizations identify, prioritize, and remediate software vulnerabilities faster — closing the gap between vulnerability discovery and patching.

![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/-Flask-000000?style=flat-square&logo=flask&logoColor=white)
![React](https://img.shields.io/badge/-React-61DAFB?style=flat-square&logo=react&logoColor=black)
![MySQL](https://img.shields.io/badge/-MySQL-4479A1?style=flat-square&logo=mysql&logoColor=white)
![Docker](https://img.shields.io/badge/-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![TensorFlow](https://img.shields.io/badge/-TensorFlow-FF6F00?style=flat-square&logo=tensorflow&logoColor=white)
![XGBoost](https://img.shields.io/badge/-XGBoost-blue?style=flat-square)
![Rasa](https://img.shields.io/badge/-Rasa-5A17EE?style=flat-square&logo=rasa&logoColor=white)

---

## 📌 Problem

Organizations face a constant flood of new vulnerabilities. Manual detection and patching is slow and error-prone, while attackers increasingly use automation to exploit weaknesses faster than traditional tools can respond — leading to data breaches, ransomware, and downtime.

## 💡 Solution

ShieldPatch is an AI-based automated patch prioritization system. It pulls live threat data from **NVD, EPSS, and ExploitDB**, uses **machine learning** to score and rank vulnerabilities by real exploit risk, tests patches safely in a **sandbox**, and gives admins a **dashboard + AI chatbot** to monitor and act — all with minimal manual effort.

## ✨ Key Features

- **Live Threat Intelligence** — Continuous CVE, EPSS, and ExploitDB feed integration
- **ML-Based Risk Scoring** — Exploit prediction, risk scoring, and patch compatibility models (Scikit-learn, TensorFlow, XGBoost)
- **File & System Scanning** — APK (Androguard) and EXE (pefile) analysis, OSQuery-based system scans
- **Sandbox Testing & Rollback** — Safe patch simulation via Docker/VirtualBox with automatic rollback on failure
- **AI Chatbot** — Rasa-powered assistant for patch guidance and Q&A
- **Admin Dashboard** — Real-time vulnerability status, risk levels, and patch reporting
- **Alerts & Logging** — Instant notifications for high-risk threats and full audit trail of scans/patches

## 🏗️ Architecture

The system follows a 4-layer architecture:

| Layer | Responsibility |
|---|---|
| **Presentation Layer** | UI, Dashboard, AI Chatbot (React) |
| **Business Layer** | User Management, Access Control, File Upload Handling |
| **Service Layer** | Scan & Analysis, Threat Intelligence Aggregation, ML Risk Prediction, Patch Recommendation, Reporting |
| **Data Service Layer** | MySQL Database, Sandbox Environment |

## 🔄 Process Flow

Input Data → Preprocessing → ML Models (Exploit Prediction, Risk Scoring, Patch Compatibility)

→ Probability Score Calculation → Risk Scoring & Patch Recommendation

→ Admin Review (Confirm/Reject) → Sandbox Testing → Deployment

→ Feedback stored in MySQL → Model Retraining

## 🛠️ Tech Stack

| Category | Tools |
|---|---|
| Frontend | React.js, Bootstrap, HTML5, CSS3 |
| Backend | Python (Flask) |
| Database | MySQL |
| System Scanning | OSQuery, PowerShell, Bash |
| File Analysis | Androguard (APK), pefile (EXE) |
| ML & AI | Scikit-learn, TensorFlow, XGBoost |
| Threat Intel | Requests, BeautifulSoup (CVE/NVD/ExploitDB scraping) |
| Sandbox | Docker, VirtualBox |
| Chatbot | Rasa, Gemini AI |

## 🚀 Getting Started

### Prerequisites
- Python 3.9+, Node.js 16+, MySQL 8.0+, Docker

### Installation

```bash
git clone https://github.com/AjayZordan/ShieldPatch.git
cd ShieldPatch

# Backend
cd backend
pip install -r requirements.txt
python app.py

# Frontend
cd ../shieldpatch-frontend
npm install
npm start
```

## 📚 Academic Context

This project was developed as part of the **Capstone Project (UQ24CA741A)** at **PES University, Bengaluru**, under the guidance of Prof. Archana A.

## 👤 Author

**R. Ajay Kumar**
[LinkedIn](https://linkedin.com/in/ajaykumar-secdev) · ajaykumar040702@gmail.com
