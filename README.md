# 🛡️ AI-Enhanced Adaptive Honeypot & Intrusion Detection System

An intelligent cybersecurity tool that deploys a **deceptive login portal** to attract, detect, and analyze malicious activity in real time. Built with **Python (Flask)** and powered by a **Machine Learning-based anomaly detection engine**.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?logo=scikit-learn)
![SQLite](https://img.shields.io/badge/Database-SQLite-green?logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📌 What is This?

This project is a **honeypot** — a fake system designed to look like a real login portal. When attackers try to break in using techniques like SQL injection or brute force, the system:

1. **Captures** all their data (IP, payloads, headers, cookies)
2. **Analyzes** the attack using signature matching + AI
3. **Classifies** the threat level as HIGH, MEDIUM, or LOW
4. **Responds adaptively** — throttling bots and feeding fake data to high-risk attackers
5. **Logs everything** to a database for monitoring through an admin dashboard

---

## 🏗️ Architecture

```
Attacker Request
       │
       ▼
┌─────────────────┐
│  Throttling      │  ← Delays repeat offenders (1-3 sec)
│  Middleware      │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Hybrid Detection│
│  Engine          │
│  ┌─────────────┐ │
│  │ Signature   │ │  ← Regex-based SQLi/XSS detection
│  │ Checker     │ │
│  └─────────────┘ │
│  ┌─────────────┐ │
│  │ AI Behavioral│ │  ← Isolation Forest anomaly detection
│  │ Hook        │ │
│  └─────────────┘ │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Adaptive Response│
│  HIGH → Shadow   │  ← Serve fake database (mock_database.json)
│  LOW  → Login    │  ← Serve normal login page
└────────┬────────┘
         ▼
┌─────────────────┐
│  SQLite Database │  ← Log IP, payload, risk, country, timestamp
│  (attacks.db)    │
└─────────────────┘
         ▼
┌─────────────────┐
│  Admin Dashboard │  ← Real-time monitoring & analytics
└─────────────────┘
```

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🪤 **Decoy Login Portal** | Fake login page that captures attacker credentials, headers, and cookies |
| 🔍 **Signature Detection** | Regex-based detection for SQL Injection (SQLi) and Cross-Site Scripting (XSS) |
| 🧠 **AI Anomaly Detection** | Isolation Forest ML model for behavioral analysis |
| ⏱️ **Adaptive Throttling** | `time.sleep()` delays that increase with the attacker's risk score |
| 🔀 **Shadow Routing** | High-risk attackers receive fake database data instead of real responses |
| 📊 **Real-Time Dashboard** | Admin panel with attack stats, severity charts, and trend analytics |
| 📄 **Attack Logs** | Detailed logs of every captured intrusion attempt |
| 📈 **Trend Analytics** | Time-series visualization of attack activity |
| 🚫 **IP Blocking** | Manual IP blocking/unblocking from the admin panel |
| 🔐 **Password Hashing** | Admin passwords stored securely using `pbkdf2:sha256` |
| 🌍 **GeoIP Lookup** | Identifies the attacker's country using IP geolocation |
| 📡 **Telemetry API** | `/api/telemetry` endpoint providing live JSON data for integrations |
| 🔔 **Real-Time Alerting** | Automated Discord/Slack webhook notifications for HIGH-risk attacks |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or higher

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/ai-enhanced-honeypot.git
cd ai-enhanced-honeypot

# 2. Create a virtual environment
python -m venv venv

# 3. Activate it
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the application
python app.py
```

### 🔔 Configuring Real-Time Alerts

To receive alerts on Discord or Slack:
1. Create a Webhook URL in your Discord channel settings.
2. Open the `.env` file.
3. Replace `your_webhook_here` with your actual Discord Webhook URL:
   ```env
   WEBHOOK_URL=https://discord.com/api/webhooks/...
   ```

### Access the Application

| Page | URL | Description |
|------|-----|-------------|
| Honeypot (Decoy) | `http://127.0.0.1:5000/login` | Fake login page for attackers |
| Admin Login | `http://127.0.0.1:5000/admin_login` | Real admin authentication |
| Admin Signup | `http://127.0.0.1:5000/signup` | Create a new admin account |
| Dashboard | `http://127.0.0.1:5000/dashboard` | Real-time attack monitoring |
| Attack Logs | `http://127.0.0.1:5000/logs` | Detailed attack records |
| Analytics | `http://127.0.0.1:5000/analytics` | Attack trend charts |
| System Monitor | `http://127.0.0.1:5000/system` | Server health & status |
| Telemetry API | `http://127.0.0.1:5000/api/telemetry` | Live JSON attack data |

---

## 📁 Project Structure

```
ai_honeypot_system/
├── app.py                 # Main Flask application & routing
├── honeypot.py            # Hybrid Detection Engine (Signatures + AI)
├── ai_model.py            # Isolation Forest ML model
├── database.py            # SQLite database operations
├── mock_database.json     # Fake data served to high-risk attackers
├── .env                   # Environment variables (secret key)
├── attacks.db             # SQLite database (auto-generated)
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates (Jinja2)
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── logs.html
│   ├── analytics.html
│   ├── blocked.html
│   └── system.html
└── static/                # CSS and JavaScript files
    └── style.css
```

---

## 🧪 Testing

Run the automated test suite to verify all security features:

```bash
python test_honeypot.py
```

**Expected Results:**

| Test | Description | Expected |
|------|-------------|----------|
| 1 | Telemetry API returns valid JSON | ✅ PASS |
| 2 | SQLi payload triggers shadow routing | ✅ PASS |
| 3 | XSS payload triggers shadow routing | ✅ PASS |
| 4 | Normal login does NOT trigger shadow routing | ✅ PASS |
| 5 | 100KB payload does NOT crash the server | ✅ PASS |
| 6 | Attack counts increase after attacks | ✅ PASS |

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite
- **ML Model:** scikit-learn (Isolation Forest)
- **Security:** Werkzeug (password hashing), python-dotenv
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **GeoIP:** ip-api.com

---

## 📜 License

This project is licensed under the MIT License.

---

## 👤 Author

Built as a cybersecurity portfolio project demonstrating expertise in:
- Intrusion Detection Systems (IDS)
- Honeypot deployment & deception technology
- Machine Learning for threat detection
- Secure web application development
