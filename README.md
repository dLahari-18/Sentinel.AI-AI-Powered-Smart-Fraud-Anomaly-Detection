# Sentinel.ai – AI-Powered Smart Fraud & Anomaly Detection

**Repository:** `Sentinel.AI-AI-Powered-Smart-Fraud-Anomaly-Detection`  
**Description:** A full-stack, AI-powered behavioral anomaly detection system that continuously monitors user activity, calculates dynamic risk scores, classifies users (Normal, Suspicious, Blocked), and visualizes real-time cybersecurity metrics on a professional dashboard. Built with Python, Flask, and Chart.js; deployable on Render.

---

## 🚀 Project Overview

**Sentinel.ai** solves the problem of post-login fraud and suspicious user activity:

- Traditional security systems only verify users at login.
- Hackers may mimic legitimate users.
- Sudden changes in user behavior go undetected.

**Sentinel.ai features:**

- Continuous behavioral profiling (screen time, location, device, login frequency)
- Time-based anomaly detection
- Location intelligence & impossible travel detection
- Device change detection
- Dynamic risk scoring
- User classification: Normal ✅ / Suspicious ⚠️ / Blocked ❌
- Explainable AI with clear reasons for alerts
- Real-time dashboard metrics, timeline, and risk distribution
- CSV export of reports

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python + Flask |
| Data / ML | Pandas, NumPy (Scikit-learn optional) |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |
| Deployment | Render.com |
| Dependencies | flask, pandas, numpy, gunicorn |

---

## 📁 Project Structure
sentinel-ai/
├── app.py
├── requirements.txt
├── dataset.csv (auto-generated)
├── templates/
│ ├── login.html
│ └── dashboard.html
└── README.md

---

## ⚙️ Setup Instructions

1. **Clone the repository:**
```bash
git clone https://github.com/dLahari-18/Sentinel.AI-AI-Powered-Smart-Fraud-Anomaly-Detection.git
cd Sentinel.AI-AI-Powered-Smart-Fraud-Anomaly-Detection
Install dependencies:
pip install -r requirements.txt
Run the application locally:
python app.py
Access the dashboard:
Open http://127.0.0.1:5000/ in your browser.
Login credentials (hardcoded for demo):
Admin: admin / sentinel123
Analyst: analyst / risk2024
Viewer: viewer / view123
🖥️ Features
Real-Time Anomaly Detection: Enter user activity to calculate risk instantly.
Behavior Timeline: Step-by-step activity log with timestamps.
User Table & Risk Chart: Filterable table, bar chart of risk distribution.
CSV Export: Download full risk report.
Scalable Dataset: Synthetic dataset of 50–100 users.
🎨 Dashboard Design
Theme: Dark navy (#0a0f1c) background, blue (#3b82f6) primary, purple (#a855f7) accent.
Cards: Rounded corners, soft shadow, hover glow.
Typography: H1–H3 headings, body text, status colors for Normal ✅, Suspicious ⚠️, Blocked ❌.
Responsive: Works on desktop, tablet, and mobile.
📊 Sample Test Scenarios
Scenario	Input	Risk Score	Status
Normal	User 1, Nellore, mobile, 2h, 1 attempt	15	✅ Normal
Suspicious	User 1, tablet (new device), 2h, 1 attempt	35	⚠️ Suspicious
Blocked	User 1, Bangalore, desktop, 8h, 5 attempts	85	❌ Blocked
🚀 Deployment on Render
Push code to GitHub.
On Render, create a New Web Service → Connect this repo.
Set:
Build Command: pip install -r requirements.txt
Start Command: gunicorn app:app
Deploy and access live dashboard.
📚 Learning Outcomes
Full-stack development (Flask + HTML/CSS/JS)
Explainable anomaly detection
Real-time data visualization with Chart.js
Authentication & session management
File export (CSV)
Cloud deployment
UI/UX design with modern color schemes
📝 Notes
Dataset is generated automatically on first run; no external database required.
Lightweight, rule-based system; can be extended with ML models later.
All code is self-contained and ready for internship portfolio.

Author: dLahari-18
Project: Internship-ready AI cybersecurity tool


---

This README is **portfolio-ready**, clearly communicates your project’s value, and shows **all technical and UI features** — perfect for recruiters looking at your repo.  

If you want, I can **also add a section with screenshots placeholders and badges for live demo**, which will make the repo **even more impressive**.  

Do you want me to do that?