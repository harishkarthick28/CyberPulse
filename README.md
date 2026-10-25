# 🛡️ CyberPulse — Early-Warning Cybersecurity Dashboard for Small Businesses

> **Winner-Ready Hackathon Submission**  
> *Transforming noisy security logs into deterministic, multi-stage attack correlation, plain-language executive narratives, and 1-click guided containment.*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit App](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B.svg)](https://streamlit.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-orange.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/pytest-passing-success.svg)](tests/)

---

## 🎯 Executive Overview & Problem Statement

Small and medium-sized businesses (SMBs) represent **43% of all cyberattacks**, yet **60% go out of business within six months of a severe breach**. 

The fundamental problem is not a lack of logs—every Microsoft 365, Google Workspace, and endpoint firewall generates millions of records daily. **The problem is the "Translation Gap"**:
1. **Isolated Alert Blindness**: Individual events look innocuous in isolation (e.g., a single failed login or a new MacBook connection). No one connects the dots until files are already encrypted.
2. **Cryptic Telemetry**: Small business owners, office managers, and part-time IT admins don't understand JSON SIEM outputs or raw PowerShell Base64 flags.
3. **Paralysis & Hesitation**: By the time an incident response firm is contacted, the average attacker dwell time has already surpassed 16 days.

### 💡 The CyberPulse Solution
**CyberPulse** is an intelligent early-warning cybersecurity system specifically engineered for small businesses. It connects everyday log streams, correlates suspicious events across **User, IP, Device, and Time** into a single chronological attack chain, dynamically calculates a threat score (0–100), translates technical jargon into plain-English stories, and provides 1-click containment buttons.

In our flagship simulated ransomware scenario, **CyberPulse alerts the business owner 3 hours and 15 minutes BEFORE ransomware locks their files**, giving them ample time to contain the threat with a single click.

---

## ✨ Key Features & Architecture

```
                                      ┌────────────────────────────────┐
                                      │   Everyday Cloud & EDR Logs    │
                                      │  (AzureAD, M365, Defender, OK) │
                                      └────────────────┬───────────────┘
                                                       │
                                                       ▼
                                      ┌────────────────────────────────┐
                                      │  10 Transparent Rules Engine   │
                                      │ (Deterministic, zero black-box)│
                                      └────────────────┬───────────────┘
                                                       │
                                                       ▼
                                      ┌────────────────────────────────┐
                                      │ Multi-Entity Correlator Module │
                                      │   [User + IP + Device + Time]  │
                                      └────────────────┬───────────────┘
                                                       │
                       ┌───────────────────────────────┴───────────────────────────────┐
                       ▼                                                               ▼
        ┌─────────────────────────────┐                                 ┌─────────────────────────────┐
        │ Dynamic Severity Scoring    │                                 │ Plain-Language Narrative    │
        │ • 0-100 Mathematical Model  │                                 │ • Executive Summary         │
        │ • Green / Yellow / Red Bands│                                 │ • Why Link Was Made         │
        │ • Kill-Chain Stage Bonus    │                                 │ • Business Impact           │
        └──────────────┬──────────────┘                                 └──────────────┬──────────────┘
                       │                                                               │
                       └───────────────────────────────┬───────────────────────────────┘
                                                       ▼
                                      ┌────────────────────────────────┐
                                      │   Modern Dark SOC Dashboard    │
                                      │  (Streamlit + Plotly + CSS)    │
                                      │  • Risk Gauge Meter            │
                                      │  • Interactive Timeline        │
                                      │  • 1-Click Guided Containment  │
                                      └────────────────────────────────┘
```

### 1. 🎮 Live Interactive Attack Simulator
- **Ransomware Kill Chain**: Brute Force Spray ➔ Impossible Travel ➔ Rogue Device Enrollment ➔ MFA Fatigue Bypass ➔ Hidden Forwarding Rule ➔ Global Admin Escalation ➔ Encoded PowerShell ➔ Shadow Copy Deletion.
- **Data Exfiltration Chain**: TOR Node Access ➔ Unmanaged Linux Node ➔ 3:40 AM Off-Hours Access ➔ 1,420 Customer Database Files Harvested.
- **Normal Day**: Clean, routine corporate employee operations proving zero false-positive fatigue.
- **Playback Controls**: Step-by-Step advancement (ideal for live video demos and screenshots), Fast-Forward, and Full-Auto streaming.

### 2. 🧠 10 Transparent Detection Rules
Zero black-box hallucinations. Pure deterministic rules mapped to MITRE ATT&CK:
1. `RULE-01`: **Password Spray / Credential Burst** (`T1110.003`)
2. `RULE-02`: **Impossible Travel Anomaly** (`T1078.004`)
3. `RULE-03`: **Unregistered / Non-Compliant Device** (`T1204`)
4. `RULE-04`: **MFA Push Fatigue / Bombing Bypass** (`T1621`)
5. `RULE-05`: **Hidden Mailbox Auto-Forwarding Rule** (`T1114.003`)
6. `RULE-06`: **Unauthorized Admin Privilege Escalation** (`T1098`)
7. `RULE-07`: **Obfuscated Base64 PowerShell Execution** (`T1059.001`)
8. `RULE-08`: **Volume Shadow Copy Deletion / Ransomware Precursor** (`T1490`)
9. `RULE-09`: **Abnormal Off-Hours Data Access** (`T1530`)
10. `RULE-10`: **Mass Cloud Data Exfiltration Spike** (`T1567`)

### 3. 📊 Dynamic 0–100 Severity Scoring
- **Base Severity Points**: Low (5), Medium (15), High (25), Critical (40).
- **Stage Escalation Multiplier**: $+10$ points for each unique MITRE kill-chain stage breached.
- **Alert Volume Density**: $+3$ points per subsequent correlated event.
- **Color-Coded Bands**:
  - 🟢 **Green (0–39)**: Normal / Routine Activity
  - 🟡 **Yellow (40–74)**: Suspicious / Elevated Concern
  - 🔴 **Red (75–100)**: Critical Active Breach

### 4. 💬 Plain-Language Explainer Box
Translates raw SIEM logs into actionable executive briefs explaining **what happened**, **why the events were linked**, and the **real-world dollar/operational risk**.

### 5. ⚡ 1-Click Guided Response Panel
Simulate immediate, automated SOAR containment with live audit trail logging:
- 🔒 **Lock Compromised User Account**
- 🚪 **Revoke All Active OAuth & Browser Sessions**
- 🛡️ **Perimeter Firewall IP Block**
- 🔌 **Host Network Isolation (EDR Quarantine)**

---

## 📂 Project Structure

```
cyberpulse/
├── .gitignore                     # Git ignore rules for Python/Streamlit
├── requirements.txt               # Production dependencies
├── README.md                      # Comprehensive documentation
├── app.py                         # Modern Dark SOC Streamlit Dashboard
├── data/
│   ├── __init__.py
│   └── synthetic_logs.json        # High-fidelity multi-stage attack scenarios
├── rules/
│   ├── __init__.py
│   ├── detector.py                # 10 Transparent detection rule engines
│   └── correlator.py              # Multi-parameter correlation & dynamic scoring
├── utils/
│   ├── __init__.py
│   ├── explainer.py               # Plain-language narrative & remediation playbook
│   └── visualizer.py              # Plotly Gauge, Timeline & MITRE charts
└── tests/
    ├── __init__.py
    └── test_rules.py              # Pytest automated test suite
```

---

## 🚀 Quickstart & Local Setup

### Prerequisites
- Python 3.11 or higher
- `git` and `pip`

### 1. Clone the Repository
```bash
git clone https://github.com/harishkarthick28/CyberPulse.git
cd cyberpulse
```

### 2. Set Up Virtual Environment (Recommended)
On macOS/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```
On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Pytest Test Suite
Validate all 10 detection rules, correlation clustering, and scoring logic:
```bash
pytest -v
```

### 5. Launch the Dashboard
```bash
python -m streamlit run app.py
```
*(Or simply `streamlit run app.py`)*
Open your browser at `http://localhost:8501`.

---

## 🎬 Live Demo & Video Recording Walkthrough

To record a demo for hackathon judges:

1. **Start on "Normal Day"**:
   - Select `Normal Business Day (Quiet Logs)` in the sidebar.
   - Click `🚀 Fast-Forward`.
   - Show how the Threat Level stays in the **Green (0-39)** zone with zero false alarms.

2. **Switch to "Ransomware Chain"**:
   - Select `🚨 Ransomware Multi-Stage Kill Chain`.
   - Click `🔄 Reset Sim` to begin at Step 0.
   - Click `▶ Step Event` to step through the attack timeline:
     - **Step 1 (08:15)**: Password spray detected from St. Petersburg IP.
     - **Step 2 (08:22)**: Impossible travel anomaly. Score climbs into **Yellow**.
     - **Step 4 (08:35)**: MFA Fatigue bypass.
     - **Step 6 (10:04)**: Admin rights escalation. Score enters **Red Critical (85+)**.
     - Notice the **Early Warning Lead Time badge: "3 hr 15 min early warning"**!
   - Highlight the **Plain-Language Explainer Box** showing the plain-English story.
   - Click `Lock Account` and `Network Isolate Device` under **1-Click Guided Incident Response**.
   - Show how the threat level immediately drops and the Containment Audit Log updates!

---

## 📤 Pushing to GitHub

Follow these steps to push this clean codebase to your GitHub repository:

```bash
# 1. Initialize git (if not already done)
git init

# 2. Stage all files
git add .

# 3. Create your initial commit
git commit -m "feat: CyberPulse production-ready early-warning SOC dashboard"

# 4. Set default branch to main
git branch -M main

# 5. Link to your GitHub repo
git remote add origin https://github.com/harishkarthick28/CyberPulse.git

# 6. Push code to GitHub
git push -u origin main
```

---

## 🛡️ Hackathon Evaluation Alignment

| Judging Criteria | How CyberPulse Excels |
| :--- | :--- |
| **Real-World Impact** | Solves the #1 risk for SMBs: lack of a dedicated $200k/yr SOC team. |
| **Technical Rigor** | Deterministic 10-rule detection engine + multi-parameter correlation algorithm + dynamic scoring model. |
| **User Experience** | Sleek SOC dark mode styling, Plotly visual gauges, interactive timelines, and zero technical jargon in explanations. |
| **Production Readiness** | 100% modular code, zero placeholders, complete `pytest` test suite, clean Git hygiene. |

---

## 📜 License
Distributed under the MIT License. See `LICENSE` for details.
