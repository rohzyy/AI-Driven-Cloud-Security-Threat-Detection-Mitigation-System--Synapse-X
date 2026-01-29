# Cloud Threat Detection System

> AI-Powered Real-Time Network Security Monitoring & Threat Mitigation

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com/)
[![ML Models](https://img.shields.io/badge/ML-Dual%20Model-orange.svg)](https://scikit-learn.org/)
[![Mobile](https://img.shields.io/badge/Deploy-Termux%20Ready-red.svg)](https://termux.com/)

Project For Fortex36
Team name - Synapse X
Project - AI-Driven Cloud Security Threat Detection & Mitigation

### Key Features

**Dual AI Model Architecture**
- UNSW-NB15 Anomaly Detection Model (9MB)
- Random Forest Attack Classifier (73MB)

**Real-Time Threat Detection**
- DoS/DDoS attacks
- Exploitation attempts
- Port scanning & reconnaissance
- Fuzzing & analysis attacks
- Backdoor & shellcode injection

**Automated Mitigation**
- IP blocking for critical threats
- Rate limiting for DoS attacks
- Session termination for suspicious activity
- Enhanced monitoring for reconnaissance

**Comprehensive Logging**
- Activity logs (all network traffic)
- Threat logs (detected anomalies)
- Mitigation logs (actions taken)

**Mobile Deployment**
- Fully compatible with Termux on Android
- Low resource footprint
- No external dependencies

---
## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Frontend Dashboard                     │
│              (Real-time Monitoring UI)                   │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP POST /api/request
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  Flask API Server                        │
│                    (app.py)                              │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│              Feature Extraction                          │
│        (40+ UNSW-NB15 compatible features)              │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│         Model 1: UNSW-NB15 Anomaly Detector             │
│              (unsw_nb15_model.pkl)                       │
└───────────────────────┬─────────────────────────────────┘
                        │
                  ┌─────┴─────┐
                  │           │
            Normal ▼           ▼ Anomaly Detected
                  │           │
                  │    ┌──────────────────────────────┐
                  │    │ Model 2: RF Attack Classifier │
                  │    │    (rf_model.joblib)          │
                  │    └──────────┬───────────────────┘
                  │               │
                  │               ▼
                  │    ┌──────────────────────────────┐
                  │    │  Mitigation Engine            │
                  │    │  (actions.py)                 │
                  │    └──────────┬───────────────────┘
                  │               │
                  ▼               ▼
           ┌──────────────────────────────────────────┐
           │         Logging System                    │
           │  ├── activity_log.txt                    │
           │  ├── threat_log.txt                      │
           │  └── mitigation_log.txt                  │
           └──────────────────────────────────────────┘
```

---

## How to use it:
A deployable AI-based data center security system that runs on a single node, monitors network activity in real-time, detects threats using dual machine learning models, and automatically triggers mitigation actions. All activity is logged to text files for audit and analysis.

### 1. **Start the Server**
```
Access demo at http://localhost:5000
```

### 2. **Open Dashboard**
Navigate to `http://localhost:5000` in your browser

### 3. **Simulate Traffic**
- Use the **Network Traffic Simulator** panel
- Select traffic type (Normal/DoS/Exploit/Recon)
- Click "Send Traffic" to test detection
- Or use **Auto Simulate Traffic** for continuous demo

### 4. **Monitor Results**
- Watch **real-time logs** update in three panels
- View **system statistics** (requests, threats, blocks)
- See **mitigation actions** triggered automatically

---

## Team & Acknowledgments

**Built for:** Fortex 36
**Team Lead** Rohan Malyadri  
**Team** Kesava, Thanishker, Harinesh  

---

**Made with 💙 for Fortex36 by Team SynapseX**
