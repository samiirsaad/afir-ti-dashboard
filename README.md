# 🛡️ AFIR-TI Dashboard
### Autonomous Firewall Incident Response & Threat Intelligence

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-green.svg)
![Kali Linux](https://img.shields.io/badge/Kali-Linux-red.svg)
![Flask](https://img.shields.io/badge/flask-2.0%2B-lightgrey.svg)
![AI Powered](https://img.shields.io/badge/AI-Powered-purple.svg)

**Next-Generation SIEM with AI-Powered Threat Detection & Automated Response**

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [API Reference](#-api-reference)

</div>

---

## 🚀 Overview

AFIR-TI is an advanced, AI-powered Security Information and Event Management (SIEM) system designed for Kali Linux. It combines machine learning, behavioral analytics, and automated response capabilities to provide real-time threat detection, investigation, and remediation.

### 🔥 Key Highlights
- **🤖 AI-Powered**: SHAP explainability, LLM chat assistant, attack prediction
- **🧠 Advanced ML**: LSTM + Isolation Forest + Rule Engine hybrid detection
- **📊 Real-time Visualization**: Interactive dashboards with Chart.js
- **⚡ Automated Response**: Playbook-based auto-remediation
- **🎯 MITRE ATT&CK**: Full tactic & technique mapping
- **🔍 Threat Hunting**: Advanced query interface for manual investigation
- **📋 Case Management**: Professional incident tracking workflow
- **🌐 UEBA**: User & Entity Behavior Analytics with risk scoring

---

## ✨ Features

### 🧠 AI-Powered Capabilities

| Feature | Description |
|---------|-------------|
| **🔍 SHAP Explainability** | Every ML decision comes with feature-level explanations |
| **💬 AI Chat Assistant** | Natural language Q&A about your security data (Arabic/English) |
| **🔮 Attack Prediction** | Predict next attack steps using LSTM forecasting |
| **📝 Auto-Narratives** | Convert technical events into human-readable summaries |
| **🎛️ Adaptive Thresholds** | Self-tuning detection thresholds based on FP/FN rates |

### 🛡️ SIEM Core Features

| Feature | Description |
|---------|-------------|
| **🔗 Event Correlation** | Link related events across sources within 60s windows |
| **📏 Baseline Detection** | Learn normal behavior & detect anomalies automatically |
| **📁 Case Management** | Kanban-style incident tracking with notes & resolution |
| **👤 UEBA Profiles** | Risk scores (0-100) for every IP with behavior tags |
| **⚙️ Playbook Automation** | Auto-respond to brute force, port scans, critical threats |
| **🎯 Threat Hunting** | Advanced query builder for historical data exploration |
| **🖥️ Asset Inventory** | Track devices, owners, criticality levels |
| **📊 Compliance Reports** | ISO 27001 ready reports with PDF export |
| **⏱️ Incident Timeline** | Reconstruct attacks step-by-step with phase markers |
| **🌍 Threat Feed Integration** | Cross-reference with Feodo Tracker & other feeds |

---

## ⚡ Quick Start

### Prerequisites
```bash
# Kali Linux (recommended) or any Debian-based system
# Python 3.8+
# Root/sudo access for iptables integration
```

### Installation

```bash
# Clone the repository
git clone https://github.com/samiirsaad/afir-ti-dashboard.git
cd afir-ti-dashboard

# Install dependencies
pip install -r requirements.txt

# Optional: For full AI features
pip install shap anthropic reportlab psutil

# Create required directories
sudo mkdir -p /opt/firewall_irt
sudo cp -r opt/firewall_irt/* /opt/firewall_irt/

# Run the dashboard
python app.py
```

### Access Dashboard
```
http://localhost:5000
```

---

## 📁 Project Structure

```
afir-ti-dashboard/
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── LICENSE                         # MIT License
│
├── engines/                        # Core detection engines (12 files)
├── templates/                      # HTML dashboard
├── opt/firewall_irt/               # Data directory
├── .github/                        # GitHub templates & workflows
└── docs/                           # Documentation
```

---

## 🔌 API Endpoints

### Core | SIEM | AI | Config | Export
- `/api/events` - Get all events
- `/api/blocked` - Get blocked IPs
- `/api/correlated` - Correlated attacks
- `/api/cases` - Incident cases
- `/api/entities` - UEBA profiles
- `/api/chat` - AI assistant
- `/api/predictions` - Attack forecasts
- `/api/explain/<id>` - SHAP explanations
- `/api/config` - System configuration
- `/api/export/csv` - CSV export
- `/api/export/pdf` - PDF report

*See [docs/API.md](docs/API.md) for complete reference*

---

## ⚙️ Configuration

Edit `/opt/firewall_irt/config.json`:

```json
{
  "failed_conn_threshold": 10,
  "port_scan_threshold": 15,
  "lstm_anomaly_score": 0.5,
  "block_duration": 3600,
  "ml_weight": 0.7,
  "anthropic_key": "",
  "adaptive_thresholds_enabled": true
}
```

---

## 🔒 Security Notes

- **Root Access Required** for iptables integration
- **Protect API Keys** in config.json
- **Do not expose** to public networks without authentication
- **Backup** `/opt/firewall_irt/` regularly

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file

---

## 👨‍💻 Author

**Samiir Saad**  
GitHub: [@samiirsaad](https://github.com/samiirsaad)

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

</div>
