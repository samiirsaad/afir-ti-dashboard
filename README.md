# 🛡️ AFIR-TI Dashboard
### Autonomous Firewall Incident Response & Threat Intelligence

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?logo=kali-linux&logoColor=white)](https://www.kali.org/)

**AFIR-TI** is a next-generation, AI-powered Security Operations Center (SOC) dashboard designed for Kali Linux. It combines real-time threat detection, SIEM capabilities, and advanced AI analytics to provide autonomous incident response.

![Dashboard Preview](https://via.placeholder.com/800x450/0d1117/3fb950?text=AFIR-TI+Dashboard+Preview)

## ✨ Key Features

### 🧠 AI-Powered Intelligence
- **SHAP Explainability**: Understand *why* an IP was blocked with detailed feature contribution charts.
- **AI Chat Assistant**: Ask natural language questions about your security data (e.g., "What is the most dangerous IP today?").
- **Attack Prediction**: LSTM-based forecasting to predict the next likely attack vector.
- **Auto-Tuning Thresholds**: Self-adjusting detection limits based on false positive rates.

### 🛡️ SIEM & Correlation
- **Event Correlation**: Link events from the same IP across multiple sources within 60s windows.
- **Baseline Deviation**: Detect anomalies by learning normal behavior patterns for every IP.
- **Case Management**: Full Kanban-style workflow for tracking incidents from "Open" to "Resolved".
- **UEBA**: User and Entity Behavior Analytics with risk scoring (0-100).

### 🌐 Threat Intelligence
- **MITRE ATT&CK Mapping**: Visual matrix of detected tactics and techniques.
- **Threat Feed Integration**: Auto-check IPs against global blocklists (e.g., Feodo Tracker).
- **Asset Inventory**: Track criticality and ownership of network assets.
- **Playbook Automation**: Automated response actions for brute-force, port scans, and critical threats.

### 📊 Visualization & Reporting
- **Real-time Heatmaps**: GitHub-style contribution graphs for attack intensity.
- **Compliance Reporting**: Generate PDF reports for ISO27001 and basic standards.
- **Interactive Timeline**: Reconstruct attacks step-by-step.
- **Dark Mode UI**: Professional, eye-friendly interface built with Chart.js.

## 🚀 Quick Start

### Prerequisites
- **OS**: Kali Linux (Recommended) or any Debian-based distro with root access.
- **Python**: 3.8 or higher.
- **Root Access**: Required for `iptables` integration.

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/samiirsaad/afir-ti-dashboard.git
   cd afir-ti-dashboard
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *Note: For full AI features, ensure `shap`, `anthropic`, and `reportlab` are installed.*

3. **Configure API Keys (Optional)**:
   Edit `opt/firewall_irt/config.json` to add your Anthropic API key for the Chat Assistant.

4. **Run the Dashboard**:
   ```bash
   sudo python app.py
   ```

5. **Access the UI**:
   Open your browser and navigate to `http://localhost:5000`.

## 📂 Project Structure

```
afir-ti-dashboard/
├── app.py                  # Main Flask application & API endpoints
├── templates/
│   └── index.html          # Single-file React-less Dark Theme UI
├── opt/firewall_irt/       # Data storage directory
│   ├── events.json         # Detected threat events
│   ├── blocked_ips.json    # Currently blocked IPs
│   ├── config.json         # System configuration
│   ├── cases.json          # Incident cases
│   └── ...                 # Other data files
├── engines/                # Core logic modules
│   ├── correlation_engine.py
│   ├── baseline_engine.py
│   ├── chat_assistant.py
│   ├── explainability_engine.py
│   └── ...
└── requirements.txt        # Python dependencies
```

## 🔌 API Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/events` | GET | Retrieve all detected events with SHAP explanations |
| `/api/chat` | POST | Send a natural language query to the AI assistant |
| `/api/cases` | GET/POST | Manage incident cases |
| `/api/predictions` | GET | Get AI-predicted future attacks |
| `/api/mitre-stats` | GET | Retrieve MITRE ATT&CK statistics |
| `/api/export/pdf` | GET | Generate a PDF security report |
| `/api/hunt` | POST | Run custom threat hunting queries |

*(Full API documentation available in the `docs/` folder)*

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
1. Fork the project.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## 🙏 Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Visualization powered by [Chart.js](https://www.chartjs.org/)
- AI capabilities via [Anthropic](https://www.anthropic.com/) & [SHAP](https://github.com/slundberg/shap)
- Inspired by modern SOC workflows and MITRE ATT&CK framework.

---
<p align="center">Made with ❤️ by <a href="https://github.com/samiirsaad">@samiirsaad</a></p>
