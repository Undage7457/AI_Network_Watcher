# 📡 AI Network Watcher

AI Network Watcher is a real-time AI-powered Wi-Fi monitoring and intrusion detection system built using Python, Streamlit, PostgreSQL, Scapy, and Machine Learning.

The application scans local networks, detects connected devices, identifies unknown/intruder devices, performs AI anomaly analysis, stores scan logs in PostgreSQL, and sends Telegram security alerts.

---

# 🚀 Features

✅ Real-Time Network Scanning  
✅ ARP-Based Device Discovery  
✅ AI-Powered Intrusion Detection  
✅ Device Classification System  
✅ PostgreSQL Database Logging  
✅ Telegram Security Alerts  
✅ Streamlit Dashboard  
✅ Auto Refresh Monitoring  
✅ Vendor & Hostname Detection  
✅ Trusted Device Management  

---

# 🛠️ Technologies Used

- Python
- Streamlit
- PostgreSQL
- SQLAlchemy
- Scapy
- Pandas
- Scikit-learn
- Telegram Bot API
- dotenv
- mac-vendor-lookup

---

# 📂 Project Structure

```bash
AI_Network_Watcher/
│
├── ai/
│   ├── detect_anomaly.py
│   ├── model.pkl
│   └── encoder.pkl
│
├── dashboard/
│   └── app.py
│
├── database/
│   └── db.py
│
├── scanner/
│   └── trusted_devices.json
│
├── requirements.txt
├── README.md
└── .env


Installation
1️⃣ Clone Repository
git clone https://github.com/Undage7457/AI_Network_Watcher.git

cd AI_Network_Watcher
2️⃣ Create Virtual Environment
python -m venv venv

Activate environment:

Windows
.\venv\Scripts\activate
Linux / Mac
source venv/bin/activate
3️⃣ Install Dependencies
pip install -r requirements.txt
🗄️ PostgreSQL Setup

Create database:

CREATE DATABASE ai_network_watcher;

Create table:

CREATE TABLE IF NOT EXISTS device_logs (

    id SERIAL PRIMARY KEY,

    ip_address VARCHAR(50),
    mac_address VARCHAR(100),
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,

    is_intruder BOOLEAN,

    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
🔐 Environment Variables

Create a .env file:

DB_HOST=localhost
DB_PORT=5432
DB_NAME=ai_network_watcher
DB_USER=postgres
DB_PASSWORD=your_password

BOT_TOKEN=your_telegram_bot_token
CHAT_ID=your_chat_id
▶️ Run Application
streamlit run .\dashboard\app.py

Application runs at:

http://localhost:8501
🤖 AI Detection

The project uses machine learning anomaly detection to:

Detect suspicious devices
Analyze vendor behavior
Identify intruders
Generate anomaly scores
📲 Telegram Alerts

The system sends real-time Telegram alerts when suspicious devices are detected.

Example alert:

🚨 AI Security Alert!

IP Address: 192.168.1.10
MAC Address: xx:xx:xx:xx
Vendor: Apple
Device Type: iPhone
AI Anomaly Score: 0.9342
Suspicious: True
📊 Dashboard Features
Connected device table
Intruder detection
AI anomaly scoring
Real-time refresh
PostgreSQL logging
🔒 Security Notes
Run terminal as Administrator for ARP scanning on Windows
Keep .env private
Never upload credentials to GitHub
📌 Future Improvements
Live packet sniffing
Advanced AI models
Device fingerprinting
Threat intelligence APIs
Docker deployment
Cloud deployment
Multi-network monitoring
👨‍💻 Author

Suraj Undage