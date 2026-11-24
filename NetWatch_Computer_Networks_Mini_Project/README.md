# NetWatch — Real-Time Network Packet Analyzer & Traffic Monitoring Dashboard

A third-year Computer Networks mini-project with a React dashboard and Python/Flask backend.

## Features
- Live packet capture through Scapy (requires Npcap on Windows and administrator permissions; Linux/macOS may require sudo).
- Clearly labelled demo mode so the dashboard can be demonstrated without packet-capture permissions.
- Packet explorer with protocol, IP, port and packet-size filters.
- Protocol, IP and traffic statistics.
- Rule-based traffic alerts (heuristics, not proof of an attack).
- Offline `.pcap` / `.pcapng` upload and analysis.
- CSV export and PDF summary report.
- Responsive dark cybersecurity dashboard.

## Requirements
- Windows 10/11, Linux, or macOS
- Python 3.10+
- Node.js 18+
- For live capture on Windows: install Npcap from https://npcap.com/ and run the backend terminal as Administrator.
- For live capture on Linux/macOS: run backend with appropriate packet-capture privileges.

## Run on Windows (VS Code)

### 1. Backend
Open a terminal in the project root:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Backend: http://127.0.0.1:5000

If PowerShell blocks activation, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

For live capture, open VS Code / terminal as Administrator and ensure Npcap is installed. The application can still run in demo mode without these permissions.

### 2. Frontend (open a second terminal)
From the project root:

```powershell
cd frontend
npm install
npm run dev
```

Frontend: http://localhost:5173

## First use
1. Start the backend and frontend.
2. Open http://localhost:5173.
3. Select **Demo Mode** and click **Start Capture** to populate the dashboard with clearly labelled generated demonstration records.
4. To capture real traffic, choose **Live Capture**, select a network interface, and start capture. Capture only networks/devices for which you have permission.
5. Upload a `.pcap` or `.pcapng` file from Packet Lab for offline analysis.

## Notes and limitations
- The demo generator is synthetic and is labelled as demo data; it is not real network traffic.
- Live packet capture depends on OS permissions, installed capture drivers, and interface support.
- HTTPS payloads remain encrypted. NetWatch displays packet metadata and does not decrypt HTTPS.
- Security alerts are simple heuristics based on traffic patterns. They do not confirm malicious activity.
- IP geolocation is intentionally not included.
- This is an educational monitoring tool, not an enterprise IDS or firewall. It does not block traffic.

## Project structure
```text
NetWatch_Computer_Networks_Mini_Project/
├── backend/
│   ├── app.py
│   ├── packet_engine.py
│   ├── requirements.txt
│   └── uploads/
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── styles.css
│       └── api.js
├── documentation/
│   └── Mini_Project_Report.md
├── screenshots/
├── start_project.bat
└── README.md
```
