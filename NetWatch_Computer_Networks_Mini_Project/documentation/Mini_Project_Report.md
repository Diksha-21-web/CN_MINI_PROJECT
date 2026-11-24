# NetWatch: Real-Time Network Packet Analyzer and Traffic Monitoring Dashboard

## Abstract
NetWatch is a web-based educational network monitoring application that captures and analyzes packet metadata. It identifies common protocols, summarizes source and destination IP addresses, visualizes traffic statistics, flags selected traffic patterns using transparent heuristics, and supports offline PCAP analysis. A React frontend communicates with a Python Flask backend. Scapy provides packet decoding and optional live capture.

## 1. Introduction
Computer networks exchange information in the form of packets. Packet analysis helps understand communication endpoints, protocols, packet sizes, and traffic patterns. NetWatch provides a user-friendly dashboard for exploring these concepts.

## 2. Problem Statement
Raw packet traces can be difficult for beginners to interpret. The project aims to make packet metadata and traffic summaries easier to inspect through a web interface.

## 3. Objectives
- Capture packets in a permitted local environment.
- Identify protocols and extract packet header metadata.
- Search and filter captured packets.
- Visualize protocol and IP-level statistics.
- Demonstrate simple heuristic traffic alerts.
- Analyze offline PCAP/PCAPNG files.
- Export packet data and a PDF summary.

## 4. Existing and Proposed System
Wireshark is a powerful packet analyzer, but its detailed interface can be challenging for beginners. NetWatch provides a simplified dashboard and summary visualizations while using Scapy for packet processing. It complements rather than replaces Wireshark.

## 5. System Architecture
Network interface or uploaded PCAP → Scapy packet decoder → Flask API and analysis engine → React dashboard, charts, packet explorer and reports.

## 6. Modules
1. Overview dashboard.
2. Live packet capture and labelled demo mode.
3. Packet explorer.
4. Protocol analysis.
5. IP address analysis.
6. Rule-based security observations.
7. Offline PCAP analyzer.
8. CSV/PDF report export.

## 7. Algorithms and Processing
For each packet, the backend extracts timestamp, protocol, source/destination IP, ports where applicable, packet length, direction estimate and summary. Counters aggregate protocol frequencies and source/destination activity. Simple heuristics flag high packet volume and traffic to many distinct destination ports. These observations are not definitive attack classifications.

## 8. Technology Stack
- Frontend: React, Vite, CSS, Recharts, Lucide React.
- Backend: Python, Flask, Flask-CORS.
- Packet processing: Scapy.
- Capture support: Npcap on Windows or native capture permissions on Unix-like systems.
- Storage: in-memory session data and SQLite-ready modular structure; uploaded PCAP is temporarily stored for parsing.
- Reporting: CSV and ReportLab PDF.

## 9. Testing Plan
- Backend health endpoint.
- Start/stop demo capture.
- Verify packet records and statistics.
- Filter packet list by protocol and search string.
- Upload valid PCAP and reject unsupported file extensions.
- Export CSV and PDF.
- Attempt live capture only with correct OS privileges and capture driver.

## 10. Limitations
- Live capture is OS and permission dependent.
- HTTPS payloads are encrypted and are not decrypted.
- Demo records are synthetic and visibly labelled.
- Heuristic alerts can produce false positives and false negatives.
- The tool does not block packets or act as an enterprise IDS.

## 11. Future Scope
- Persistent capture sessions and user authentication.
- More advanced flow-level analysis.
- Configurable alert thresholds.
- Additional routing and subnet visualization.
- Role-based access and multi-interface comparison.

## 12. Conclusion
NetWatch combines practical packet analysis concepts with a modern web dashboard. It is suitable for demonstrating packet capture, protocol identification, IP metadata analysis, traffic visualization, and offline trace analysis in a controlled educational environment.
