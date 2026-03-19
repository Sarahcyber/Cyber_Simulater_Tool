# 🛡️ Cyber-Incident Simulator & Responder 

A Python-based Laboratory for Network Attack & Defense Simulation

This project is an educational cybersecurity laboratory designed to demonstrate the lifecycle of a network attack. It simulates common threats and shows how automated defense systems (Mitigation Engines) can detect and neutralize these threats in real-time.

# 🎯 Project Overview

The goal of this project is to bridge the gap between offensive and defensive security by providing a hands-on simulation of:

Reconnaissance (Attack): Scanning for open doors (ports) on a target.

Disruption (Attack): Flooding a target with data to simulate a Denial of Service (DoS) attack.

Automated Response (Defense): Monitoring traffic and automatically "blacklisting" offenders when thresholds are exceeded.

# ✨ Key Features

Port Scan Simulation: Uses TCP SYN packets to identify open services on a target IP.

ICMP Flood Simulation: Sends a high-speed stream of packets to simulate a network-level attack.

Live Event Dashboard: A Flask-based UI that streams live logs from the backend using Server-Sent Events (SSE).

Auto-Mitigation Engine: Automatically detects when a user exceeds 50 requests and records their IP in a blocked_ips.txt file.

# 🛠️ Tech Stack

Python 3.8+: Core programming logic.

Flask: Web server and dashboard routing.

Scapy: Advanced packet manipulation and network analysis.

HTML/CSS/JS: Real-time interactive front-end.

# 🚀 Installation & Usage

⚠️ Prerequisite: Administrator Privileges

Because this tool sends raw network packets via Scapy, you MUST run the terminal as an Administrator (Windows) or use sudo (Linux/macOS).

Install Dependencies:

 ` pip install -r requirements.txt `


Run the Application:

# Windows (Run CMD as Administrator)
python app.py

# Linux / macOS
sudo python app.py


Access the Dashboard:
Open your browser and navigate to: http://127.0.0.1:5000

📁 File Structure

app.py: The Flask server, SSE stream logic, and mitigation rules.

simulator.py: Offensive logic containing Port Scan and ICMP Flood functions.

templates/index.html: The UI containing the live log box and attack controls.

requirements.txt: List of necessary Python libraries.

blocked_ips.txt: Auto-generated log of all blocked IP addresses.

📜 Disclaimer

This software is for Educational Purposes Only. Do not use this tool against any target without explicit authorization. The developer is not responsible for any misuse or damage caused by this application.
