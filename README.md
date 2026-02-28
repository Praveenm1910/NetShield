# 🛡️ NetShield – Intrusion Detection & Prevention System (IDPS)

NetShield is a lightweight Intrusion Detection and Prevention System (IDPS) designed to detect and mitigate common Layer 2 and Layer 3 network attacks in real time.  

It is built using **C (libpcap)** for high-speed packet capture and detection, and **Python** for logging, alerting, and cloud dashboard integration.

---

## 📌 Project Objective

The goal of NetShield is to:

- Detect ARP Spoofing attacks
- Detect DDoS attacks based on traffic thresholds
- Automatically block malicious IP addresses
- Send real-time email alerts
- Log attack data to Firebase
- Display attack data on a live monitoring dashboard

This project demonstrates practical implementation of:

- Packet sniffing
- Network intrusion detection
- Automated prevention mechanisms
- Cloud-based logging
- Real-time monitoring systems

---

## 🔎 Features

### 1️⃣ ARP Spoofing Detection

- Monitors ARP packets in real time
- Detects multiple MAC addresses claiming the same IP
- Identifies IP-MAC inconsistencies
- Logs attacker details
- Triggers prevention mechanism

### 2️⃣ DDoS Detection

- Tracks incoming packet rate per IP
- Uses threshold-based detection
- Identifies abnormal traffic spikes
- Flags potential attackers

### 3️⃣ Automatic IP Blocking

- Blocks malicious IP addresses using iptables
- Prevents further traffic from attacker
- Reduces impact of active attacks

### 4️⃣ Email Alert System

- Sends instant alert notifications
- Includes:
  - Attack Type
  - Attacker IP
  - Timestamp
- Enables quick administrative response

### 5️⃣ Firebase Cloud Logging

- Pushes attack logs to Firebase
- Stores structured attack records
- Enables remote monitoring

### 6️⃣ Live Web Dashboard

- Displays:
  - Recent ARP attacks
  - Recent DDoS attacks
  - Real-time traffic logs
- Helps visualize network security status

---

## 🛠️ Technologies Used

| Component | Technology |
|-----------|------------|
| Packet Capture | C + libpcap |
| Detection Engine | C |
| Logging System | Python |
| Firewall Integration | iptables |
| Cloud Storage | Firebase |
| Alert System | SMTP (Email) |
| Dashboard | Web Interface |
