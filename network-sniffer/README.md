# 🕵️‍♂️ Network Sniffer — Real-Time IDS Dashboard

**Author:** Santhosh L  
**Project Name:** `network-sniffer`  
**Description:**  
A Python-based **Network Packet Sniffer** with a **real-time Flask dashboard** that monitors live network traffic, logs suspicious packets, and displays real-time alerts.  
This project demonstrates the basics of an **Intrusion Detection System (IDS)** and real-time security monitoring.

---

## 🚀 Features

- 🧠 **Real-Time Packet Capture** — Monitors live network packets with Scapy.  
- ⚠️ **Alert System** — Detects suspicious activity (like SYN flood or unusual traffic).  
- 🗄️ **SQLite Integration** — Logs all captured packet data for analysis.  
- 🌐 **Flask Web Dashboard** — Displays captured packets and alerts live.  
- 🔥 **Extensible** — Easily add new detection rules or alert types.  
- 🕵️ **Educational Purpose** — Great for learning networking and Python security.

---



---

python3 -m venv venv
source venv/bin/activate
pip install flask scapy

▶️ How to Run
🧩 Option 1 — Run both manually

Open two terminals:

Terminal 1 (Flask dashboard):

python3 app.py


Terminal 2 (Sniffer):

sudo python3 sniffer_alert2.py


Now open your browser and go to:

http://127.0.0.1:5000


You’ll see your live dashboard update every 2 seconds.

⚡ Option 2 — Use startup script

If you want to automate it, create a script called start_all.sh:

#!/bin/bash
echo "[+] Starting Network Sniffer Dashboard..."
sudo python3 sniffer_alert2.py &
sleep 2
python3 app.py


Make it executable:

chmod +x start_all.sh


Then run:

./start_all.sh

🧰 Example Output

Terminal (Sniffer):

[+] Sniffer started...
[ALERT] Possible SYN flood detected from 192.168.1.7
[+] Packet logged to database.


Flask Dashboard (Browser):

ID	Timestamp	Source	Destination	Proto	Length	Flags	Alert
1	2025-10-27 12:45:23	192.168.1.7	8.8.8.8	TCP	60	SYN	SYN Flood Detected
2	2025-10-27 12:46:01	192.168.1.10	8.8.8.8	ICMP	84	None	Normal Traffic
🧩 Future Improvements

🔒 Add a Threat Level Indicator (visual risk meter)

📊 Traffic graph for visualization

🧑‍💻 User authentication for web dashboard

☁️ Cloud integration for remote monitoring
🪪 License

This project is licensed under the MIT License — free for personal and educational use.

❤️ Acknowledgments

Built using Python, Flask, and Scapy

Inspired by Wireshark & Snort IDS concepts

Developed by Santhosh L as part of a cybersecurity learning project

📬 Contact

Author: Santhosh L
GitHub: https://github.com/<your-username>


---

## ⚙️ **.gitignore**
> Create file:  
> `nano .gitignore`

Paste this 👇  


Python cache

pycache/
*.pyc

Databases and logs

*.db
*.log

Virtual environment

venv/

Test and setup files

day1/
day4/
old/
setup_day4.sh


---

## 🪪 **LICENSE**
> Create file:  
> `nano LICENSE`

Paste this 👇  



MIT License

Copyright (c) 2025 Santhosh L

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.