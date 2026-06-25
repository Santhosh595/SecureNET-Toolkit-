# 🛠️ Network Sniffer — Learn Before You Use

Welcome! If you've never used a network sniffer before, this guide will walk you through everything you need to know — no technical background required. By the end, you'll understand what this tool does, how it works, and how to use it safely and responsibly.

---

## What Is This Tool?

Imagine a **security guard** standing at the entrance of a building. Every person who walks in or out is noted down: what time they arrived, where they came from, where they're going, and whether they're acting suspiciously. If someone tries to enter through a back door they shouldn't be using, or if 100 people rush in at once, the guard raises an alarm.

That's exactly what this tool does — but for your **network traffic**.

A **network sniffer** is a program that watches all the data flowing in and out of your computer's network connection. It captures each piece of data (called a "packet"), writes it down, and flags anything that looks unusual or threatening.

This particular tool:
- Captures live network packets using a library called **Scapy**
- Stores the captured data in a **SQLite database** (a lightweight, file-based database)
- Automatically detects suspicious patterns like **port scans** (someone probing your computer for open doors) and **packet floods** (a denial-of-service attack)

---

## Why Does This Exist?

Every day, your computer sends and receives thousands of data packets — when you browse a website, check email, stream a video, or even just stay connected to Wi-Fi. Most of this traffic is normal and safe. But sometimes, malicious actors try to:

- **Scan your computer** for vulnerabilities they can exploit
- **Flood your connection** with fake traffic to knock you offline
- **Intercept sensitive data** traveling across the network

This tool exists so you can **see what's happening on your network** in real time. You can't defend against threats you can't see. By monitoring your traffic, you can spot attacks early, understand what's happening, and take action before damage is done.

---

## Who Uses This in Real Life?

In the professional world, network sniffers are used by:

| Role | What They Use It For |
|------|---------------------|
| **SOC Analysts** (Security Operations Center) | Monitor network traffic 24/7, detect and respond to threats in real time |
| **Network Administrators** | Troubleshoot connectivity issues, monitor bandwidth usage, and ensure network health |
| **Security Engineers** | Build and test security systems, verify that firewalls and intrusion detection systems are working |
| **Incident Responders** | Investigate security breaches after they happen, figure out what data was accessed and how the attacker got in |
| **Penetration Testers** | Ethically hack into systems (with permission) to find vulnerabilities before real attackers do |

If you're a student, a hobbyist, or someone just getting into cybersecurity, this tool is a great way to learn how networks actually work.

---

## How Does It Work?

Here's a step-by-step breakdown of what happens when you run this tool:

1. **You launch the tool** — it asks you which network interface to monitor (e.g., your Wi-Fi adapter or Ethernet port).

2. **The tool starts listening** — using Scapy, it puts your network card into "promiscuous mode," which means it captures every packet it sees, not just the ones addressed to your computer.

3. **Each packet is captured** — as data flows across the network, the tool grabs each packet and extracts key information: source IP, destination IP, port numbers, protocol type, and payload size.

4. **Data is stored in SQLite** — every captured packet is saved into a local SQLite database file. This means you can go back later and review what happened, search for specific events, or analyze patterns over time.

5. **Intrusion detection runs in real time** — the tool continuously analyzes the traffic for suspicious patterns:
   - **Port scan detection**: If one IP address tries to connect to many different ports on your machine in a short time, that's flagged.
   - **Packet flood detection**: If your connection is suddenly overwhelmed with an enormous number of packets from a single source, that's flagged.

6. **Alerts are generated** — when suspicious activity is detected, the tool raises an alert so you know something unusual is happening.

7. **You review the results** — you can look at the captured data, read the alerts, and decide what action to take (block an IP, investigate further, etc.).

---

## Key Terms Explained

Before you go further, let's make sure you understand the jargon:

| Term | Simple Explanation |
|------|-------------------|
| **Packet** | A small chunk of data sent across a network. Think of it like a letter in an envelope — it has a sender, a recipient, and a message inside. |
| **IP Address** | A unique number assigned to every device on a network (like `192.168.1.1`). It's like a street address for your computer. |
| **Port** | A numbered "door" on your computer. Different services use different ports — websites use port 80/443, email uses port 25/587, etc. There are 65,535 possible ports. |
| **Protocol** | A set of rules for how data is formatted and transmitted. It's like the language two computers agree to speak to each other. |
| **TCP** (Transmission Control Protocol) | A reliable, connection-oriented protocol. It makes sure every packet arrives and is in the right order. Used for web browsing, email, file transfers. Like sending a registered letter with delivery confirmation. |
| **UDP** (User Datagram Protocol) | A fast, connectionless protocol. It sends data without checking if it arrived. Used for video streaming, online gaming, DNS lookups. Like shouting into a crowd — fast, but no guarantee everyone heard you. |
| **Intrusion** | Any unauthorized attempt to access or compromise your system. Someone trying to break in. |
| **Flood** | An attack where the attacker sends a massive number of packets to overwhelm your connection or system, making it unavailable. Like sending millions of letters to someone's mailbox so they can't receive any real mail. |
| **Port Scan** | When an attacker systematically checks many ports on your computer to find which ones are open and vulnerable. Like trying every door handle in a building to see which doors are unlocked. |
| **Alert** | A notification from the tool telling it that it detected something suspicious. It's the digital equivalent of a warning light on your dashboard. |

---

## What Does the Output Mean?

When you run the tool, you'll see output that looks something like this. Here's how to read it:

| Output Field | What It Means |
|-------------|---------------|
| **Timestamp** | The exact date and time when the packet was captured. |
| **Source IP** | The IP address of the computer that sent the packet. |
| **Destination IP** | The IP address of the computer that received the packet. |
| **Source Port** | The port number on the sender's side. |
| **Destination Port** | The port number on the receiver's side (tells you what service the packet is trying to reach). |
| **Protocol** | Whether the packet uses TCP, UDP, or another protocol. |
| **Length/Size** | How big the packet is, in bytes. |
| **Flags** | Extra information about the packet's purpose (e.g., SYN = starting a connection, ACK = acknowledging receipt). |
| **Alert Message** | If the tool detected something suspicious, this column explains what the threat is (e.g., "Port scan detected from 10.0.0.5"). |

---

## Real Example Walkthrough

Let's walk through a realistic scenario of using this tool:

**Scenario**: You've noticed your internet has been slow lately, and you suspect something is wrong.

1. **You start the sniffer** and select your Wi-Fi interface.

2. **For a few minutes**, the tool quietly captures traffic. You see normal stuff: packets going to `google.com` (port 443), your email client checking for new messages (port 993), a video streaming (port 443).

3. **Suddenly, the tool raises an alert**: ⚠️ "Port scan detected from 192.168.1.105"

4. **You investigate**: Looking at the database, you see that `192.168.1.105` has tried to connect to ports 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443 — all within 30 seconds. That's a classic port scan.

5. **You check your router**: `192.168.1.105` is your roommate's computer. Either their machine is compromised (malware is scanning the network), or they're running a network tool without realizing it.

6. **You take action**: You talk to your roommate, discover their antivirus flagged nothing, and suggest they scan their machine. Problem identified and resolved.

**Without the sniffer**, you'd just have slow internet and no idea why. **With the sniffer**, you found the source in minutes.

---

## What This Tool CANNOT Do

It's important to understand the limitations so you have realistic expectations:

- ❌ **It only monitors your own network interface** — it can't see traffic on other networks, other devices (unless they pass through your machine), or traffic on the broader internet.

- ❌ **It cannot decrypt HTTPS traffic** — most modern web traffic is encrypted (the padlock icon in your browser). The tool can see *that* you visited `bank.com`, but it cannot see *what* you did there (passwords, account numbers, etc.).

- ❌ **It is not a firewall** — it detects and alerts, but it does not automatically block threats. You need to take action yourself.

- ❌ **It cannot detect all attacks** — sophisticated attacks that mimic normal traffic may slip through. It focuses on port scans and packet floods specifically.

- ❌ **It won't work without proper permissions** — capturing packets requires administrator/root access (explained below).

- ❌ **It cannot analyze wireless traffic on all systems** — some Wi-Fi adapters don't support promiscuous mode properly.

---

## ⚠️ Cautions and Warnings

### Requires Administrator/Root Access
Packet capture needs elevated privileges. On Windows, you must run the tool as Administrator. On Linux/Mac, you need `sudo`. This is because reading raw network data is a sensitive operating system operation — it's a security feature, not a bug.

### Legal Warning — Read This Carefully

> **Capturing network traffic on networks you do NOT own or have explicit permission to monitor is ILLEGAL.**

- **India**: Under the **Information Technology Act, 2000** (Section 43 and Section 66), unauthorized interception of electronic data is a punishable offense, potentially carrying fines and imprisonment up to 3 years.

- **USA**: Under the **Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), unauthorized access to computer systems and network monitoring without authorization is a federal crime, carrying penalties of up to 10 years imprisonment for a first offense.

- **European Union**: Under the **GDPR** and various national computer misuse laws, intercepting personal data without consent is illegal.

- **Most countries** have similar legislation. When in doubt, **don't capture traffic on any network you don't explicitly own or have written permission to monitor.**

### Safe Usage Guidelines
- ✅ Use only on your own home network or lab environment
- ✅ Use only on networks where you have explicit written authorization
- ✅ Use for educational purposes, security testing of your own systems, and troubleshooting
- ❌ Never use on public Wi-Fi, workplace networks (unless authorized), or any network you don't own
- ❌ Never use to intercept other people's private communications

---

## 🎓 Learning Path

If you're new to networking and cybersecurity, here's a suggested learning path to get the most out of this tool:

1. **Learn basic networking** — Understand IP addresses, ports, and how the internet works. (Resource: "Computer Networking: A Top-Down Approach" by Kurose & Ross)

2. **Understand TCP vs UDP** — These are the two most common protocols. Know the difference and when each is used.

3. **Learn about the OSI Model** — This is a 7-layer framework that explains how data travels across networks. You don't need to memorize it, but understanding the basics helps.

4. **Practice with this tool** — Run it on your own network and observe normal traffic. Get a feel for what "normal" looks like.

5. **Study common attacks** — Learn about port scans, DDoS attacks, man-in-the-middle attacks, and phishing. Understanding attacks helps you recognize them.

6. **Explore Wireshark** — Wireshark is the industry-standard network analyzer. It's more advanced but incredibly powerful. This tool is a great stepping stone to Wireshark.

7. **Learn about firewalls and IDS** — Understand how firewalls filter traffic and how Intrusion Detection Systems (IDS) like Snort work.

8. **Get certified** — If you want a career in cybersecurity, consider CompTIA Network+, CompTIA Security+, or the CEH (Certified Ethical Hacker).

---

## 📚 Further Reading

Here are some excellent resources to deepen your understanding:

### Books
- **"Computer Networking: A Top-Down Approach"** by James Kurose & Keith Ross — The best beginner-friendly networking textbook
- **"The Web Application Hacker's Handbook"** by Dafydd Stuttard — Great for understanding web security
- **"Practical Packet Analysis"** by Chris Sanders — Teaches you how to analyze network traffic with real tools

### Online Resources
- **Wireshark User Guide**: https://www.wireshark.org/docs/ — Learn the gold-standard network analyzer
- **Scapy Documentation**: https://scapy.readthedocs.io/ — The library this tool uses for packet capture
- **K Networking Basics** (Cisco): https://www.cisco.com/c/en/us/solutions/enterprise-networks/what-is-computer-networking.html
- **OWASP**: https://owasp.org/www-project-top-ten/ — The top 10 web security risks

### Tools to Explore Next
- **Wireshark** — Full-featured network protocol analyzer with a graphical interface
- **tcpdump** — Command-line packet capture tool (built into most Linux/Mac systems)
- **Snort** — Open-source intrusion detection system
- **Nmap** — Network scanning tool (the kind of tool this sniffer detects!)

### Videos
- **NetworkChuck on YouTube** — Fun, beginner-friendly networking tutorials
- **Professor Messer** — Free CompTIA Network+ and Security+ video courses

---

*Remember: With great power comes great responsibility. Use this tool ethically, legally, and for learning. The best security professionals are those who understand the technology deeply and use it to protect, not harm.*
