# 🛠️ ARPWatch — Learn Before You Use

## What Is This Tool?

Imagine your office has a directory board on the wall. It lists every employee's name and their desk number. So when a package arrives for "Alice at Desk 14," the delivery person checks the board and knows exactly where to go.

Now imagine someone sneaks in at night and swaps the name cards. The board now says "Alice at Desk 14" but the card for Alice has been replaced with an attacker's name. The next morning, all of Alice's mail, packages, and visitors go to the attacker instead. The attacker reads everything, and Alice has no idea anything is wrong.

**ARPWatch is like a security camera for that directory board — but for your computer network.**

On a local network, computers use something called ARP (Address Resolution Protocol) to remember which device has which address. ARPWatch watches those mappings in real time and alerts you if someone tries to swap them — a trick called **ARP spoofing**.

---

## Why Does This Exist?

ARP spoofing is one of the oldest and most common attacks on local networks. Here's why it matters:

- **It's surprisingly easy to do.** Free tools exist that let attackers perform ARP spoofing in seconds, even with minimal technical knowledge.
- **It's invisible to the victim.** Your computer has no built-in way to know someone has tampered with its network address book.
- **It enables serious attacks.** Once an attacker controls the address mappings, they can intercept your passwords, emails, browsing sessions, and more.
- **It's preventable — if you detect it.** ARPWatch gives you that early warning system so you can act before real damage is done.

---

## Who Uses This in Real Life?

- **Network Security Engineers** — They deploy ARPWatch across corporate networks to catch misconfigurations and attacks on their switches and subnets.
- **SOC Analysts (Security Operations Center)** — They monitor alerts from tools like ARPWatch in real time, triaging potential breaches as they happen.
- **Penetration Testers** — They use ARPWatch to verify whether their ARP spoofing simulations during security audits would be detected.
- **IT Administrators** — They run ARPWatch on critical subnets (like server farms or finance departments) to ensure no one is tampering with network traffic.

---

## How Does It Work?

Here's what ARPWatch does, step by step:

1. **It starts listening.** When you launch ARPWatch, it puts your network card into "promiscuous mode," which means it captures every ARP packet on the local network — not just the ones addressed to your machine.

2. **It builds a memory book.** As ARP packets flow by, ARPWatch records every IP address it sees and the MAC address (the hardware identifier) that goes with it. For example: `192.168.1.1 → AA:BB:CC:DD:EE:FF`.

3. **It watches for changes.** Every time it sees a new ARP mapping, it compares it to its memory book. If an IP address suddenly claims to belong to a different MAC address, that's a red flag.

4. **It alerts you immediately.** When a suspicious change is detected, ARPWatch prints a message to your terminal telling you exactly what changed — which IP, what the old MAC was, and what the new MAC is.

5. **It keeps running.** ARPWatch doesn't stop after one alert. It continues monitoring indefinitely, logging every new or changed mapping so you have a full timeline of what happened on your network.

---

## Key Terms Explained

| Term | What It Means (In Plain English) |
|------|----------------------------------|
| **ARP** | Address Resolution Protocol. Think of it as the network's phone book — it translates IP addresses (names) into MAC addresses (actual hardware identities). |
| **MAC Address** | A unique serial number burned into every network device. Like a car's VIN — it's supposed to be permanent and unique to that device. |
| **IP Address** | A temporary address assigned to a device on a network. Like a seat number at a lunch table — it can change depending on where you sit. |
| **Spoofing** | Pretending to be someone else. In ARP spoofing, an attacker sends fake ARP messages to trick the network into associating their MAC address with someone else's IP. |
| **Poisoning** | Another name for ARP spoofing. "Poisoning" refers to the fact that the attacker corrupts (poisons) the ARP cache — the memory — of devices on the network. |
| **Gateway** | The door between your local network and the outside world (usually your router). All internet traffic passes through it, making it a prime target for ARP spoofing. |
| **Baseline** | A "known good" snapshot of what your network looks like when everything is normal. ARPWatch effectively builds a baseline over time and alerts you when reality deviates from it. |
| **MITM** | Man-In-The-Middle. The position an attacker achieves through ARP spoofing — they sit between you and your gateway, silently reading or modifying everything that passes through. |

---

## What Does the Output Mean?

When ARPWatch detects something, it prints messages to your terminal. Here's how to read them:

| Output Message | What It Means | Should You Worry? |
|----------------|---------------|-------------------|
| **"new station"** | ARPWatch just discovered a device it hasn't seen before. | Not necessarily — could be a new phone, laptop, or IoT device joining the network. |
| **"changed ethernet address"** | An IP address that used to belong to one MAC address now claims to belong to a different one. | ⚠️ Yes — this is the primary sign of ARP spoofing. Investigate immediately. |
| **"flip flop"** | The same IP address keeps switching back and forth between two MAC addresses. | ⚠️ Definitely suspicious — either a misconfiguration or an active attack. |
| **"old ethernet address"** | ARPWatch is reminding you of the previous MAC address before the change. | This is context for a "changed" alert — compare old vs. new to assess risk. |
| **"reuse old ethernet address"** | A previously seen MAC address has reappeared after being absent. | Could be a device reconnecting normally, or an attacker rotating spoofed addresses. |
| **"broadcast"** | An ARP request was sent to every device on the network (normal behavior). | No — this is just how ARP works normally. |

---

## Real Example Walkthrough

Let's walk through what happens during a real ARP spoofing attack and how ARPWatch catches it.

**The Setup:**
- Your router (gateway) is at IP `192.168.1.1` with MAC `AA:BB:CC:DD:EE:01`
- Your laptop is at IP `192.168.1.50` with MAC `AA:BB:CC:DD:EE:50`
- An attacker on the same Wi-Fi network is at IP `192.168.1.99` with MAC `AA:BB:CC:DD:EE:99`

**Step 1: Normal Operation**
ARPWatch has been running and has recorded:
```
192.168.1.1  → AA:BB:CC:DD:EE:01  (router)
192.168.1.50 → AA:BB:CC:DD:EE:50  (your laptop)
```

**Step 2: The Attacker Strikes**
The attacker sends fake ARP messages to your laptop saying:
*"Hey! I'm 192.168.1.1 (the router). My MAC address is AA:BB:CC:DD:EE:99."*

And to the router saying:
*"Hey! I'm 192.168.1.50 (your laptop). My MAC address is AA:BB:CC:DD:EE:99."*

**Step 3: ARPWatch Detects It**
ARPWatch sees the router's IP (`192.168.1.1`) suddenly claiming a new MAC address and prints:
```
changed ethernet address 192.168.1.1 AA:BB:CC:DD:EE:01 → AA:BB:CC:DD:EE:99
```

**Step 4: You Take Action**
You now know:
- Someone is pretending to be your router
- Their real MAC address is `AA:BB:CC:DD:EE:99`
- You can locate and disconnect this device, or alert your network administrator

Without ARPWatch, you would have had no idea this was happening. Your internet traffic would have been silently flowing through the attacker's machine.

---

## What This Tool CANNOT Do

It's important to understand ARPWatch's limitations:

- **Local network only.** ARP operates within a single subnet. ARPWatch cannot detect ARP spoofing happening on remote networks, across the internet, or on a different VLAN.
- **Detection only, not prevention.** ARPWatch tells you something is wrong — it does not automatically block the attacker or fix the problem. You still need to take action.
- **Cannot detect attacks it doesn't see.** If the attacker is on a different network segment (behind a router or on a switched port that isolates traffic), ARPWatch won't see their packets.
- **No encrypted traffic inspection.** ARPWatch doesn't read your data — it only watches address mappings. It won't tell you what the attacker did with your traffic.
- **Can produce false positives.** Legitimate network changes (a device getting a new NIC, a VM being cloned, a failover event) can trigger alerts. You need to investigate each one.

---

## ⚠️ Cautions and Warnings

**Requires elevated privileges:**
ARPWatch needs root (Linux/macOS) or Administrator (Windows) access to put your network card into promiscuous mode and capture packets. Running without these permissions will fail.

**Only monitor networks you have permission to monitor:**
Running ARPWatch on a network you do not own or administer may violate privacy laws and computer fraud statutes. Always get explicit written permission from the network owner.

**Legal Warning:**
Network monitoring tools can be misused. ARPWatch is designed for legitimate security monitoring and educational purposes only. Using this tool on networks without authorization is illegal in most jurisdictions and can result in criminal charges. The authors and distributors of this tool accept no responsibility for misuse.

**Not a complete security solution:**
ARPWatch is one piece of a larger security strategy. It should be combined with proper network segmentation, static ARP entries for critical devices, Dynamic ARP Inspection (DAI) on managed switches, and encryption (HTTPS, VPN) for sensitive traffic.

---

## 🎓 Learning Path

If you're new to this topic, here's a suggested order to build your understanding:

1. **Start here** — Read this document fully.
2. **Learn the basics of networking** — Understand what IP addresses and MAC addresses are, and how devices communicate on a local network. (Resource: "Computer Networking: A Top-Down Approach" by Kurose & Ross)
3. **Understand ARP deeply** — Look up how ARP requests and replies work. Try running `arp -a` in your terminal to see your own ARP table.
4. **Experiment safely** — Set up a small test network (or use virtual machines) and run ARPWatch to see what normal traffic looks like.
5. **Explore related tools** — Look into Wireshark (to see ARP packets visually), arp-scan (to actively discover devices), and Ettercap (to understand how attackers perform ARP spoofing — for educational purposes only).
6. **Learn about defenses** — Study Dynamic ARP Inspection (DAI), static ARP entries, and 802.1X port-based authentication.
7. **Practice detection** — Use ARPWatch alongside a controlled ARP spoofing exercise to see how quickly you can identify and respond to the attack.

---

## 📚 Further Reading

- **RFC 826** — The original ARP specification: https://tools.ietf.org/html/rfc826
- **"ARP Spoofing and Poisoning"** — SANS Institute reading room: https://www.sans.org/reading-room/
- **Wireshark ARP Analysis** — How to capture and inspect ARP traffic: https://www.wireshark.org/docs/
- **"The TCP/IP Guide"** — Comprehensive networking reference: http://www.tcpipguide.com/
- **NIST Guide to Enterprise Telework Security** — Covers ARP-related risks in remote work: https://csrc.nist.gov/publications
- **"Hacking Exposed"** (McClure, Scambray, Kurtz) — Classic book covering ARP attacks and defenses in practical detail.
- **Cisco: Dynamic ARP Inspection Configuration** — How enterprise switches defend against ARP spoofing: https://www.cisco.com
