# 🛠️ LogSentry — Learn Before You Use

## What Is This Tool? (The Simple Version)

A hotel keeps a logbook of everyone who enters and
leaves. LogSentry reads that logbook and flags:
someone tried 100 wrong room keys, someone entered
at 3AM, someone went to floors they shouldn't access.

It ingests logs from multiple sources (Linux auth,
web servers, Windows Events, firewalls), normalizes
them into a unified format, runs detection rules,
and generates incident reports.

## Why Does This Exist? (The Problem It Solves)

Attackers leave traces in logs. A brute force attack
[trying thousands of passwords] shows up as hundreds
of failed login attempts. A successful breach shows
up as unusual access patterns.

Without automated log analysis, these signals get
buried in millions of lines of text. LogSentry finds
the needle in the haystack.

## Who Uses This in Real Life?

- SOC analysts [Security Operations Center — people
  who monitor for attacks 24/7]
- Incident responders investigating breaches
- System administrators monitoring server health
- Compliance auditors checking access logs

## How Does It Work? (Step by Step, Plain English)

1. You point it at a log file (or it auto-detects
   the format)
2. It normalizes the data [converts different formats
   into one standard structure]
3. It runs 15 detection rules against the data:
   - Brute force attacks (many failed logins)
   - Successful logins after many failures
   - Off-hours access (3AM logins)
   - Privilege escalation (user became admin)
   - Impossible travel (login from India then USA
     5 minutes later)
   - New admin accounts created
   - Password spraying (one password, many users)
   - Command injection in web logs
   - SQL injection attempts
   - Directory traversal attempts
   - Scanner activity (Nikto, sqlmap user agents)
   - Malware callback patterns
   - Data exfiltration indicators
   - Configuration changes
   - Account lockouts
4. It correlates events across sources [connects
   dots between different log types]
5. It maps findings to MITRE ATT&CK [a framework
   that describes how attackers operate]
6. It generates an incident report with timeline,
   severity, and recommended actions

## Key Terms Explained (Glossary)

**Log** — a record of events on a computer. Like a
security camera recording everything that happens.

**Auth Log** — records of who logged in, when, and
whether they succeeded. Like a sign-in sheet.

**Event ID** — a number that identifies what type of
event occurred. Like a category code.

**Brute Force** — trying every possible password until
one works. Like trying every key on a keyring.

**MITRE ATT&CK** — a knowledge base of attacker tactics.
Like a criminal playbook that security teams use to
recognize attacks.

**Correlation** — connecting events from different sources
to see the full picture. Like combining security camera
footage with door access logs.

**Anomaly** — something that doesn't fit the normal
pattern. Like someone entering your office at 3AM.

**Incident** — a confirmed security event that needs
investigation. Like a break-in.

**Normalization** — converting different log formats
into one standard structure. Like translating multiple
languages into English.

## What Does the Output Mean?

| Result | What It Means | What To Do |
|--------|---------------|------------|
| INFO | Normal activity, logged for reference | No action needed |
| LOW | Slightly unusual, probably benign | Note it |
| MEDIUM | Worth investigating | Check the details |
| HIGH | Likely an attack in progress | Investigate now |
| CRITICAL | Confirmed breach or active attack | Respond immediately |

## Real Example Walkthrough

You have an auth.log with 10,000 lines. You run
LogSentry and it finds:

```
CRITICAL: Brute force attack detected
  Source IP: 192.168.1.100
  Target accounts: root, admin, user
  Failed attempts: 847
  Time window: 14:32 - 14:47
  Result: Successful login as 'admin' at 14:47

HIGH: Privilege escalation detected
  User: admin
  Action: sudo su -
  Time: 14:48

MEDIUM: Off-hours access
  User: admin
  Time: 03:12 (next day)
```

This tells you an attacker brute-forced the admin
password, got in, became root, and came back that
night. You need to reset all passwords and check
for backdoors.

## What This Tool CANNOT Do (Limitations)

- It can only analyze logs you provide
- It cannot detect attacks not captured in logs
- It may produce false positives on unusual but
  legitimate activity
- It does not block attacks, only detects them

## ⚠️ Cautions and Warnings

### Before You Use This Tool:
- Only analyze logs from systems you administer
- Logs may contain sensitive user data (IPs,
  usernames, sometimes passwords)
- Ensure you have authorization to access the logs

### What Can Go Wrong:
- Analyzing logs without authorization may violate
  privacy laws
- False positives may waste investigation time
- Large log files may take significant processing time

### Legal Warning:
Using this tool on systems without permission may violate:
- India: IT Act 2000, Section 43 and 66
- USA: Computer Fraud and Abuse Act (CFAA)
- And equivalent laws in your country

## 🎓 Learning Path (What to Learn Next)

- **SIEM systems** — learn about enterprise log
  management (Splunk, ELK, Wazuh)
- **Incident response** — understand the full process
  of handling a security breach
- **Forensic analysis** — learn how to preserve and
  analyze digital evidence
- **MITRE ATT&CK framework** — study the full attacker
  playbook

## 📚 Further Reading

- [MITRE ATT&CK](https://attack.mitre.org/) — free framework
- [OWASP Logging Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [TryHackMe: SOC Level 1](https://tryhackme.com) — free path
- [Wikipedia: Log Analysis](https://en.wikipedia.org/wiki/Log_analysis)
