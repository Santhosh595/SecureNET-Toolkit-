"""
MITRE ATT&CK Mapping
Maps detection rules to ATT&CK techniques and generates Navigator layers.
"""

import json
from typing import List, Dict


# ATT&CK Technique definitions
TECHNIQUES = {
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access, Persistence, Privilege Escalation, Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1110.003": {
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "T1078.003": {
        "name": "Valid Accounts: Local Accounts",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/003/",
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1059.007": {
        "name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1078.002": {
        "name": "Valid Accounts: Domain Accounts",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1078/002/",
    },
    "T1543.003": {
        "name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence, Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1543/003/",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1030": {
        "name": "Data Transfer Size Limits",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1030/",
    },
}

# Rule name to MITRE technique mapping
RULE_TO_MITRE = {
    "SSH Brute Force": "T1110.001",
    "SSH Success After Failures": "T1078",
    "Credential Stuffing": "T1110.003",
    "Off-Hours Login": "T1078",
    "Root Login Attempt": "T1078.003",
    "Web Scanner Detection": "T1595",
    "Directory Traversal": "T1083",
    "SQL Injection": "T1190",
    "XSS Attempt": "T1059.007",
    "Port Scan Detected": "T1046",
    "Privilege Escalation (Windows)": "T1078.002",
    "New Service Installed": "T1543.003",
    "Repeated 403/401 Responses": "T1110",
    "Large Data Transfer": "T1030",
    "Geographic Anomaly": "T1078",
}


def get_technique_info(mitre_id: str) -> dict:
    """Get technique information by ID."""
    return TECHNIQUES.get(mitre_id, {
        "name": "Unknown Technique",
        "tactic": "Unknown",
        "url": "",
    })


def get_tactics_covered(alerts: list) -> list:
    """Get list of ATT&CK tactics covered by alerts."""
    tactics = set()
    for alert in alerts:
        mitre_id = alert.get("mitre_id", "")
        if mitre_id and mitre_id in TECHNIQUES:
            tactic_str = TECHNIQUES[mitre_id].get("tactic", "")
            for tactic in tactic_str.split(","):
                tactics.add(tactic.strip())
    return sorted(tactics)


def get_techniques_triggered(alerts: list) -> list:
    """Get list of techniques triggered by alerts with counts."""
    technique_counts = {}
    for alert in alerts:
        mitre_id = alert.get("mitre_id", "")
        if mitre_id:
            if mitre_id not in technique_counts:
                technique_counts[mitre_id] = {
                    "id": mitre_id,
                    "count": 0,
                    "alerts": [],
                }
            technique_counts[mitre_id]["count"] += 1
            technique_counts[mitre_id]["alerts"].append(alert.get("rule_name", ""))

    result = []
    for tid, data in technique_counts.items():
        info = TECHNIQUES.get(tid, {})
        result.append({
            "technique_id": tid,
            "name": info.get("name", "Unknown"),
            "tactic": info.get("tactic", "Unknown"),
            "count": data["count"],
            "rules": list(set(data["alerts"])),
        })

    result.sort(key=lambda x: -x["count"])
    return result


def build_attack_navigator_layer(alerts: list, title: str = "LogSentry Detection Results") -> dict:
    """Build an ATT&CK Navigator layer JSON."""
    techniques = get_techniques_triggered(alerts)

    layer = {
        "name": title,
        "versions": {
            "attack": "15",
            "navigator": "4.9.1",
            "layer": "4"
        },
        "domain": "enterprise-attack",
        "description": "LogSentry detected ATT&CK techniques from log analysis",
        "filters": {
            "platforms": ["windows", "linux", "mac"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "1-5 detections", "color": "#ffe766"},
            {"label": "6-20 detections", "color": "#ff9900"},
            {"label": "20+ detections", "color": "#ff6666"}
        ],
        "metadata": [
            {"name": "Generated by", "value": "LogSentry"}
        ],
        "links": [
            {
                "label": "ATT&CK Navigator",
                "url": "https://mitre-attack.github.io/attack-navigator/"
            }
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }

    for tech in techniques:
        score = min(tech["count"] * 20, 100)
        technique_entry = {
            "techniqueID": tech["technique_id"],
            "tactic": tech["tactic"].split(",")[0].strip() if tech["tactic"] else "Discovery",
            "score": score,
            "color": "",
            "comment": f"Detected {tech['count']} time(s) by: {', '.join(tech['rules'])}",
            "enabled": True,
            "showSubtechniques": False
        }
        layer["techniques"].append(technique_entry)

    return layer
