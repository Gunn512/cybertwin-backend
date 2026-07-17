# Gunn Nguyen
from datetime import datetime, timezone

def get_scenario():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    return [
        {
            "step": 1,
            "timestamp": now,
            "source_ip": "6.6.6.6", 
            "source_name": "Attacker IP",
            "source_os": "Kali Linux",
            "target_ip": "8.8.8.8", 
            "target_name": "INTERNET",
            "target_os": "Gateway",
            "attack_technique": "Initial Access (T1190)",
            "severity": "medium",
        },
        {
            "step": 2,
            "timestamp": now,
            "source_ip": "8.8.8.8",
            "source_name": "INTERNET",
            "source_os": "Gateway",
            "target_ip": "10.0.0.4",
            "target_name": "Web Server",
            "target_os": "Ubuntu 22.04",
            "attack_technique": "Exploit Public-Facing Application (T1190)",
            "severity": "high",
        },
        {
            "step": 3,
            "timestamp": now,
            "source_ip": "10.0.0.4",
            "source_name": "Web Server",
            "source_os": "Ubuntu 22.04",
            "target_ip": "10.0.0.10",
            "target_name": "Database Server",
            "target_os": "CentOS 8",
            "attack_technique": "Lateral Movement & Privilege Escalation (T1021)",
            "severity": "critical",
        },
        {
            "step": 4,
            "timestamp": now,
            "source_ip": "10.0.0.10",
            "source_name": "Database Server",
            "source_os": "CentOS 8",
            "target_ip": "6.6.6.6",
            "target_name": "Attacker C2 Server",
            "target_os": "Unknown",
            "attack_technique": "Data Exfiltration to C2 (T1048)",
            "severity": "critical",
        }
    ]