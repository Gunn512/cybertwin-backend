from datetime import datetime, timezone

def get_scenario():
    # Tự động lấy thời gian thực mỗi khi kịch bản được gọi
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    return [
        {
            "step": 1,
            "timestamp": now,
            "source_ip": "114.12.5.88",
            "source_name": "Attacker IP",
            "source_os": "Kali Linux",
            "target_ip": "10.0.0.4",
            "target_name": "Web Server",
            "target_os": "Ubuntu 22.04",
            "attack_technique": "Exploit Public-Facing Application (T1190)",
            "severity": "critical",
        },
        {
            "step": 2,
            "timestamp": now,
            "source_ip": "10.0.0.4",
            "source_name": "Web Server",
            "source_os": "Ubuntu 22.04",
            "target_ip": "10.0.0.10",
            "target_name": "Database Server",
            "target_os": "Windows Server 2022",
            "attack_technique": "Lateral Movement (T1021)",
            "severity": "high",
        },
        {
            "step": 3,
            "timestamp": now,
            "source_ip": "10.0.0.10",
            "source_name": "Database Server",
            "source_os": "Windows Server 2022",
            "target_ip": "185.34.12.90",
            "target_name": "External C2 Server",
            "target_os": "Unknown",
            "attack_technique": "Exfiltration Over Alternative Protocol (T1048)",
            "severity": "critical",
        }
    ]