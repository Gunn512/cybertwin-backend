from datetime import datetime, timezone

def get_scenario():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    return [
        {
            "step": 1,
            "timestamp": now,
            "source_ip": "203.0.113.45",
            "source_name": "Botnet Node 1",
            "source_os": "Unknown",
            "target_ip": "10.0.0.100",
            "target_name": "Admin Jumpbox",
            "target_os": "CentOS 8",
            "attack_technique": "Brute Force: Password Guessing (T1110.001)",
            "severity": "medium",
            "description": "Ghi nhận 500 lần đăng nhập thất bại vào tài khoản 'root' qua SSH trong 5 phút."
        },
        {
            "step": 2,
            "timestamp": now,
            "source_ip": "203.0.113.45",
            "source_name": "Botnet Node 1",
            "source_os": "Unknown",
            "target_ip": "10.0.0.100",
            "target_name": "Admin Jumpbox",
            "target_os": "CentOS 8",
            "attack_technique": "Valid Accounts (T1078)",
            "severity": "high",
            "description": "Đăng nhập thành công vào tài khoản 'root' từ IP Botnet."
        },
        {
            "step": 3,
            "timestamp": now,
            "source_ip": "10.0.0.100",
            "source_name": "Admin Jumpbox",
            "source_os": "CentOS 8",
            "target_ip": "10.0.0.200",
            "target_name": "Core Switch",
            "target_os": "Cisco IOS",
            "attack_technique": "Network Service Discovery (T1046)",
            "severity": "critical",
            "description": "Từ Admin Jumpbox, kẻ tấn công rà quét các thiết bị mạng nội bộ."
        }
    ]