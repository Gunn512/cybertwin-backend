from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models import SecurityAlert

def correlate_alerts(db: Session, time_window_minutes: int = 5) -> list:
    """
    Thuật toán gom cụm (Correlation Engine) xâu chuỗi các cảnh báo bảo mật 
    dựa trên thiết bị nguồn/đích và khoảng thời gian sát nhau.
    """
    # Lấy toàn bộ alert sắp xếp theo thời gian tăng dần
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.timestamp.asc()).all()
    
    if not alerts:
        return []

    chains = []
    current_chain = []

    for alert in alerts:
        if not current_chain:
            current_chain.append(alert)
            continue

        last_alert = current_chain[-1]
        
        # Kiểm tra điều kiện gom cụm:
        # 1. Cùng IP nguồn hoặc cùng luồng (source_device_id / target_device_id)
        # 2. Khoảng thời gian giữa 2 alert nằm trong ngưỡng time_window_minutes
        same_actors = (
            alert.source_device_id == last_alert.source_device_id or
            alert.target_device_id == last_alert.target_device_id or
            alert.source_device_id == last_alert.target_device_id # Di chuyển ngang (lateral movement)
        )
        
        # Xử lý tính toán chênh lệch thời gian an toàn
        try:
            t1 = datetime.fromisoformat(last_alert.timestamp)
            t2 = datetime.fromisoformat(alert.timestamp)
            time_diff = abs(t2 - t1) <= timedelta(minutes=time_window_minutes)
        except Exception:
            time_diff = True # Fallback nếu định dạng chuỗi thời gian khác biệt

        if same_actors and time_diff:
            current_chain.append(alert)
        else:
            # Lưu chuỗi cũ và khởi tạo chuỗi mới
            chains.append(current_chain)
            current_chain = [alert]

    if current_chain:
        chains.append(current_chain)

    # Định dạng lại kết quả trả về dưới dạng các chuỗi hành vi liên tục có ý nghĩa
    formatted_chains = []
    for idx, chain in enumerate(chains, start=1):
        formatted_chains.append({
            "chain_id": f"CHAIN_{idx:03d}",
            "total_events": len(chain),
            "start_time": chain[0].timestamp,
            "end_time": chain[-1].timestamp,
            "techniques": [a.attack_technique for a in chain],
            "alert_ids": [a.id for a in chain]
        })

    return formatted_chains