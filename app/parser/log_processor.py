from sqlalchemy.orm import Session
from app.models import Device, SecurityAlert
from datetime import datetime
import uuid

def process_raw_log(db: Session, log_data: dict):
    """
    Hàm xử lý log thô, tự động chuẩn hóa dữ liệu, cập nhật danh sách thiết bị (Nodes)
    và ghi nhận hành vi tấn công (Edges) vào Database.
    """
    try:
        # 1. Bóc tách các trường thông tin cốt lõi từ log thô
        src_ip = log_data.get("source_ip")
        dst_ip = log_data.get("target_ip")
        src_name = log_data.get("source_name", "Unknown Device")
        dst_name = log_data.get("target_name", "Unknown Server")
        technique = log_data.get("attack_technique")
        severity = log_data.get("severity", "medium").lower()
        
        if not src_ip or not dst_ip or not technique:
            return {"status": "error", "message": "Dữ liệu log thiếu các trường bắt buộc (source_ip, target_ip, attack_technique)"}

        # 2. Xử lý THIẾT BỊ NGUỒN (Source Node)
        # Kiểm tra xem IP nguồn đã tồn tại trong bảng devices chưa
        source_device = db.query(Device).filter(Device.ip_address == src_ip).first()
        if not source_device:
            # Nếu chưa có, tự động tạo mới một Node thiết bị
            src_id = f"N_{uuid.uuid4().hex[:6]}" # Tạo ID ngắn ngẫu nhiên, ví dụ: N_a1b2c3
            source_device = Device(
                id=src_id,
                ip_address=src_ip,
                device_name=src_name,
                os_type=log_data.get("source_os", "Unknown")
            )
            db.add(source_device)
            db.flush() # Đẩy dữ liệu tạm thời xuống để lấy ID sử dụng tiếp

        # 3. Xử lý THIẾT BỊ ĐÍCH (Target Node)
        # Kiểm tra xem IP đích đã tồn tại trong bảng devices chưa
        target_device = db.query(Device).filter(Device.ip_address == dst_ip).first()
        if not target_device:
            # Nếu chưa có, tự động tạo mới một Node thiết bị đích
            dst_id = f"N_{uuid.uuid4().hex[:6]}"
            target_device = Device(
                id=dst_id,
                ip_address=dst_ip,
                device_name=dst_name,
                os_type=log_data.get("target_os", "Unknown")
            )
            db.add(target_device)
            db.flush()

        # 4. Ghi nhận HÀNH VI TẤN CÔNG (Edge) vào bảng security_alerts
        edge_id = f"E_{uuid.uuid4().hex[:6]}" # Tạo ID ngắn cho đường liên kết
        new_alert = SecurityAlert(
            id=edge_id,
            source_device_id=source_device.id,
            target_device_id=target_device.id,
            attack_technique=technique,
            severity=severity,
            timestamp=datetime.utcnow()
        )
        db.add(new_alert)
        db.commit() # Lưu vĩnh viễn tất cả thay đổi vào file cybertwin.db

        return {
            "status": "success",
            "message": "Xử lý và lưu log thành công",
            "data": {
                "alert_id": edge_id,
                "source_node": {"id": source_device.id, "ip": src_ip, "name": src_name},
                "target_node": {"id": target_device.id, "ip": dst_ip, "name": dst_name},
                "technique": technique,
                "severity": severity
            }
        }

    except Exception as e:
        db.rollback() # Hoàn tác nếu xảy ra lỗi hệ thống
        return {"status": "error", "message": f"Lỗi hệ thống: {str(e)}"}