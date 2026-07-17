# Gunn Nguyen
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import uuid

# Import từ thư mục nội bộ của dự án
from app.models import init_db, SessionLocal, Device, SecurityAlert, AiInsight
from app.parser.log_processor import process_raw_log
from app.ai.llm_analyst import analyze_attack_log
from app.simulator.attack_simulator import AttackSimulator

# 1. KHỞI TẠO DATABASE
init_db()

# 2. KHỞI TẠO ỨNG DỤNG FASTAPI (Bắt buộc phải có dòng này để tránh lỗi NameError)
app = FastAPI(title="CyberTwin API", version="1.0")

# 3. CẤU HÌNH CORS
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"]
)

# 4. HÀM HỖ TRỢ VÀ MODEL
def get_db():
    db = SessionLocal()
    try: 
        yield db
    finally: 
        db.close()

class AIExplainRequest(BaseModel):
    edge_id: Optional[str] = None
    step: Optional[int] = None

system_state = {"is_isolated": False}

# ==========================================
# CÁC ENDPOINT API
# ==========================================

@app.get("/api/v1/network/topology")
def get_topology():
    try:
        nodes_list = [
            {"id": "8.8.8.8", "label": "INTERNET", "level": 1, "group": "internet"},
            {"id": "10.0.0.1", "label": "NextGen Firewall", "level": 2, "group": "firewall"},
            
            # CẤP 3: CÁC SWITCH ĐẠI DIỆN CHO ZONE (BẮT BUỘC có chữ SWITCH để Frontend hiện Icon)
            {"id": "10.0.0.2", "label": "DMZ SWITCH", "level": 3, "group": "zone"},
            {"id": "10.0.1.0", "label": "LAN SWITCH", "level": 3, "group": "zone"},
            
            # CẤP 4: TẤT CẢ SERVER
            {"id": "10.0.0.4", "label": "Web Server", "level": 4, "group": "server"},
            {"id": "10.0.0.5", "label": "App Server", "level": 4, "group": "server"},
            {"id": "10.0.1.10", "label": "Active Directory", "level": 4, "group": "server"},
            {"id": "10.0.1.20", "label": "File Server", "level": 4, "group": "server"},
            {"id": "10.0.0.10", "label": "Database Server", "level": 4, "group": "database"},
            {"id": "10.0.1.50", "label": "Admin PC", "level": 4, "group": "pc"}
        ]

        infrastructure_edges = [
            {"id": "e_int_fw", "from": "8.8.8.8", "to": "10.0.0.1", "color": {"color": "#64748b"}, "dashes": False},
            {"id": "e_fw_dmz", "from": "10.0.0.1", "to": "10.0.0.2", "color": {"color": "#64748b"}, "dashes": False},
            {"id": "e_fw_lan", "from": "10.0.0.1", "to": "10.0.1.0", "color": {"color": "#64748b"}, "dashes": False},
            {"id": "e_dmz_web", "from": "10.0.0.2", "to": "10.0.0.4", "color": {"color": "#4ade80"}},
            {"id": "e_dmz_app", "from": "10.0.0.2", "to": "10.0.0.5", "color": {"color": "#4ade80"}},
            {"id": "e_lan_ad", "from": "10.0.1.0", "to": "10.0.1.10", "color": {"color": "#4ade80"}},
            {"id": "e_lan_file", "from": "10.0.1.0", "to": "10.0.1.20", "color": {"color": "#4ade80"}},
            {"id": "e_lan_db", "from": "10.0.1.0", "to": "10.0.0.10", "color": {"color": "#4ade80"}},
            {"id": "e_lan_admin", "from": "10.0.1.0", "to": "10.0.1.50", "color": {"color": "#4ade80"}},
            
            # 2 Dòng này bắt buộc "hidden: True" để duy trì cấu trúc không bị méo thẳng đứng
            {"id": "e_web_app", "from": "10.0.0.4", "to": "10.0.0.5", "hidden": True},
            {"id": "e_app_db", "from": "10.0.0.5", "to": "10.0.0.10", "hidden": True},
        ]
        return {"status": "success", "nodes": nodes_list, "infrastructure_edges": infrastructure_edges}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/alerts/graph")
def get_active_alerts(db: Session = Depends(get_db)):
    try:
        alerts = db.query(SecurityAlert).all()
        edges_list = []
        compromised_nodes = set()
        
        # ĐÃ SỬA: Không trả về mảng rỗng khi bị Isolate nữa, để giữ nguyên đường nét đứt lịch sử
        for a in alerts:
            severity_lower = a.severity.lower()
            edge_color = "#ef4444" if severity_lower == "critical" else "#f59e0b" if severity_lower == "medium" else "#f97316"
            edge_id = f"e_{a.source_device_id}_{a.target_device_id}"

            edges_list.append({
                "id": edge_id, "from": a.source_device_id, "to": a.target_device_id,
                "label": a.attack_technique.split(" (")[0],
                "color": {"color": edge_color, "highlight": "#ef4444"},
                "severity": severity_lower, "targetName": a.target_device_id
            })
            compromised_nodes.add(a.source_device_id)
            compromised_nodes.add(a.target_device_id)

        updated_nodes = [{"id": n_id, "status": "COMPROMISED"} for n_id in compromised_nodes]
        return {"status": "success", "updated_nodes": updated_nodes, "attack_edges": edges_list, "is_isolated": system_state["is_isolated"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ai/explain")
def trigger_ai_explanation(payload: AIExplainRequest, db: Session = Depends(get_db)):
    if payload.step is not None:
        step = payload.step
        total_steps = 7
        
        # Cấu trúc JSON mới đáp ứng bảng SOC Dashboard
        step_data = {
            1: {
                "stage": "Initial Access", "severity": "Medium", "source": "Internet", "target": "Internet Gateway", "mitre": "T1190",
                "observation": "Ghi nhận lưu lượng truy cập bất thường từ IP lạ (6.6.6.6) liên tục gửi các gói tin thăm dò nhắm vào cổng biên của hệ thống.",
                "impact": "Có nguy cơ lộ lọt thông tin về cấu trúc mạng và các dịch vụ đang mở hướng Internet.",
                "assessment": "Đây mang dấu hiệu điển hình của giai đoạn Initial Access. Kẻ tấn công đang rà quét (scanning) tìm điểm yếu.",
                "actions": ["Giám sát chặt chẽ IP 6.6.6.6", "Bật chế độ Strict Logging trên Gateway", "Kiểm tra các bản vá định kỳ"]
            },
            2: {
                "stage": "Firewall Evasion", "severity": "High", "source": "Gateway", "target": "NextGen Firewall", "mitre": "T1562",
                "observation": "Phát hiện payload được mã hóa tinh vi cố gắng đi qua lớp kiểm duyệt IPS/IDS của NextGen Firewall.",
                "impact": "Nếu vượt qua, kẻ tấn công có thể tiếp cận trực tiếp với phân vùng DMZ bên trong.",
                "assessment": "Mức độ đe dọa tăng cao. Kẻ tấn công đang sử dụng kỹ thuật Evasion để che giấu hành vi thâm nhập.",
                "actions": ["Kích hoạt rule chặn chủ động trên Firewall", "Phân tích payload mã hóa", "Kiểm tra tính toàn vẹn của rule IPS"]
            },
            3: {
                "stage": "Web Exploit", "severity": "Critical", "source": "Firewall", "target": "Web Server", "mitre": "T1190",
                "observation": "Lưu lượng độc hại đã tiếp cận Web Server (10.0.0.4). Phát hiện mã lệnh lạ được thực thi trên service của Web Server.",
                "impact": "Web Server đã bị xâm nhập và có khả năng bị điều khiển từ xa (RCE).",
                "assessment": "Kẻ tấn công đã có chỗ đứng (foothold) đầu tiên trong mạng DMZ. Sự cố chuyển sang trạng thái nguy hiểm.",
                "actions": ["Cô lập Web Server khỏi LAN", "Trích xuất log Web Service", "Tìm kiếm và vô hiệu hóa webshell"]
            },
            4: {
                "stage": "Lateral Movement", "severity": "Critical", "source": "Web Server", "target": "App Server", "mitre": "T1021",
                "observation": "Có các kết nối SMB/RDP trái phép khởi tạo từ Web Server trỏ thẳng vào Application Server trong cùng DMZ.",
                "impact": "Phạm vi lây nhiễm đang mở rộng. Các máy chủ lân cận đối mặt với rủi ro bị chiếm quyền.",
                "assessment": "Xác nhận hành vi di chuyển ngang (Lateral Movement). Kẻ tấn công đang tìm kiếm đường lọt vào mạng nội bộ.",
                "actions": ["Cắt kết nối giữa Web và App Server", "Đổi mật khẩu Local Admin", "Quét mã độc trên App Server"]
            },
            5: {
                "stage": "DB Privilege Escalation", "severity": "Critical", "source": "App Server", "target": "Database Server", "mitre": "T1068",
                "observation": "Ghi nhận phiên đăng nhập hợp lệ nhưng với đặc quyền cao (Admin/Root) từ App Server vào Database Server nằm sâu trong LAN.",
                "impact": "Kẻ tấn công đã chiếm được quyền truy cập vào trung tâm dữ liệu lõi của tổ chức.",
                "assessment": "Leo thang đặc quyền thành công. Dữ liệu nhạy cảm hoàn toàn bị phơi bày. Báo động đỏ toàn hệ thống.",
                "actions": ["Khóa tài khoản DB Admin hiện tại", "Kích hoạt Tường lửa CSDL (WAF/DAM)", "Chuẩn bị phương án Backup"]
            },
            6: {
                "stage": "Data Exfiltration", "severity": "Critical", "source": "Database Server", "target": "Internet", "mitre": "T1041",
                "observation": "Lưu lượng mạng tăng đột biến từ Database Server. Các tệp tin nén lớn đang được gửi ngược ra ngoài thông qua các node trung gian.",
                "impact": "Khả năng mất mát dữ liệu khách hàng, mã nguồn hoặc tài sản trí tuệ là rất cao.",
                "assessment": "Đang diễn ra quá trình trích xuất dữ liệu (Data Exfiltration). Hành động ngăn chặn cần thực hiện tính bằng giây.",
                "actions": ["Đóng ngay port Outbound của DB Server", "Giết các tiến trình nén file lạ", "Cảnh báo đội pháp lý/truyền thông"]
            },
            7: {
                "stage": "C2 Connection", "severity": "Critical", "source": "Gateway", "target": "Attacker C2", "mitre": "T1071",
                "observation": "Một đường hầm liên lạc (Tunnel) ổn định đã được thiết lập giữa hệ thống nội bộ và máy chủ C2 của kẻ tấn công (6.6.6.6).",
                "impact": "Kẻ tấn công có thể liên tục ra lệnh, thả thêm mã độc (Ransomware) hoặc xóa dấu vết.",
                "assessment": "Chiến dịch APT đã hoàn thiện toàn bộ chuỗi tấn công. Hệ thống đã mất quyền kiểm soát một phần.",
                "actions": ["CẮT MẠNG INTERNET TOÀN CỤC", "Kích hoạt quy trình Incident Response cấp 1", "Lưu trữ toàn bộ Log để điều tra"]
            }
        }
        
        # Xử lý báo cáo tổng kết
        if step > total_steps:
            return {
                "status": "success", "is_summary": True, "title": "INCIDENT ACTION REPORT",
                "summary": {
                    "overall_risk": "CRITICAL",
                    "affected_assets": 4,
                    "mitre_tactics": ["T1190", "T1562", "T1021", "T1068", "T1041", "T1071"],
                    "attack_chain": ["Attack", "Internet", "NextGen Firewall", "Web Server", "App Server", "Database Server", "C2 Server"]
                },
                "recommendations": [
                    "Cô lập khẩn cấp Database Server và Web Server khỏi mạng nội bộ.",
                    "Thực hiện rà soát và thu hồi toàn bộ credential của hệ thống.",
                    "Xóa bỏ các webshell, backdoor và chặn vĩnh viễn IP C2 (6.6.6.6).",
                    "Cập nhật chính sách Zero-Trust cho phân vùng Internal LAN."
                ]
            }
            
        curr = step_data.get(step, step_data[1])
        return {
            "status": "success", 
            "is_summary": False, 
            "step": step,
            "total_steps": total_steps,
            "stage": curr["stage"], 
            "severity": curr["severity"],
            "source": curr["source"],
            "target": curr["target"],
            "mitre": curr["mitre"],
            "observation": curr["observation"],
            "impact": curr["impact"],
            "assessment": curr["assessment"],
            "actions": curr["actions"]
        }
    
    # Trả về mặc định nếu bấm thủ công
    return {
        "status": "success", 
        "is_summary": False, 
        "step": 0, "total_steps": 0,
        "stage": "Manual Investigation",
        "severity": "Unknown", "source": "Selected", "target": "Selected", "mitre": "TBD",
        "observation": "Chuyên gia SOC đang tiến hành điều tra thủ công trên luồng mạng này.",
        "impact": "Đang đánh giá mức độ ảnh hưởng đến hệ thống.",
        "assessment": "Cần thêm dữ liệu phân tích từ hệ thống Log trung tâm.",
        "actions": ["Kiểm tra Event Viewer", "Trích xuất PCAP", "So khớp Threat Intelligence"]
    }

@app.post("/api/v1/simulator/step")
def run_simulator_step(scenario_name: str, step: int, db: Session = Depends(get_db)):
    if system_state["is_isolated"]: 
        raise HTTPException(status_code=400, detail="Hệ thống đã bị cô lập.")
    
    alerts_sequence = [
        [{"src": "6.6.6.6", "dst": "8.8.8.8", "label": "Initial Access", "sev": "MEDIUM"}],
        [{"src": "8.8.8.8", "dst": "10.0.0.1", "label": "Firewall Evasion", "sev": "HIGH"}],
        [{"src": "10.0.0.1", "dst": "10.0.0.2", "label": "Web Exploit", "sev": "CRITICAL"}, {"src": "10.0.0.2", "dst": "10.0.0.4", "label": "Web Exploit", "sev": "CRITICAL"}],
        [{"src": "10.0.0.4", "dst": "10.0.0.5", "label": "Lateral Movement", "sev": "CRITICAL"}],
        [{"src": "10.0.0.5", "dst": "10.0.0.10", "label": "DB Privilege Escalation", "sev": "CRITICAL"}],
        [{"src": "10.0.0.10", "dst": "10.0.1.0", "label": "Data Exfiltration", "sev": "CRITICAL"}, 
         {"src": "10.0.1.0", "dst": "10.0.0.1", "label": "Data Exfiltration", "sev": "CRITICAL"}, 
         {"src": "10.0.0.1", "dst": "8.8.8.8", "label": "Data Exfiltration", "sev": "CRITICAL"}],
        [{"src": "8.8.8.8", "dst": "6.6.6.6", "label": "C2 Connection", "sev": "CRITICAL"}]
    ]
    
    if step > len(alerts_sequence): 
        return {"status": "success"}
        
    current_step_alerts = alerts_sequence[step - 1]
    for alert in current_step_alerts:
        db.add(SecurityAlert(
            id=str(uuid.uuid4()), 
            source_device_id=alert["src"], 
            target_device_id=alert["dst"], 
            attack_technique=alert["label"], 
            severity=alert["sev"]
        ))
    db.commit()
    return {"status": "success"}

@app.post("/api/v1/simulator/isolate")
def isolate_system():
    system_state["is_isolated"] = True
    return {"status": "success", "message": "Đã cô lập thành công."}

@app.post("/api/v1/simulator/reset")
def reset_simulator(db: Session = Depends(get_db)):
    try:
        system_state["is_isolated"] = False
        db.query(AiInsight).delete()
        db.query(SecurityAlert).delete()
        db.query(Device).delete()
        
        seed_devices = [
            Device(id="6.6.6.6", device_name="Attacker IP", ip_address="6.6.6.6", os_type="Kali Linux"),
            Device(id="8.8.8.8", device_name="INTERNET", ip_address="8.8.8.8", os_type="Gateway"),
            Device(id="10.0.0.1", device_name="NextGen Firewall", ip_address="10.0.0.1", os_type="Palo Alto"),
            Device(id="10.0.0.2", device_name="DMZ Zone", ip_address="10.0.0.2", os_type="Network"),
            Device(id="10.0.1.0", device_name="Internal LAN", ip_address="10.0.1.0", os_type="Network"),
            Device(id="10.0.0.4", device_name="Web Server", ip_address="10.0.0.4", os_type="Ubuntu"),
            Device(id="10.0.1.10", device_name="Active Directory", ip_address="10.0.1.10", os_type="Windows Server"),
            Device(id="10.0.0.5", device_name="App Server", ip_address="10.0.0.5", os_type="Ubuntu"),
            Device(id="10.0.1.20", device_name="File Server", ip_address="10.0.1.20", os_type="Windows Server"),
            Device(id="10.0.0.10", device_name="Database Server", ip_address="10.0.0.10", os_type="CentOS"),
            Device(id="10.0.1.50", device_name="Admin PC", ip_address="10.0.1.50", os_type="Windows 11")
        ]
        db.bulk_save_objects(seed_devices)
        db.commit()
        return {"status": "success"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))