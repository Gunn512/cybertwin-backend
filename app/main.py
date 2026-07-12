from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.models import init_db, SessionLocal
from app.parser.log_processor import process_raw_log
from app.models import Device, SecurityAlert, AiInsight
from app.ai.llm_analyst import analyze_attack_log
import uuid
from app.parser.correlation_engine import correlate_alerts
from pydantic import BaseModel

# Khởi tạo Database
init_db()

app = FastAPI(
    title="CyberTwin API",
    description="Hệ thống API phục vụ trực quan hóa chuỗi tấn công mạng",
    version="1.0"
)

# --- CẤU HÌNH BẬT ĐÈN XANH CHO CÁC PORT KHÁC KẾT NỐI (CORS) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cho phép tất cả các nguồn (bao gồm http://localhost:5173) gọi tới
    allow_credentials=True,
    allow_methods=["*"],  # Cho phép tất cả các phương thức GET, POST, PUT, DELETE
    allow_headers=["*"],  # Cho phép tất cả các định dạng Header dữ liệu
)

# Hàm bổ trợ (Dependency) để quản lý đóng mở kết nối Database an toàn
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"status": "success", "message": "Backend CyberTwin và Database đã sẵn sàng!"}

# --- ENDPOINT TIẾP NHẬN LOG MỚI ---
@app.post("/api/v1/alerts/ingest")
def ingest_log(log_data: dict, db: Session = Depends(get_db)):
    """Cổng API tiếp nhận log thô từ hệ thống hoặc script giả lập"""
    result = process_raw_log(db, log_data)
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result


# --- ENDPOINT TRẢ VỀ CẤU TRÚC ĐỒ THỊ (DÀNH CHO FRONTEND VẼ GRAPH) ---
@app.get("/api/v1/alerts/graph")
def get_graph_data(db: Session = Depends(get_db)):
    """API trả về cấu trúc nodes và edges chuẩn hóa để vẽ sơ đồ mạng tương tác"""
    try:
        # 1. Lấy tất cả thiết bị từ DB để làm danh sách Nodes
        devices = db.query(Device).all()
        nodes_list = []
        for d in devices:
            nodes_list.append({
                "id": d.id,
                "label": d.device_name,
                "title": f"IP: {d.ip_address} | OS: {d.os_type}",
                "group": "attacker" if "attacker" in d.device_name.lower() else "server"
            })

        # 2. Lấy tất cả cảnh báo từ DB để làm danh sách Edges (đường nối)
        alerts = db.query(SecurityAlert).all()
        edges_list = []
        for a in alerts:
            # Định nghĩa màu sắc dựa trên mức độ nghiêm trọng
            color_map = {"critical": "#dc2626", "high": "#f97316", "medium": "#eab308"}
            edge_color = color_map.get(a.severity.lower(), "#94a3b8")

            edges_list.append({
                "id": a.id,
                "from": a.source_device_id,
                "to": a.target_device_id,
                "label": a.attack_technique.split(" (")[0], # Cắt ngắn tên kỹ thuật hiển thị cho đẹp
                "color": {"color": edge_color, "highlight": "#3b82f6"},
                "arrows": "to" # Mũi tên chỉ hướng tấn công
            })

        return {
            "status": "success",
            "nodes": nodes_list,
            "edges": edges_list
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi lấy dữ liệu đồ thị: {str(e)}")    


# --- ENDPOINT GỌI AI PHÂN TÍCH LOG (CÓ SỬ DỤNG CACHE ĐỂ TRÁNH TRÙNG LẶP) ---
@app.post("/api/v1/ai/analyze")
def trigger_ai_analysis(payload: dict, db: Session = Depends(get_db)):
    """API tiếp nhận ID cảnh báo, tự động gọi Gemini AI phân tích chi tiết kỹ thuật"""
    alert_id = payload.get("alert_id")
    if not alert_id:
        raise HTTPException(status_code=400, detail="Thiếu trường alert_id bắt buộc")

    # 1. Kiểm tra xem Alert này có tồn tại trong database không
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Không tìm thấy mã sự cố mạng này")

    # 2. KIỂM TRA BỘ NHỚ ĐỆM (CACHE): Nếu cuộc tấn công này đã được AI giải thích trước đó rồi
    # thì lấy luôn kết quả trong bảng `ai_insights` ra trả về luôn, tránh gọi lại API Gemini gây tốn lượt/tiền
    if alert.ai_insight:
        return {
            "status": "success",
            "explanation": alert.ai_insight.explanation_text,
            "mitigation": alert.ai_insight.mitigation_steps,
            "cached": True
        }

    # 3. Nếu chưa có trong cache, gom dữ liệu ngữ cảnh để gửi cho Gemini AI
    src = alert.source_device
    dst = alert.target_device
    
    source_info = f"IP: {src.ip_address} | Tên: {src.device_name} | HĐH: {src.os_type}"
    target_info = f"IP: {dst.ip_address} | Tên: {dst.device_name} | HĐH: {dst.os_type}"

    # Gọi module AI LangChain
    ai_result = analyze_attack_log(
        technique=alert.attack_technique,
        severity=alert.severity,
        source_info=source_info,
        target_info=target_info
    )

    if ai_result["status"] == "error":
        raise HTTPException(
            status_code=500,
            detail=ai_result["message"]
        )

    # 4. Lưu kết quả phân tích của AI vào bảng `ai_insights` làm bộ nhớ đệm cho lần sau
    new_insight = AiInsight(
        id=f"AI_{uuid.uuid4().hex[:6]}",
        alert_id=alert.id,
        explanation_text=ai_result["explanation"],
        mitigation_steps=ai_result["mitigation"]
    )
    db.add(new_insight)
    db.commit()

    return {
        "status": "success",
        "explanation": ai_result["explanation"],
        "mitigation": ai_result["mitigation"],
        "cached": False
    }

# --- ENDPOINT GỌI GOM CỤM CHUỖI TẤN CÔNG ---
@app.get("/api/v1/alerts/chains")
def get_attack_chains(db: Session = Depends(get_db)):
    """API trả về các chuỗi tấn công đã được gom cụm bởi Correlation Engine"""
    try:
        chains = correlate_alerts(db)
        return {
            "status": "success",
            "chains": chains
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi gom cụm sự kiện: {str(e)}")

        