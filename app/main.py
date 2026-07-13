from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.models import init_db, SessionLocal, Device, SecurityAlert, AiInsight
from app.parser.log_processor import process_raw_log
from app.ai.llm_analyst import analyze_attack_log
from pydantic import BaseModel
import uuid
import json
import os
from app.simulator.attack_simulator import AttackSimulator

init_db()

app = FastAPI(title="CyberTwin API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class AIExplainRequest(BaseModel):
    edge_id: str

@app.get("/")
def read_root():
    return {"status": "success", "message": "Backend CyberTwin đã sẵn sàng!"}

@app.post("/api/v1/alerts/ingest")
def ingest_log(log_data: dict, db: Session = Depends(get_db)):
    result = process_raw_log(db, log_data)
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.get("/api/v1/alerts/graph")
def get_graph_data(db: Session = Depends(get_db)):
    try:
        devices = db.query(Device).all()
        nodes_list = []
        for d in devices:
            is_attacker = "attacker" in d.device_name.lower()
            nodes_list.append({
                "id": d.id,
                "label": d.device_name,
                "title": f"IP: {d.ip_address} | OS: {d.os_type}",
                "color": {
                    "background": "#10b981" if is_attacker else "#3b82f6",
                    "border": "#059669" if is_attacker else "#2563eb",
                    "hover": {"background": "#34d399" if is_attacker else "#60a5fa", "border": "#10b981" if is_attacker else "#3b82f6"},
                    "highlight": {"background": "#34d399" if is_attacker else "#60a5fa", "border": "#10b981" if is_attacker else "#3b82f6"}
                }
            })

        alerts = db.query(SecurityAlert).all()
        edges_list = []
        for a in alerts:
            color_map = {"critical": "#dc2626", "high": "#f97316", "medium": "#eab308"}
            base_color = color_map.get(a.severity.lower(), "#94a3b8")
            edges_list.append({
                "id": a.id, "from": a.source_device_id, "to": a.target_device_id,
                "label": a.attack_technique.split(" (")[0], 
                "color": {
                    "color": base_color,
                    "hover": "#f87171",
                    "highlight": "#f87171"
                }, 
                "arrows": "to"
            })
            
        return {"status": "success", "nodes": nodes_list, "edges": edges_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ai/explain")
def trigger_ai_explanation(payload: AIExplainRequest, db: Session = Depends(get_db)):
    alert_id = payload.edge_id
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Không tìm thấy sự cố")

    # Kiểm tra Cache
    existing_insight = db.query(AiInsight).filter(AiInsight.alert_id == alert_id).first()
    if existing_insight:
        return {"status": "success", "explanation": f"{existing_insight.explanation_text}\n\n🛡️ KHUYẾN NGHỊ KHẮC PHỤC KHẨN CẤP:\n{existing_insight.mitigation_steps}"}

    src = db.query(Device).filter(Device.id == alert.source_device_id).first()
    dst = db.query(Device).filter(Device.id == alert.target_device_id).first()
    source_info = f"IP: {src.ip_address} - {src.device_name}" if src else "Unknown"
    target_info = f"IP: {dst.ip_address} - {dst.device_name}" if dst else "Unknown"

    ai_result = analyze_attack_log(alert.attack_technique, alert.severity, source_info, target_info)

    # Đóng gói lỗi mượt mà nếu AI từ chối
    if ai_result["status"] == "error":
        error_msg = f"⚠️ LỖI KẾT NỐI GEMINI AI:\n{ai_result['message']}\n\n👉 Vui lòng kiểm tra lại cấu hình API Key trong file .env"
        return {"status": "success", "explanation": error_msg}

    new_insight = AiInsight(id=f"AI_{uuid.uuid4().hex[:6]}", alert_id=alert.id, explanation_text=ai_result["explanation"], mitigation_steps=ai_result["mitigation"])
    db.add(new_insight)
    db.commit()

    return {"status": "success", "explanation": f"{ai_result['explanation']}\n\n🛡️ KHUYẾN NGHỊ KHẮC PHỤC KHẨN CẤP:\n{ai_result['mitigation']}"}

# Test OK 18h 13/07/2026


# --- CÁC ENDPOINT ĐIỀU KHIỂN BỘ GIẢ LẬP (SIMULATOR) ---

@app.post("/api/v1/simulator/step")
def run_simulator_step(scenario_name: str, step: int, db: Session = Depends(get_db)):
    """API kích hoạt 1 bước của kịch bản tấn công"""
    simulator = AttackSimulator(db)
    
    try:
        # Lấy tổng số bước để Frontend biết tiến trình (Ví dụ: Bước 1/3)
        total_steps = simulator.get_total_steps(scenario_name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
        
    # Chạy đúng bước được yêu cầu
    result = simulator.run_step(scenario_name, step)
    
    if result["status"] == "error":
         raise HTTPException(status_code=400, detail=result["message"])

    return {
        "status": "success", 
        "message": f"Chạy thành công bước {step}/{total_steps} của {scenario_name}",
        "total_steps": total_steps
    }

@app.post("/api/v1/simulator/reset")
def reset_simulator(db: Session = Depends(get_db)):
    """API dọn dẹp sạch sẽ Database để Demo lại từ đầu"""
    try:
        db.query(AiInsight).delete()
        db.query(SecurityAlert).delete()
        db.query(Device).delete()
        db.commit()
        return {"status": "success", "message": "Đã làm sạch hệ thống."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))    