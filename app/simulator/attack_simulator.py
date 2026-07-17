# Gunn Nguyen
import time
from sqlalchemy.orm import Session
from app.parser.log_processor import process_raw_log
from app.scenarios.attack_repository import AttackRepository

class AttackSimulator:
    def __init__(self, db: Session):
        self.db = db

    def run(self, scenario_name: str, delay: int = 2):
        """Chạy toàn bộ kịch bản tự động, có thời gian nghỉ (Dùng cho file Test CLI)"""
        print(f"\n🚀 BẮT ĐẦU MÔ PHỎNG KỊCH BẢN: [{scenario_name.upper()}]")
        scenario_data = AttackRepository.get_scenario(scenario_name)
        
        for log in scenario_data:
            step = log.get("step")
            technique = log.get("attack_technique")
            
            print(f"\n⏳ Đang thực thi Bước {step}: {technique}...")
            
            result = process_raw_log(self.db, log)
            
            if result["status"] == "error":
                print(f"❌ LỖI HỆ THỐNG: {result['message']}")
                break
                
            print(f"✅ Bơm log thành công!")
            print(f"   Nguồn: {log.get('source_ip')} -> Đích: {log.get('target_ip')}")
            time.sleep(delay)
            
        print("\n🎉 ĐÃ HOÀN THÀNH TOÀN BỘ KỊCH BẢN!\n")

    def run_step(self, scenario_name: str, step_index: int):
        """Chạy một bước cụ thể (Dành cho API FastAPI gọi từ Frontend)"""
        scenario_data = AttackRepository.get_scenario(scenario_name)
        
        if step_index < 1 or step_index > len(scenario_data):
            return {"status": "error", "message": f"Bước {step_index} không tồn tại."}
            
        log_data = scenario_data[step_index - 1]
        
        # Chỉ gọi hàm xử lý log vào bảng security_alerts (An toàn, không xóa thiết bị)
        return process_raw_log(self.db, log_data)
        
    def get_total_steps(self, scenario_name: str):
        """Lấy tổng số bước của kịch bản"""
        return len(AttackRepository.get_scenario(scenario_name))