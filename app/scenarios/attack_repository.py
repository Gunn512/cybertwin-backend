# Gunn Nguyen
from app.scenarios import apt_demo

class AttackRepository:
    @staticmethod
    def get_scenario(scenario_name: str) -> list:
        # Chỉ đăng ký duy nhất kịch bản APT Demo
        scenarios = {
            "apt_demo": apt_demo.get_scenario,
        }
        
        if scenario_name not in scenarios:
            raise ValueError(f"Kịch bản '{scenario_name}' không tồn tại trong hệ thống.")
            
        # Gọi hàm để lấy dữ liệu kịch bản
        return scenarios[scenario_name]() 