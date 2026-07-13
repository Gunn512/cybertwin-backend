from app.models import SessionLocal
from app.simulator.attack_simulator import AttackSimulator

db = SessionLocal()

try:
    # Khởi tạo bộ giả lập với kết nối Database
    simulator = AttackSimulator(db)

    # Chạy kịch bản APT với độ trễ 2 giây mỗi bước
    simulator.run(
        scenario_name="malware_demo",
        delay=2
    )
finally:
    db.close()