from app.models import SessionLocal
from app.parser.log_processor import process_raw_log
from app.scenarios.attack_repository import get_steps

db = SessionLocal()

logs = get_steps("APT-001")

for log in logs:
    result = process_raw_log(db, log)
    print(result)

db.close()