from sqlalchemy import Column, String, DateTime, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime
from app.config import settings

# Khởi tạo Base class để các model kế thừa
Base = declarative_base()

class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, index=True) # Ví dụ: "N1", "N2"
    ip_address = Column(String, unique=True, nullable=False) # Ví dụ: "192.168.1.50"
    device_name = Column(String, nullable=False) # Ví dụ: "Web Server"
    os_type = Column(String, nullable=True) # Ví dụ: "Linux", "Windows"

    # Thiết lập mối quan hệ ngược để dễ truy vấn log từ thiết bị
    alerts_sent = relationship("SecurityAlert", foreign_keys="SecurityAlert.source_device_id", back_populates="source_device")
    alerts_received = relationship("SecurityAlert", foreign_keys="SecurityAlert.target_device_id", back_populates="target_device")


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(String, primary_key=True, index=True) # Ví dụ: "E1", "E2"
    source_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    target_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    attack_technique = Column(String, nullable=False) # Ví dụ: "Brute Force (SSH)"
    severity = Column(String, nullable=False) # Ví dụ: "high", "critical", "medium"
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Thiết lập liên kết (Join) vật lý giữa các bảng
    source_device = relationship("Device", foreign_keys=[source_device_id], back_populates="alerts_sent")
    target_device = relationship("Device", foreign_keys=[target_device_id], back_populates="alerts_received")
    
    # Liên kết 1-1 với bảng kết quả AI
    ai_insight = relationship("AiInsight", uselist=False, back_populates="alert")


class AiInsight(Base):
    __tablename__ = "ai_insights"

    id = Column(String, primary_key=True, index=True)
    alert_id = Column(String, ForeignKey("security_alerts.id"), unique=True, nullable=False)
    explanation_text = Column(String, nullable=False) # Lời giải thích của AI
    mitigation_steps = Column(String, nullable=False) # Các bước xử lý sự cố khẩn cấp

    # Liên kết ngược lại bảng Alert
    alert = relationship("SecurityAlert", back_populates="ai_insight")


# --- THIẾT LẬP KẾT NỐI DATABASE ---
engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Hàm khởi tạo và quét để tự động tạo file database + các bảng trống"""
    Base.metadata.create_all(bind=engine)