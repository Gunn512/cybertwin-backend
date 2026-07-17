# Gunn Nguyen
import os
from dotenv import load_dotenv

# Tải các biến từ file .env
load_dotenv()

class Settings:
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cybertwin.db")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY")

settings = Settings()