from google import genai
from google.genai import errors
from dotenv import load_dotenv
import os
import json

load_dotenv()


# Khởi tạo client một lần
api_key = os.getenv("GEMINI_API_KEY")
MODELS = [
    "models/gemini-flash-lite-latest",
    "models/gemini-3.1-flash-lite",
    "models/gemini-3.5-flash",
]


if not api_key:
    raise RuntimeError("Không tìm thấy GEMINI_API_KEY trong file .env")

# Khởi tạo Gemini Client
client = genai.Client(api_key=api_key)


def analyze_attack_log(
    technique: str,
    severity: str,
    source_info: str,
    target_info: str,
) -> dict:

    prompt = f"""
Bạn là một chuyên gia SOC cấp cao.

Phân tích sự cố sau:

Hành vi: {technique}
Mức độ: {severity}
Nguồn: {source_info}
Đích: {target_info}

Chỉ trả về JSON đúng định dạng:

{{
    "explanation": "...",
    "mitigation": "..."
}}

Không markdown.
Không ```json.
Không giải thích thêm.
"""

    last_error = None

    for model in MODELS:
        try:
            print(f"Đang thử model: {model}")

            response = client.models.generate_content(
                model=model,
                contents=prompt,
            )

            raw_text = response.text.strip()

            if raw_text.startswith("```"):
                raw_text = (
                    raw_text.replace("```json", "")
                    .replace("```", "")
                    .strip()
                )

            data = json.loads(raw_text)

            print(f"Thành công với model: {model}")

            return {
                "status": "success",
                "explanation": data.get("explanation", ""),
                "mitigation": data.get("mitigation", ""),
                "cached": False,
            }

        except Exception as e:
            print(f"Lỗi với {model}: {e}")
            last_error = e

    return {
        "status": "error",
        "message": str(last_error),
        "cached": False,
    }