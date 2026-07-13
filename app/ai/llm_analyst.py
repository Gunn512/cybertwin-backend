from google import genai
from google.genai import errors
from dotenv import load_dotenv
import os
import json

load_dotenv()


# Khởi tạo client một lần
api_key = os.getenv("GEMINI_API_KEY")
# MODEL_NAME = "models/gemini-3.5-flash"
# MODEL_NAME = "models/gemini-2.5-flash"
# MODEL_NAME = "gemini-2.5-flash"
# MODEL_NAME = "gemini-flash-latest"
MODEL_NAME = "models/gemini-flash-lite-latest"
# MODEL_NAME = "models/gemini-3.1-flash-lite"


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

    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
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

        return {
            "status": "success",
            "explanation": data.get("explanation", ""),
            "mitigation": data.get("mitigation", ""),
            "cached": False,
        }

    except errors.ClientError as e:
        print(f"Gemini Client Error: {e}")
        return {
            "status": "error",
            "message": str(e),
            "cached": False,
        }

    except json.JSONDecodeError:
        return {
            "status": "error",
            "message": f"Gemini trả về không phải JSON:\n{raw_text}",
            "cached": False,
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "cached": False,
        }