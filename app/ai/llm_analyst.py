from google import genai
# from google.genai import errors
import os
import json
from dotenv import load_dotenv

load_dotenv()


def analyze_attack_log(technique: str, severity: str, source_info: str, target_info: str) -> dict:
    # Khởi tạo client chính thức nhận diện trọn vẹn định dạng AQ...
    api_key=os.getenv("GEMINI_API_KEY")       

    if not api_key:
        raise ValueError("Không tìm thấy GEMINI_API_KEY trong file .env")

    client = genai.Client(
        api_key=api_key
    )
    
    prompt = f"""
        Bạn là một chuyên gia phân tích an ninh mạng SOC cấp cao.

        Hãy phân tích sự cố sau:

        Hành vi: {technique}
        Mức độ: {severity}
        Nguồn: {source_info}
        Đích: {target_info}

        Trả lời DUY NHẤT bằng JSON

        Định dạng: 
        
        {{
            "explanation": "...",
            "mitigation": "..."
        }}

        Không được thêm markdown.
        Không được thêm ```json.
        Không được giải thích ngoài JSON.
    """    

    try:
        # Gọi trực tiếp qua SDK mới với model flash tiêu chuẩn
        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=prompt,
        )
        
        raw_text = response.text.strip()

        # Phòng trường hợp Gemini vẫn trả về ```json
        raw_text = raw_text.replace("```json", "")
        raw_text = raw_text.replace("```", "").strip()

        data = json.loads(raw_text)

        return {
            "status": "success",
            "explanation": data["explanation"],
            "mitigation": data["mitigation"],
            "cached": False
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()

        return {
            "status": "error",
            "message": str(e),
            "cached": False
        }