from google import genai
from google.genai import types

client = genai.Client(
    api_key="AQ.Ab8RN6KuczCpdsSQ3dOlvs2ICETVAM6I7TWhJH-ab43gnb9yhw",
    http_options=types.HttpOptions(
        api_version="v1beta"
    )
)

response = client.models.generate_content(
    model="gemini-3.5-flash",
    contents="Xin chào"
)

print(response.text)