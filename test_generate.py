from google import genai
from dotenv import load_dotenv
import os

load_dotenv()

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)

models = [
    "models/gemini-3.5-flash",
    "models/gemini-3.1-flash-lite",
    "models/gemini-flash-lite-latest",
    "models/gemini-2.0-flash",
]

for m in models:

    print("="*60)
    print(m)

    try:

        r = client.models.generate_content(
            model=m,
            contents="Hello"
        )

        print("SUCCESS")
        print(r.text)

    except Exception as e:
        print(e)