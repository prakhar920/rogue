import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
if not OPENAI_API_KEY:
    raise ValueError("OpenAI API key not found. Please set the OPENAI_API_KEY environment variable or create a .env file with OPENAI_API_KEY=your-key-here.")