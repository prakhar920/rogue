# constants.py
import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

DEMO_MODE = os.getenv("DEMO_MODE", "").lower() in ("1", "true", "yes")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# In non-demo mode, we need at least one API key to function.
if not DEMO_MODE and not OPENAI_API_KEY and not GEMINI_API_KEY:
    raise ValueError(
        "No API key found. Please set either OPENAI_API_KEY or GEMINI_API_KEY "
        "as an environment variable or in a .env file to continue."
    )