# constants.py
import os

DEMO_MODE = os.getenv("DEMO_MODE", "").lower() in ("1", "true", "yes")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Only require a real API key when not in demo mode
if not OPENAI_API_KEY and not DEMO_MODE:
    raise ValueError(
        "OpenAI API key not found. Please set the OPENAI_API_KEY environment variable or create a .env file with OPENAI_API_KEY=your-key-here."
    )
