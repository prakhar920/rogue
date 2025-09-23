# llm.py
import base64
import os
import re
import traceback
from typing import Dict, List, Optional
from openai import OpenAI
from anthropic import Anthropic
from constants import OPENAI_API_KEY
from utils import get_base64_image

# Demo fallback text used when DEMO_MODE is enabled or when API calls fail
DEMO_FALLBACK_TEXT = """[DEMO MODE] Sample LLM analysis:
- Possible Vulnerability: Reflected XSS in 'q' parameter
  Sample payload: <script>alert('xss')</script>
- Possible Vulnerability: Missing security headers (X-Frame-Options)
Recommendations:
1. Sanitize user input and output-encode where necessary.
2. Add security headers: X-Frame-Options, Content-Security-Policy, Referrer-Policy.
"""

class LLM:
    """
    Large Language Model interface for security testing.

    Provides methods to interact with LLMs for security analysis and testing.
    Uses system prompts to guide the model in performing security assessments
    and vulnerability discovery. Enhanced with live security knowledge from expert sources.
    """

    def __init__(self, knowledge_content: Optional[str] = None):
        """Initialize the LLM client and system prompt with security knowledge.

        Args:
            knowledge_content (str): Pre-fetched security knowledge summary to include in system prompt
        """
        # Initialize OpenAI client
        self.client = OpenAI(api_key=OPENAI_API_KEY)

        # Use provided knowledge summary or fallback message
        if knowledge_content:
            self.knowledge_content = knowledge_content
        else:
            self.knowledge_content = "## Security Knowledge Base unavailable - proceeding with standard techniques"

        # long system prompt omitted for brevity in this snippet- keep original if you have it
        self.system_prompt = f"""
        You are a security researcher who is also the lead for an internal red team and the security team. Your job is to carefully scan a website, step by step, and evaluate if there are any security issues. You will be provided a lot of details about our internal company that we're testing, so feel free to fuzz, probe, and test the website. Here are just some of the concerns we want to focus on from web perspective.

        {self.knowledge_content}

        ## Apply Your Security Knowledge
        ...
        """


    def call_llm_with_fallback(self, messages: List[Dict[str, str]], model: str = "o4-mini", reasoning: str = "medium", temperature: float = 0.0) -> str:
        """
        Wrapper for calling the LLM client with an automatic fallback to DEMO text if:
         - DEMO_MODE env var is set, or
         - The API call raises an exception (e.g., insufficient quota).

        Args:
            messages: Chat messages to send to the model.
            model: Model name to use.
            reasoning: (optional) reasoning effort if supported.
            temperature: sampling temperature.

        Returns:
            The model's text response (or demo fallback text).
        """
        # Explicit demo mode override for demonstrations
        if os.getenv("DEMO_MODE", "").lower() in ("1", "true", "yes"):
            return DEMO_FALLBACK_TEXT

        try:
            # Use the repo's OpenAI client interface (matches original usage)
            response = self.client.chat.completions.create(
                model=model,
                reasoning_effort=reasoning,
                messages=messages,
                temperature=temperature
            )
            # defensive checks
            if hasattr(response, "choices") and len(response.choices) > 0:
                # matches original structure: response.choices[0].message.content
                choice = response.choices[0]
                if hasattr(choice, "message") and hasattr(choice.message, "content"):
                    return choice.message.content
                # fallback: try dict-style access
                try:
                    return response["choices"][0]["message"]["content"]
                except Exception:
                    pass

            # If structure unexpected, fall back to demo text
            return DEMO_FALLBACK_TEXT

        except Exception:
            print("[!] OpenAI / LLM API call failed — falling back to DEMO output")
            traceback.print_exc()
            return DEMO_FALLBACK_TEXT


    def reason(self, messages: List[Dict[str, str]], reasoning: str = "medium") -> str:
        """
        Generate a reasoned response from the LLM based on conversation history.

        Args:
            messages: List of conversation messages with role and content
            reasoning: Reasoning effort level ("low", "medium", "high")

        Returns:
            Generated response text
        """
        # Use the wrapper which will fallback to the demo text if needed
        return self.call_llm_with_fallback(messages, model="o4-mini", reasoning=reasoning, temperature=0.2)


    def output(self, message: str, temperature: float = 0.0) -> str:
        """
        Generate a single response from the LLM.

        Args:
            message: Input prompt text
            temperature: Sampling temperature (0.0 = deterministic)

        Returns:
            Generated response text
        """
        messages = [{"role": "user", "content": message}]
        # Use higher-capability model name if desired; demo wrapper will still handle failures
        return self.call_llm_with_fallback(messages, model="gpt-4o", reasoning="medium", temperature=temperature)
