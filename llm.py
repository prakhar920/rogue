# llm.py
import os
import traceback
from typing import Dict, List, Optional

from openai import OpenAI
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

from constants import OPENAI_API_KEY, GEMINI_API_KEY, DEMO_MODE

# Demo fallback text used when DEMO_MODE is enabled or when API calls fail
DEMO_FALLBACK_TEXT = """
* DISCUSSION
[DEMO MODE] This is a sample analysis. The 'q' parameter appears vulnerable to Reflected XSS. I will attempt a basic payload to confirm.
* ACTION
execute_js('alert("XSS in q parameter")')
"""

class LLM:
    """
    Large Language Model interface for security testing.
    
    Provides methods to interact with LLMs for security analysis and testing.
    This class can dynamically switch between OpenAI and Google Gemini models.
    """

    def __init__(self, model: str, knowledge_content: Optional[str] = None):
        """
        Initialize the LLM client and system prompt with security knowledge.

        Args:
            model (str): The name of the LLM model to use (e.g., 'o4-mini', 'gemini-1.5-pro').
            knowledge_content (str): Pre-fetched security knowledge summary.
        """
        self.model_name = model
        self.knowledge_content = knowledge_content or "## Security Knowledge Base unavailable - proceeding with standard techniques"
        self.is_gemini = 'gemini' in self.model_name.lower()

        try:
            if self.is_gemini:
                if not GEMINI_API_KEY and not DEMO_MODE:
                    raise ValueError("GEMINI_API_KEY is not set.")
                genai.configure(api_key=GEMINI_API_KEY)
                self.client = genai.GenerativeModel(
                    self.model_name,
                    safety_settings={
                        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                    }
                )
            else:
                if not OPENAI_API_KEY and not DEMO_MODE:
                    raise ValueError("OPENAI_API_KEY is not set.")
                self.client = OpenAI(api_key=OPENAI_API_KEY)
        except Exception as e:
            raise RuntimeError(f"Failed to initialize LLM client for model {self.model_name}: {e}")

        # The full system prompt (shortened here for clarity)
        self.system_prompt = f"""
        You are a security researcher who is also the lead for an internal red team and the security team. Your job is to carefully scan a website, step by step, and evaluate if there are any security issues. You will be provided a lot of details about our internal company that we're testing, so feel free to fuzz, probe, and test the website. Here are just some of the concerns we want to focus on from a web perspective.

        {self.knowledge_content}

        ## Apply Your Security Knowledge
        You have access to the latest security research and proven exploitation techniques from PentestMonkey Cheat Sheets, CAPEC Attack Patterns, OWASP WSTG Techniques, CISA KEV (Known Exploited Vulnerabilities), DevSec Blog, and PortSwigger labs. Apply this knowledge strategically.
        
        ## Tools
        You are an agent and have access to plenty of tools. Your output must select one tool to use.
        - execute_js(js_code)
        - click(css_selector)
        - fill(css_selector, value)
        - auth_needed()
        - get_user_input(prompt)
        - presskey(key)
        - submit(css_selector)
        - goto(url)
        - refresh()
        - python_interpreter(code, page=None)
        - complete()
        
        ## Output format
        At every step, you must only do one action. Your output must be of the following format:

        * DISCUSSION
        A brief two-line analysis. What was done, what was the result, and what is the next step.
        * ACTION
        The single tool call you will execute next. No explanation needed.

        ## Rules and Instructions to follow
        - Always provide a discussion and a tool action.
        - Do not call complete() unless you have a working exploit with clear reproduction steps.
        - Use the element selectors provided in the initial page summary.
        - Act like a human expert, not a machine. Try creative and advanced techniques.
        """

    def reason(self, messages: List[Dict[str, str]]) -> str:
        """
        Generate a reasoned response from the LLM based on conversation history.

        Args:
            messages: List of conversation messages with role and content.

        Returns:
            Generated response text.
        """
        if DEMO_MODE:
            return DEMO_FALLBACK_TEXT

        try:
            if self.is_gemini:
                # Gemini uses a different message format
                gemini_messages = []
                for msg in messages:
                    role = "model" if msg["role"] == "assistant" else "user"
                    # Gemini doesn't have a 'system' role, so we prepend it to the first user message
                    if msg["role"] == "system":
                        continue # System prompt is handled separately
                    gemini_messages.append({"role": role, "parts": [msg["content"]]})

                # Prepend the system prompt to the conversation
                response = self.client.generate_content(
                    [self.system_prompt] + gemini_messages
                )
                return response.text
            else:
                # OpenAI call
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    temperature=0.2,
                )
                return response.choices[0].message.content
        except Exception as e:
            print(f"[!] LLM API call failed: {e}")
            traceback.print_exc()
            return DEMO_FALLBACK_TEXT