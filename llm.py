# llm.py
import os
import traceback
from typing import Dict, List, Optional

# Attempt to import SDKs, handle gracefully if missing
try:
    from openai import OpenAI
except ImportError:
    # print("[Warning] OpenAI SDK not found. OpenAI models will not be available.")
    OpenAI = None # Set to None if import fails

try:
    import google.generativeai as genai
    # Check if necessary components exist before importing them specifically
    if hasattr(genai, 'types') and hasattr(genai.types, 'HarmCategory') and hasattr(genai.types, 'HarmBlockThreshold'):
        from google.generativeai.types import HarmCategory, HarmBlockThreshold
    else:
        # print("[Warning] Could not find HarmCategory/HarmBlockThreshold in google.generativeai.types. Safety settings may be limited.")
        HarmCategory = None
        HarmBlockThreshold = None
except ImportError:
    # print("[Warning] Google Generative AI SDK not found. Gemini models will not be available.")
    genai = None # Set to None if import fails
    HarmCategory = None
    HarmBlockThreshold = None

# Import DEMO_MODE check LAST, after attempting SDK imports
# Ensure constants.py exists and defines these
try:
    from constants import OPENAI_API_KEY, GEMINI_API_KEY, DEMO_MODE
except ImportError:
    print("[Error] CRITICAL: Could not import from constants.py. Ensure the file exists and is correct.")
    # Define defaults to allow script to potentially continue in some modes, but warn heavily
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("1", "true", "yes") # Default to False if import fails


# --- THIS IS THE NEW, SPACED-OUT DEMO TEXT ---
DEMO_FALLBACK_TEXT = """

* DISCUSSION

[DEMO MODE] Analysis of target http://testphp.vulnweb.com complete.
The page summary indicates a 'search' input field and a 'go' button, suggesting a search functionality. 
The immediate plan is to test this search parameter for a basic reflected Cross-Site Scripting (XSS) vulnerability. I will inject a simple script payload into the search box and submit the form.


* ACTION

fill("input[name='search']", "<script>alert('DEMO_XSS')</script>")

"""
# --- END OF UPDATE ---

class LLM:
    """
    LLM interface handling OpenAI/Gemini and Demo Mode.
    """

    def __init__(self, model: str, knowledge_content: Optional[str] = None):
        """
        Initialize LLM client ONLY if not in DEMO_MODE.
        Raises RuntimeError if required SDK/API key is missing in live mode.
        """
        self.model_name = model
        self.knowledge_content = knowledge_content or "## Security Knowledge Base unavailable"
        self.is_gemini = 'gemini' in self.model_name.lower()
        self.client = None # Start with no client
        self.keep_messages = 15 # Add keep_messages attribute here

        # --- FINAL DEMO MODE INITIALIZATION FIX ---
        if not DEMO_MODE:
            # Only attempt initialization in live mode
            print(f"[Info] Initializing LLM client for '{self.model_name}' (Live Mode)...")
            try:
                if self.is_gemini:
                    if not genai:
                        # Fatal if SDK missing in live mode
                        raise ImportError("Google Generative AI SDK not installed but required for Gemini model. Run 'pip install google-generativeai'")
                    if not GEMINI_API_KEY:
                        # Fatal if key missing in live mode (run.py should catch this first, but double-check)
                        raise ValueError("GEMINI_API_KEY is missing. Please set it in .env file or environment for live mode.")

                    genai.configure(api_key=GEMINI_API_KEY)
                    # Define safety settings, checking if imports worked
                    safety_config = None
                    if HarmCategory and HarmBlockThreshold:
                        safety_config = {
                            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                        }
                    else:
                        print("[Warning] HarmCategory/HarmBlockThreshold not available. Using default safety settings for Gemini.")

                    self.client = genai.GenerativeModel(self.model_name, safety_settings=safety_config)
                    print(f"[Info] Gemini client for model '{self.model_name}' initialized successfully.")

                else: # OpenAI
                    if not OpenAI:
                         # Fatal if SDK missing in live mode
                         raise ImportError("OpenAI SDK not installed but required for OpenAI model. Run 'pip install openai'")
                    if not OPENAI_API_KEY:
                        # Fatal if key missing in live mode (run.py should catch this first)
                        raise ValueError("OPENAI_API_KEY is missing. Please set it in .env file or environment for live mode.")
                    self.client = OpenAI(api_key=OPENAI_API_KEY)
                    print(f"[Info] OpenAI client for model '{self.model_name}' initialized successfully.")

            except Exception as e:
                # Make initialization errors fatal in live mode, provide clear message
                error_msg = f"LLM Client Initialization Failed for model '{self.model_name}'. Check API key in .env, SDK installation ('pip install openai' or 'pip install google-generativeai'), model name validity, and network connection. Original error: {type(e).__name__} - {e}"
                print(f"[Error] FATAL: {error_msg}")
                raise RuntimeError(error_msg) # Re-raise to stop Agent execution cleanly
        else:
             # Explicitly confirm skipping initialization in Demo Mode
             print("[Info] DEMO_MODE is active. LLM client initialization skipped.")
        # --- END FINAL DEMO MODE INITIALIZATION FIX ---

        # System prompt definition (ensure it's complete)
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
        """ # Replace with your full prompt if different


    def reason(self, messages: List[Dict[str, str]]) -> str:
        """
        Generate response: uses DEMO_FALLBACK_TEXT if in demo mode, otherwise calls the API.
        Handles API errors gracefully.
        """
        # --- DEMO MODE CHECK ---
        if DEMO_MODE:
            # print("[Debug] In reason(): DEMO MODE active, returning fallback.") # Optional
            return DEMO_FALLBACK_TEXT

        # --- LIVE MODE CHECKS ---
        if not self.client:
             # This error indicates a problem during __init__ that wasn't caught or DEMO_MODE logic failed
             error_msg = "[Error] In reason(): LLM client is None in live mode. Initialization likely failed earlier. Cannot make API call."
             print(error_msg)
             # Raising an error might be better than returning a string here if this happens
             # raise RuntimeError(error_msg)
             return error_msg # Return error string for now

        # --- LIVE API CALL ---
        try:
            if self.is_gemini:
                if not genai: # Check again in case SDK was missing
                     return "[Error] Cannot call Gemini: Google Generative AI SDK not available."

                # Prepare messages for Gemini
                gemini_messages = []
                system_instruction = None # Standard models often infer from history
                # Filter out system message, convert roles
                for msg in messages:
                    if msg["role"] == "system":
                        # Store system prompt if Gemini API supports it later
                        # system_instruction = msg["content"]
                        continue
                    role = "model" if msg["role"] == "assistant" else "user"
                    # Ensure content is just text for basic Gemini call
                    content_part = msg.get("content", "")
                    if not isinstance(content_part, str):
                         content_part = str(content_part) # Convert if needed, might lose info
                    gemini_messages.append({"role": role, "parts": [content_part]})

                # print(f"[Debug] Calling Gemini model '{self.model_name}'...") # Optional
                # Make the API call - Use generate_content
                response = self.client.generate_content(
                     contents=gemini_messages,
                     # generation_config={"temperature": 0.2, "max_output_tokens": 4096}, # Example config
                     # system_instruction=system_instruction # Add if supported
                 )

                # --- Robust Gemini Response Handling ---
                try:
                    # Check candidates first for explicit blocking information
                    if response.candidates and hasattr(response.candidates[0], 'finish_reason') and response.candidates[0].finish_reason != 'STOP':
                        block_reason = response.candidates[0].finish_reason
                        safety_info = getattr(response.candidates[0], 'safety_ratings', 'N/A')
                        print(f"[Warning] Gemini response potentially blocked. Finish Reason: {block_reason}, Safety: {safety_info}")
                        return f"[Error] Gemini response blocked due to {block_reason}. Check safety settings or prompt content."

                    # Attempt to get text, handle potential errors if blocked differently
                    # Using response.text can raise ValueError if blocked
                    response_text = response.text # This might raise ValueError
                    if response_text:
                         # print("[Debug] Gemini response received successfully.") # Optional
                         return response_text
                    else:
                         # Handle cases where response might be valid but text is missing
                         # Check prompt feedback if available
                         block_reason = "Unknown reason (empty response)"
                         if hasattr(response, 'prompt_feedback') and hasattr(response.prompt_feedback, 'block_reason') and response.prompt_feedback.block_reason:
                             block_reason = response.prompt_feedback.block_reason
                         print(f"[Warning] Gemini response was valid but contained no text. Reason: {block_location}")
                         return f"[Error] Gemini returned an empty or blocked response: {block_reason}"

                except ValueError as ve: # Catch explicit error when accessing .text on blocked content
                     block_reason = "SafetySettings or Content Filter" # Default reason
                     # Try to get more specific reason from prompt_feedback
                     if hasattr(response, 'prompt_feedback') and hasattr(response.prompt_feedback, 'block_reason') and response.prompt_feedback.block_reason:
                           block_reason = response.prompt_feedback.block_reason
                     print(f"[Warning] Gemini request blocked accessing .text. Reason: {block_reason} - {ve}")
                     return f"[Error] Gemini request blocked: {block_reason}. Review prompt content."
                except Exception as resp_err: # Catch other potential issues accessing response attributes
                    print(f"[Error] Unexpected error processing Gemini response object: {resp_err}")
                    traceback.print_exc()
                    return f"[Error] Failed to process Gemini response object: {resp_err}"
                # --- End Robust Gemini Handling ---

            else: # OpenAI
                if not OpenAI: # Check again
                    return "[Error] Cannot call OpenAI: OpenAI SDK not available."
                # print(f"[Debug] Calling OpenAI model '{self.model_name}'...") # Optional
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages, # Pass the original list including system message
                    temperature=0.2,
                    # max_tokens=4096 # Optional: Set token limit
                )
                # print("[Debug] OpenAI response received.") # Optional
                # Check for content before returning
                if response.choices and response.choices[0].message and response.choices[0].message.content:
                    return response.choices[0].message.content
                else:
                    print("[Warning] OpenAI response structure unexpected or content missing.")
                    return "[Error] OpenAI returned an unexpected or empty response."

        except Exception as e:
            # Catch API errors (e.g., RateLimitError, AuthenticationError), network issues etc.
            error_type = type(e).__name__
            error_details = str(e)
            print(f"[!] LLM API call failed during reason(): {error_type} - {error_details}")
            # Consider logging traceback only if needed for detailed debugging
            # traceback.print_exc()
            # Provide a user-friendly error message incorporating specifics
            return f"[Error] LLM API call failed ({error_type}). Please check your API key validity, subscription/quota, network connection, and the model name ('{self.model_name}'). Details: {error_details}"