# planner.py
import yaml
import re
from typing import Dict, List, Optional
from functools import wraps
from llm import LLM # Import our new LLM class

def retry_on_yaml_error(max_retries: int = 3):
    """Decorator that retries a function if it raises a YAML parsing error."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except yaml.YAMLError as e:
                    retries += 1
                    if retries == max_retries:
                        print(f"Failed after {max_retries} retries: {e}")
                        return []
                    print(f"YAML parsing failed, attempt {retries} of {max_retries}")
            return []
        return wrapper
    return decorator

class Planner:
    """A class that uses an LLM to generate security testing plans."""
    
    def __init__(self, llm_instance: LLM, knowledge_summary: Optional[str] = None, 
                 enable_baseline_checks: bool = True, max_plans: int = None,
                 num_plans_target: int = 10, additional_instructions: str = ''):
        """
        Initialize the planner.
        
        Args:
            llm_instance: An initialized instance of the LLM class.
            knowledge_summary: Optional security knowledge base summary.
            enable_baseline_checks: Whether to include OWASP Top 10 baseline checks.
            max_plans: Maximum number of plans to generate.
            num_plans_target: Target number of plans to generate.
            additional_instructions: Custom instructions for the planner.
        """
        self.llm = llm_instance # Use the passed LLM instance
        self.knowledge_summary = knowledge_summary
        self.enable_baseline_checks = enable_baseline_checks
        self.max_plans = max_plans
        self.num_plans_target = num_plans_target
        self.additional_instructions = additional_instructions
        self.knowledge_base = None # Will be set by agent if RAG enabled

        self.baseline_checks = [
            {"title": "A01: Broken Access Control", "description": "Test for flaws related to authentication, authorization, and session management."},
            {"title": "A03: Injection (SQL, NoSQL, Command)", "description": "Probe inputs for injection vulnerabilities by sending malicious data."},
            {"title": "A05: Security Misconfiguration", "description": "Check for insecure default configurations, open ports, and verbose error messages."},
            {"title": "A07: Identification and Authentication Failures", "description": "Test for weaknesses in user identification and authentication processes."},
            {"title": "A10: Server-Side Request Forgery (SSRF)", "description": "Test features that fetch remote resources to see if they can be forced to make requests to internal services."},
        ]

    @retry_on_yaml_error()
    def plan_batch(self, context_data: str, batch_size: int) -> List[Dict]:
        """
        Generate a batch of security testing plans with iterative context.
        """
        plan_instruction = f"{batch_size} distinct security test plans"

        system_prompt = f"""
        You are an expert bug bounty hunter. Based on the provided page content, generate {plan_instruction}. Each plan should focus on a specific vulnerability type or attack vector.

        Consider testing for:
        - SQL Injection, Cross-Site Scripting (XSS), Authentication/Authorization flaws, Directory Traversal, Command Injection, Business Logic vulnerabilities, CSRF, Information Disclosure.

        For each plan, provide:
        1. title: A clear, specific test plan name
        2. description: A detailed methodology explaining what to test and how.

        Return your response ONLY as a YAML list of plans, enclosed in markdown code fences:
        ```yaml
        - title: "Plan Title 1"
          description: "Detailed description..."
        - title: "Plan Title 2"
          description: "Detailed description..."
        ```
        Focus on plans likely to yield high-impact vulnerabilities.
        {self.additional_instructions}
        
        IMPORTANT: If execution insights are provided, use them to:
        1. Avoid repeating failed approaches unless you have a new angle.
        2. Build upon successful techniques with variations.
        3. Focus on areas that haven't been thoroughly tested yet.
        """

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": context_data}
        ]
        
        response_text = self.llm.reason(messages)
        
        # Extract YAML content from the response
        yaml_match = re.search(r'```yaml\n(.*?)\n```', response_text, re.DOTALL)
        if not yaml_match:
            print("Warning: No valid YAML plan found in the LLM response.")
            return []
            
        yaml_content = yaml_match.group(1)
        plans = yaml.safe_load(yaml_content)
        return plans if isinstance(plans, list) else []