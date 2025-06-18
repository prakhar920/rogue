import yaml
import base64
import os
import re
from typing import Dict, List, Optional
from openai import OpenAI
from anthropic import Anthropic
from constants import OPENAI_API_KEY
from functools import wraps

def retry_on_yaml_error(max_retries: int = 3):
    """
    Decorator that retries a function if it raises a YAML parsing error.
    
    Args:
        max_retries (int): Maximum number of retries before giving up
        
    Returns:
        Decorated function that implements retry logic
    """
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
    """
    A class that uses OpenAI's API to generate security testing plans.
    """
    
    def __init__(self, knowledge_summary: Optional[str] = None, 
                 enable_baseline_checks: bool = True, max_plans: int = None,
                 num_plans_target: int = 10):
        """
        Initialize the planner.
        
        Args:
            knowledge_summary: Optional security knowledge base summary
            enable_baseline_checks: Whether to always include OWASP Top 10 baseline checks
            max_plans: Maximum number of plans to generate (None = unlimited)
            num_plans_target: Target number of security testing plans to generate (default: 10, use -1 for unlimited)
        """
        self.knowledge_summary = knowledge_summary
        self.enable_baseline_checks = enable_baseline_checks
        self.max_plans = max_plans
        self.num_plans_target = num_plans_target if num_plans_target is not None else (max_plans if max_plans is not None else 10)
        self.knowledge_base = None  # Will be set by agent if RAG enabled
        
        # Initialize OpenAI client
        openai_api_key = os.getenv('OPENAI_API_KEY')
        if not openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        
        # OWASP Top 10 2021 baseline security checks that should always be performed
        self.baseline_checks = [
            {
                "title": "A01: Broken Access Control - Authentication Bypass Testing",
                "description": "Test authentication mechanisms for bypass vulnerabilities including SQL injection in login forms, parameter tampering for role elevation, and direct object reference manipulation. Try authentication bypass techniques like null byte injection, boolean-based SQLi ('OR 1=1--), and session token manipulation."
            },
            {
                "title": "A02: Cryptographic Failures - Session and Data Protection", 
                "description": "Examine session management security including session hijacking, fixation, and weak session tokens. Test for sensitive data exposure through HTTP (vs HTTPS), weak encryption, and information disclosure through error messages or debug information."
            },
            {
                "title": "A03: SQL Injection - Database Attack Vectors",
                "description": "Systematically test all input parameters for SQL injection vulnerabilities including GET/POST parameters, headers, and cookies. Use techniques like error-based injection, boolean blind injection, time-based blind injection, and UNION-based extraction."
            },
            {
                "title": "A04: Insecure Design - Business Logic Vulnerabilities",
                "description": "Test business logic flaws including workflow bypasses, race conditions, privilege escalation through parameter manipulation, and abuse of application features. Look for design flaws in multi-step processes and security controls."
            },
            {
                "title": "A05: Security Misconfiguration - Server and Application Issues", 
                "description": "Check for security misconfigurations including default credentials, unnecessary services, verbose error messages, directory traversal, and insecure HTTP headers. Test for admin interfaces and debug endpoints."
            },
            {
                "title": "A06: Vulnerable Components - Third-Party Security",
                "description": "Identify and test known vulnerabilities in third-party components, frameworks, and libraries. Look for version disclosure in headers, JavaScript libraries, and CMS platforms that may have known exploits."
            },
            {
                "title": "A07: Identification and Authentication Failures",
                "description": "Test authentication mechanisms for weaknesses including weak password policies, credential stuffing opportunities, session management flaws, and multi-factor authentication bypasses."
            },
            {
                "title": "A08: Software and Data Integrity Failures",
                "description": "Test for insecure deserialization, supply chain attacks, and data integrity issues. Look for auto-update mechanisms, plugin systems, and data validation bypasses."
            },
            {
                "title": "A09: Security Logging and Monitoring Failures", 
                "description": "Test the application's logging and monitoring capabilities by attempting various attacks and checking if they're properly detected and logged. Look for information disclosure through logs."
            },
            {
                "title": "A10: Server-Side Request Forgery (SSRF)",
                "description": "Test for SSRF vulnerabilities in URL parameters, file upload functions, and any features that fetch external resources. Try accessing internal services, cloud metadata endpoints, and local file systems."
            }
        ]
        
        # Use provided knowledge summary or fallback message
        if knowledge_summary:
            knowledge_content = knowledge_summary
        else:
            knowledge_content = """
        ## Current Security Knowledge Base
        You have access to the latest security research and proven techniques:
        - **DevSec Blog Web API Security Champion Series**: Focus on authorization bypasses, authentication flaws, object-level access control, and resource consumption attacks
        - **PentestMonkey Cheat Sheets**: SQL injection, XSS, CSRF, authentication bypasses, access control flaws, SSRF, XXE, and business logic vulnerabilities
        - **Expert Penetration Testing Techniques**: Advanced payload crafting, polyglot attacks, chained exploits, and novel bypass methods

        When planning security tests, prioritize techniques that have proven successful in real-world penetration tests and CTF challenges. Think like a security expert who understands both classic attack vectors and modern exploitation techniques.
        """
        
        self.knowledge_content = knowledge_content
        
        # Determine plan count instruction
        if self.num_plans_target <= 0:
            plan_instruction = "as many comprehensive security test plans as possible (aim for 15-25+ distinct plans)"
        else:
            plan_instruction = f"{self.num_plans_target} distinct security test plans"
        
        self.system_prompt = f"""
        You are an expert bug bounty hunter with years of experience finding critical vulnerabilities in web applications. Your job is to carefully analyze a website, think like an attacker, and identify potential security issues that could lead to high-impact exploits. You will be provided details about our internal company that we're testing, so think creatively about how the application could be abused.

        Based on the provided page content, generate {plan_instruction}. Each plan should focus on a specific vulnerability type or attack vector.

        Consider testing for:
        - SQL Injection (authentication bypass, data extraction, blind techniques)
        - Cross-Site Scripting (reflected, stored, DOM-based)
        - Authentication and authorization flaws
        - Directory traversal and path manipulation
        - Command injection and code execution
        - Business logic vulnerabilities
        - CSRF and state management issues
        - Information disclosure
        - Input validation bypasses
        - Session management weaknesses

        For each plan, provide:
        1. title: A clear, specific test plan name
        2. description: Detailed methodology explaining what to test and how

        Return your response as a YAML list of plans:
        ```yaml
        - title: "Plan Title 1"
          description: "Detailed description of what to test and methodology..."
        - title: "Plan Title 2"  
          description: "Detailed description of what to test and methodology..."
        ```

        Focus on plans that are most likely to yield high-impact vulnerabilities given the page content and functionality observed."""

    def _assess_page_complexity(self, page_data: str) -> int:
        """
        Assess the complexity and attack surface of a page to determine optimal number of additional plans.
        
        Args:
            page_data (str): Page information and content
            
        Returns:
            int: Recommended number of additional plans beyond baseline checks
        """
        complexity_score = 0
        page_lower = page_data.lower()
        
        # Technology stack indicators
        tech_indicators = {
            'asp.net': 3, '.asp': 2, '.aspx': 2, 'viewstate': 2,
            'php': 2, '.php': 1, 'wordpress': 3, 'drupal': 3,
            'javascript': 1, 'ajax': 2, 'react': 2, 'angular': 2,
            'api': 2, 'rest': 1, 'graphql': 3, 'soap': 2,
            'upload': 3, 'file': 1, 'download': 2,
            'admin': 3, 'administrator': 3, 'management': 2,
            'search': 2, 'filter': 1, 'sort': 1,
            'forum': 2, 'comment': 2, 'message': 2, 'post': 1,
            'login': 2, 'register': 2, 'authentication': 2,
            'payment': 4, 'checkout': 4, 'cart': 2, 'order': 2,
            'database': 2, 'sql': 2, 'query': 2,
            'template': 2, 'include': 2, 'import': 1,
        }
        
        for indicator, score in tech_indicators.items():
            if indicator in page_lower:
                complexity_score += score
        
        # Form and input indicators
        form_indicators = ['form', 'input', 'textarea', 'select', 'button']
        form_count = sum(1 for indicator in form_indicators if indicator in page_lower)
        complexity_score += min(form_count * 2, 10)  # Cap form contribution at 10
        
        # Parameter indicators
        param_indicators = ['?', '&', 'param', 'id=', 'page=', 'action=', 'mode=']
        param_count = sum(1 for indicator in param_indicators if indicator in page_lower)
        complexity_score += min(param_count, 8)  # Cap parameter contribution at 8
        
        # Convert complexity score to number of additional plans
        if complexity_score <= 5:
            return 2  # Simple page - minimal additional testing
        elif complexity_score <= 15:
            return 5  # Moderate complexity 
        elif complexity_score <= 25:
            return 8  # High complexity
        else:
            return 12  # Very high complexity - comprehensive testing needed
    
    def _generate_dynamic_plans(self, page_data: str, num_plans: int) -> List[Dict]:
        """
        Generate additional context-specific security test plans based on page analysis.
        
        Args:
            page_data (str): Page information and content
            num_plans (int): Number of additional plans to generate
            
        Returns:
            List[Dict]: Generated security test plans
        """
        if num_plans <= 0:
            return []
            
        # Create dynamic system prompt for context-specific plans
        dynamic_prompt = f"""
        You are an expert penetration tester. Based on the page content analysis below, generate exactly {num_plans} highly targeted security test plans that are specifically relevant to the technologies and functionality you observe.

        {self.knowledge_content}

        Focus on:
        - Technology-specific vulnerabilities (based on detected stack)
        - Functionality-specific attack vectors (based on observed features)
        - Context-appropriate testing techniques
        - High-impact exploitation scenarios

        Generate exactly {num_plans} distinct plans. Each plan should be highly specific to the page content provided.
        
        Return as YAML:
        ```yaml
        - title: "Specific Plan Title"
          description: "Detailed context-specific methodology..."
        ```
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": dynamic_prompt},
                    {"role": "user", "content": page_data}
                ],
                max_tokens=4000,
                temperature=0.8
            )
            
            response_text = response.choices[0].message.content
            
            # Extract YAML content
            yaml_match = re.search(r'```yaml\n(.*?)\n```', response_text, re.DOTALL)
            if yaml_match:
                yaml_content = yaml_match.group(1)
                plans = yaml.safe_load(yaml_content)
                return plans if isinstance(plans, list) else []
            else:
                print("No valid YAML found in response")
                return []
                
        except Exception as e:
            print(f"Error generating dynamic plans: {e}")
            return []

    def plan(self, page_data: str) -> List[Dict]:
        """
        Generate a comprehensive list of security testing plans.
        
        Args:
            page_data (str): Information about the page to test
            
        Returns:
            List[Dict]: List of security test plans
        """
        all_plans = []
        
        # Always include baseline OWASP Top 10 checks if enabled
        if self.enable_baseline_checks:
            all_plans.extend(self.baseline_checks)
        
        # Assess page complexity to determine how many additional plans to generate
        if self.num_plans_target > 0:
            # Fixed number of plans requested
            additional_plans_needed = max(0, self.num_plans_target - len(all_plans))
        else:
            # Dynamic based on complexity
            additional_plans_needed = self._assess_page_complexity(page_data)
        
        # Generate additional context-specific plans
        if additional_plans_needed > 0:
            dynamic_plans = self._generate_dynamic_plans(page_data, additional_plans_needed)
            all_plans.extend(dynamic_plans)
        
        # Apply max_plans limit if set
        if self.max_plans and self.max_plans > 0:
            all_plans = all_plans[:self.max_plans]
        
        # Apply num_plans_target limit if set
        if self.num_plans_target > 0:
            all_plans = all_plans[:self.num_plans_target]
        
        return all_plans

    @retry_on_yaml_error(max_retries=3)
    def _try_parse_yaml(self, yaml_content: str) -> List[Dict]:
        """
        Attempt to parse YAML content with retry logic.
        
        Args:
            yaml_content (str): YAML content to parse
            
        Returns:
            List[Dict]: Parsed plans or empty list on failure
        """
        try:
            plans = yaml.safe_load(yaml_content)
            return plans if isinstance(plans, list) else []
        except yaml.YAMLError:
            # Let the decorator handle retries
            raise

    @retry_on_yaml_error()
    def plan_batch(self, context_data: str, batch_size: int) -> List[Dict]:
        """
        Generate a batch of security testing plans with iterative context.
        
        Args:
            context_data (str): Input message containing page information and execution insights
            batch_size (int): Number of plans to generate in this batch
            
        Returns:
            List[Dict]: List of testing plan items, each containing title and description
        """
        # Create a modified system prompt for batch planning
        batch_prompt = self.system_prompt.replace(
            "as many comprehensive security test plans as possible (aim for 15-25+ distinct plans)",
            f"exactly {batch_size} distinct security test plans"
        ).replace(
            f"{self.num_plans_target} distinct security test plans",
            f"exactly {batch_size} distinct security test plans"
        )
        
        # Add iterative planning instruction
        batch_prompt += f"""

        IMPORTANT: Generate exactly {batch_size} new and unique security test plans. If execution insights are provided, use them to:
        1. Avoid repeating failed approaches unless you have a new angle
        2. Build upon successful techniques with variations
        3. Focus on areas that haven't been thoroughly tested yet
        4. Consider chaining attacks based on discovered vulnerabilities
        
        Ensure each plan is distinct and targets different attack vectors or methodologies."""
        
        messages = [
            {"role": "system", "content": batch_prompt},
            {"role": "user", "content": context_data}
        ]
        
        response = self.client.chat.completions.create(
            model="o3-mini",
            messages=messages,
        )
        
        # Parse YAML response into list of dicts
        yaml_str = response.choices[0].message.content
        
        # Strip markdown code blocks if present
        if yaml_str.strip().startswith('```'):
            # Remove opening ```yaml or ``` 
            lines = yaml_str.strip().split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            # Remove closing ```
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            yaml_str = '\n'.join(lines)
        
        items = yaml.safe_load(yaml_str)
        if not isinstance(items, list):
            items = [items]
        
        # Return exactly the requested batch size
        return items[:batch_size]
