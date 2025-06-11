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
                 enable_baseline_checks: bool = True, max_plans: int = None):
        """
        Initialize the planner.
        
        Args:
            knowledge_summary: Optional security knowledge base summary
            enable_baseline_checks: Whether to always include OWASP Top 10 baseline checks
            max_plans: Maximum number of plans to generate (None = unlimited)
        """
        self.knowledge_summary = knowledge_summary
        self.enable_baseline_checks = enable_baseline_checks
        self.max_plans = max_plans
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
        - **PortSwigger Web Security Academy Labs**: SQL injection, XSS, CSRF, authentication bypasses, access control flaws, SSRF, XXE, and business logic vulnerabilities
        - **Expert Penetration Testing Techniques**: Advanced payload crafting, polyglot attacks, chained exploits, and novel bypass methods

        When planning security tests, prioritize techniques that have proven successful in real-world penetration tests and CTF challenges. Think like a security expert who understands both classic attack vectors and modern exploitation techniques.
        """
        
        self.knowledge_content = knowledge_content

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
            List[Dict]: List of additional testing plans
        """
        # Get technology-specific knowledge if RAG is enabled
        knowledge_content = self._get_contextual_knowledge(page_data)
        
        dynamic_prompt = f"""
        {knowledge_content}
        
        You are an expert security researcher analyzing a web application for advanced vulnerabilities beyond the OWASP Top 10 baseline checks.

        Based on the provided page content and technology stack, generate {num_plans} highly targeted security test plans that are specifically relevant to this application's attack surface and technology.

        Focus on:
        - Technology-specific vulnerabilities (e.g., .NET ViewState, PHP deserialization, Node.js prototype pollution)
        - Framework-specific attacks (e.g., WordPress plugin vulnerabilities, Django template injection)
        - Modern web application attack vectors (e.g., GraphQL introspection, JWT manipulation, API rate limiting bypasses)
        - Business logic specific to this application type
        - Advanced injection techniques beyond basic SQLi/XSS
        - Cloud and infrastructure specific attacks if indicators are present

        **Page Data:**
        {page_data}

        **Response Format:**
        Return ONLY a valid YAML list of security test plans. Each plan must have exactly these fields:
        
        ```yaml
        - title: "Brief Descriptive Title"
          description: "Detailed description of what to test, specific techniques to use, and expected outcomes. Include exact payloads, parameter names, and step-by-step testing methodology."
        ```

        **Requirements:**
        - Each plan must be actionable with specific testing steps
        - Include exact parameter names, endpoints, and payloads where possible
        - Focus on high-impact vulnerabilities likely to exist in this technology stack
        - Prioritize novel and advanced attack vectors over basic scanning
        """

        try:
            response = self.client.chat.completions.create(
                model="o3-mini",
                messages=[{"role": "user", "content": dynamic_prompt}],
                max_tokens=3000,
                temperature=0.8
            )
            
            plans_text = response.choices[0].message.content.strip()
            
            # Remove markdown code block formatting if present
            if plans_text.startswith("```yaml"):
                plans_text = plans_text.replace("```yaml", "", 1)
            if plans_text.endswith("```"):
                plans_text = plans_text.rsplit("```", 1)[0]
            
            plans_text = plans_text.strip()
            
            # Parse YAML
            additional_plans = yaml.safe_load(plans_text)
            
            if not isinstance(additional_plans, list):
                print("Warning: Dynamic plans response was not a list, falling back to empty list")
                return []
                
            return additional_plans
            
        except Exception as e:
            print(f"Error generating dynamic plans: {e}")
            return []

    def _get_contextual_knowledge(self, page_data: str) -> str:
        """Get contextual knowledge including technology-specific info."""
        knowledge_parts = []
        
        # Add static knowledge base content
        knowledge_parts.append("=== SECURITY KNOWLEDGE BASE ===")
        knowledge_parts.append(self.knowledge_content)
        
        # Add technology-specific knowledge if RAG is enabled
        if self.knowledge_base:
            try:
                tech_knowledge = self.knowledge_base.get_technology_specific_knowledge(page_data)
                if tech_knowledge and tech_knowledge != "No specific technology vulnerabilities found.":
                    knowledge_parts.append("\n=== TECHNOLOGY-SPECIFIC VULNERABILITIES ===")
                    knowledge_parts.append(tech_knowledge)
                    knowledge_parts.append("\nUse this technology-specific intelligence to:")
                    knowledge_parts.append("- Target known CVEs for the detected technology stack")
                    knowledge_parts.append("- Focus on framework-specific attack vectors")
                    knowledge_parts.append("- Prioritize high-impact vulnerabilities relevant to this technology")
            except Exception as e:
                print(f"Warning: Could not fetch technology-specific knowledge: {e}")
        
        return "\n".join(knowledge_parts)

    @retry_on_yaml_error(max_retries=3)
    def plan(self, page_data: str) -> list:
        """
        Generate a comprehensive security testing plan with baseline OWASP Top 10 checks 
        and additional context-specific tests.
        
        Args:
            page_data (str): Information about the page being tested
            
        Returns:
            list: Complete list of security test plans
        """
        all_plans = []
        
        # Always include OWASP Top 10 baseline checks if enabled
        if self.enable_baseline_checks:
            all_plans.extend(self.baseline_checks)
            
        # Assess page complexity to determine number of additional plans needed
        if self.max_plans is None:
            # Dynamic planning based on page complexity
            num_additional_plans = self._assess_page_complexity(page_data)
        else:
            # Use specified max_plans, accounting for baseline checks
            baseline_count = len(self.baseline_checks) if self.enable_baseline_checks else 0
            num_additional_plans = max(0, self.max_plans - baseline_count)
            
        # Generate additional context-specific plans
        if num_additional_plans > 0:
            additional_plans = self._generate_dynamic_plans(page_data, num_additional_plans)
            all_plans.extend(additional_plans)
            
        # Apply max_plans limit if specified
        if self.max_plans is not None:
            all_plans = all_plans[:self.max_plans]
            
        return all_plans
