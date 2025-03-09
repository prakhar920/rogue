import yaml
import base64
import os
import re
from typing import Dict, List, Optional, Any
from openai import OpenAI
from anthropic import Anthropic
from constants import OPENAI_API_KEY, ANTHROPIC_API_KEY
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
    A class that uses LLMs to generate security testing plans.
    """
    
    def __init__(self, model_provider: str = "openai", model_name: str = None, debug: bool = False):
        """
        Initialize the Planner with specified provider and model.
        
        Args:
            model_provider: Provider to use ("openai" or "anthropic")
            model_name: Specific model to use (defaults to provider's recommended model)
            debug: Whether to enable debug output
        """
        self.model_provider = model_provider
        self.debug = debug
        
        # Initialize OpenAI client
        self.openai_client = OpenAI(api_key=OPENAI_API_KEY)
        
        # Initialize Anthropic client if API key is available
        if ANTHROPIC_API_KEY:
            self.anthropic_client = Anthropic(api_key=ANTHROPIC_API_KEY)
        else:
            self.anthropic_client = None
            if model_provider == "anthropic":
                raise ValueError("Anthropic API key not found but Anthropic provider requested")
        
        # Set default model names
        self.openai_model = model_name if model_name and model_provider == "openai" else "o3-mini"
        self.anthropic_model = model_name if model_name and model_provider == "anthropic" else "claude-3-sonnet-20240229"
        
        # Set model-specific configurations
        self.model_config = self._get_model_config()
        
        # Set system prompts (with provider-specific optimizations)
        self._set_system_prompts()
    
    def _get_model_config(self) -> Dict[str, Any]:
        """Get configuration settings for the selected model."""
        configs = {
            # Claude 3.7 Sonnet
            'claude-3-7-sonnet-20250219': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': True,
                'context_window': 128000,  # Beta feature
            },
            # Claude 3.5 Sonnet
            'claude-3-5-sonnet-20241022': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            },
            # Claude 3.5 Haiku
            'claude-3-5-haiku-20241022': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            },
            # Legacy Claude models
            'claude-3-opus-latest': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            },
            'claude-3-sonnet-latest': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            },
            'claude-3-haiku-latest': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            },
        }
        
        if self.model_provider == "anthropic":
            return configs.get(self.anthropic_model, {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            })
        
        return {
            'temperature': 0.0,
            'reasoning_effort': 'medium',
        }
    
    def _set_system_prompts(self):
        """Set system prompts optimized for each provider."""
        # Base prompt content (shared elements)
        base_prompt = """
        You are an expert bug bounty hunter with years of experience finding critical vulnerabilities in web applications. Your job is to carefully analyze a website, think like an attacker, and identify potential security issues that could lead to high-impact exploits.
        """
        
        # OpenAI-specific prompt
        self.openai_system_prompt = f"""
        {base_prompt} You will be provided details about our internal company that we're testing, so think creatively about how the application could be abused.

        ## Inputs
        Your inputs will be provided in the following format:

        - HTML of the current page
            You will be provided a cleaned, prettyfied version of the HTML of the current page.
        - Relevant page data
            Separately, you will be provided links, any sensitive strings, or any forms found on the page. This is a filtered set of information that might be useful to you. If you want to ignore it, you are free to do so.
        - Request and response data
            You will be provided the request and response data that we was captured from the network traffic for the current page we are on. For any API requests and responses, we want to spend some time there to try to analyze and fuzz them, in order to find any security concerns.
        
        ## Additional instructions
        - If you believe authentication would help find more vulnerabilities, start your plan by indicating that login is needed first. When you talk about login, just mention that we should call the auth_needed() function so that the user can help us login. But before you ask for the authentication, atleast have 1-2 plans that actually test stuff around authentication to make sure its implemented safely. Not everything must start with authentication though. If there are more clear vulns that you want to first explore, do that first.

        ## Output format
        You are tasked to build a plan for finding security vulnerabilities based on your expert analysis of the page and its functionality. Think deeply about how each component could potentially be exploited. 

        Output must be in yaml format. Each item should have a title, and description. Each title and description should be about a single kind of issue that could arise. We will use a yaml parser to parse your output, so start directly with the yaml. Be very specific in the description i.e if you are talking about any end points, mention their urls, etc.

        If you look at the page and determine that there is absolutely nothing interesting to test from a security perspective, just return an empty list.

        You must only base your analysis on the data you are provided. Do not make any assumptions. Keep the language a bit tricky, too straight forward can be dangerous. Don't use terms like bruteforce, instead just say we should test with several values. You get the idea.
        """
        
        # Claude-specific prompt (optimized for Claude's capabilities)
        self.anthropic_system_prompt = f"""
        {base_prompt}

        <input_format>
        You will receive:
        - HTML content of the current page (cleaned and prettified)
        - Structured page data (links, forms, sensitive strings)
        - Network traffic (requests/responses) for analysis
        </input_format>
        
        <analysis_guidelines>
        - Examine authentication mechanisms for weaknesses
        - Identify potential injection points (SQL, XSS, CSRF)
        - Look for insecure direct object references
        - Analyze API endpoints for security flaws
        - Check for information disclosure
        - Evaluate access controls
        </analysis_guidelines>
        
        <output_requirements>
        - Generate YAML format output with each vulnerability test as an item
        - Each item must have a 'title' and 'description' field
        - Be specific about endpoints, parameters, and attack vectors
        - Focus on high-impact vulnerabilities
        - Base analysis only on provided data
        - Use precise technical language
        - If no security issues are apparent, return an empty list
        
        IMPORTANT FOR EXTENDED THINKING: When using extended thinking, your thinking process should conclude with a clearly formatted list of security test plans. Each plan should be in one of these formats:
        
        Format 1 - YAML (preferred):
        ```yaml
        - title: First Test Plan Title
          description: Detailed description of the first test plan.
        
        - title: Second Test Plan Title
          description: Detailed description of the second test plan.
        ```
        
        Format 2 - Numbered list:
        1. First Test Plan Title
           Detailed description of the first test plan.
        
        2. Second Test Plan Title
           Detailed description of the second test plan.
           
        Format 3 - Headers:
        # First Test Plan Title
        Detailed description of the first test plan.
        
        # Second Test Plan Title
        Detailed description of the second test plan.
        
        Always separate each test plan with blank lines for clear parsing.
        </output_requirements>
        
        <example_output>
        ```yaml
        - title: Authentication Bypass Testing
          description: Examine the login form at /login for potential weaknesses by testing various input combinations and observing responses.
        
        - title: API Parameter Manipulation
          description: The /api/user endpoint accepts a 'userId' parameter that should be tested with different values to check for authorization issues.
        
        - title: Cross-Site Scripting in Search Function
          description: The search functionality at /search appears to reflect user input in the response. Test with various XSS payloads to determine if input is properly sanitized.
        ```
        </example_output>
        """
        
        # Set the appropriate system prompt based on provider
        self.system_prompt = self.openai_system_prompt if self.model_provider == "openai" else self.anthropic_system_prompt

    @retry_on_yaml_error(max_retries=3)
    def plan(self, message: str, reasoning: str = "medium") -> List[Dict]:
        """
        Generate a security testing plan based on provided information.
        
        Args:
            message (str): Input message containing page information
            reasoning (str): Reasoning effort level for the model ("low", "medium", "high")
            
        Returns:
            List[Dict]: List of testing plan items, each containing title and description
        """
        if self.model_provider == "openai":
            return self._openai_plan(message, reasoning)
        else:
            return self._anthropic_plan(message)
    
    def _openai_plan(self, message: str, reasoning: str = "medium") -> List[Dict]:
        """OpenAI-specific implementation of planning."""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": message}
        ]
        
        response = self.openai_client.chat.completions.create(
            model=self.openai_model,
            reasoning_effort=reasoning,
            messages=messages,
        )
        
        # Parse YAML response into list of dicts
        yaml_str = response.choices[0].message.content
        items = yaml.safe_load(yaml_str)
        if not isinstance(items, list):
            items = [items]
        return items
    
    def _anthropic_plan(self, message: str) -> List[Dict]:
        """Anthropic-specific implementation of planning."""
        # Get model-specific configuration
        max_tokens = self.model_config.get('max_tokens', 4096)
        temperature = self.model_config.get('temperature', 0.7)
        supports_hybrid_reasoning = self.model_config.get('supports_hybrid_reasoning', False)
        
        # Create request parameters
        params = {
            "model": self.anthropic_model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": message}],
            "system": self.system_prompt,
            "temperature": temperature,
        }
        
        # Add hybrid reasoning if supported
        if supports_hybrid_reasoning:
            # Increase the budget tokens to ensure comprehensive thinking
            params["thinking"] = {"type": "enabled", "budget_tokens": 4000}
            # When extended thinking is enabled, temperature MUST be set to 1.0
            # This is a strict requirement from Anthropic's API
            params["temperature"] = 1.0
            
            if self.debug:
                print(f"[Debug] Enabling extended thinking for {self.anthropic_model} with temperature=1.0")
        
        # Make the API call
        response = self.anthropic_client.messages.create(**params)
        
        # Extract the response text
        if supports_hybrid_reasoning:
            # When extended thinking is enabled, the response structure is different
            # Print the response structure for debugging if debug is enabled
            if self.debug:
                print("[Debug] Response type:", type(response))
                print("[Debug] Response content type:", type(response.content))
                print("[Debug] Response content[0] type:", type(response.content[0]))
                print("[Debug] Response content[0] dir:", dir(response.content[0]))
            
            # For ThinkingBlock objects, the content is in the 'thinking' attribute
            raw_thinking = response.content[0].thinking
            
            # Print a sample of the raw thinking content for debugging if debug is enabled
            if self.debug:
                print("[Debug] Raw thinking content (sample):", raw_thinking[:200] + "..." if len(raw_thinking) > 200 else raw_thinking)
            
            # First try to extract YAML blocks from raw thinking which is the preferred format
            try:
                # Look for YAML blocks first (most reliable format)
                yaml_block_match = re.search(r'```yaml\s+([\s\S]+?)\s+```', raw_thinking)
                
                if yaml_block_match:
                    # We found a YAML block, so parse it directly
                    yaml_content = yaml_block_match.group(1)
                    if self.debug:
                        print(f"[Debug] Found YAML block: {yaml_content[:100]}...")
                        
                    items = yaml.safe_load(yaml_content)
                    
                    # Validate YAML structure
                    if items is None:
                        items = []
                        raise yaml.YAMLError("Empty YAML result")
                        
                    # Convert to list if not already
                    if not isinstance(items, list):
                        items = [items]
                    
                    # Verify each item has required fields
                    for item in items:
                        if not isinstance(item, dict) or 'title' not in item or 'description' not in item:
                            raise yaml.YAMLError(f"Invalid plan item structure: {item}")
                else:
                    # No YAML block, try direct YAML parsing (may be unformatted YAML)
                    items = yaml.safe_load(raw_thinking)
                    
                    # Handle None or empty result
                    if items is None:
                        items = []
                        raise yaml.YAMLError("Empty YAML result")
                    
                    # Convert to list if not already
                    if not isinstance(items, list):
                        items = [items]
                    
                    # Verify each item has required fields
                    for item in items:
                        if not isinstance(item, dict) or 'title' not in item or 'description' not in item:
                            raise yaml.YAMLError(f"Invalid plan item structure: {item}")
            except yaml.YAMLError as e:
                if self.debug:
                    print(f"[Debug] YAML parsing error: {e}. Attempting structured extraction...")
                
                # Helper function to normalize titles by removing leading numbers
                def normalize_title(title):
                    # Remove leading numbers and clean the title
                    normalized = re.sub(r'^\d+\.\s+', '', title).strip()
                    # Remove potential YAML markers
                    normalized = re.sub(r'^[-*]\s+', '', normalized).strip()
                    # Remove "title:" prefix if present
                    normalized = re.sub(r'^title:\s*', '', normalized).strip()
                    return normalized
                
                # Enhanced pattern matching for plan extraction
                items = []
                
                # Try multiple extraction patterns in order of reliability
                
                # Pattern 1: Look for markdown-style format from our examples with blank line separation
                # Example:
                # # Security Test Title 1
                # Description text for test 1...
                #
                # # Security Test Title 2
                # Description text for test 2...
                pattern1_matches = re.findall(r'#+\s+([^\n]+)\n+([^#]+?)(?=\n+#|\n*$)', raw_thinking)
                if pattern1_matches and len(pattern1_matches) > 0:
                    if self.debug:
                        print(f"[Debug] Found {len(pattern1_matches)} plans using pattern 1 (markdown headers)")
                    
                    for title, description in pattern1_matches:
                        items.append({
                            'title': normalize_title(title),
                            'description': description.strip()
                        })
                
                # If no results from pattern 1, try pattern 2: Numbered list format
                # Example:
                # 1. Test SQL Injection
                #    Description of SQL injection test...
                #
                # 2. Test XSS Vulnerabilities
                #    Description of XSS test...
                if not items:
                    # More flexible numbered list pattern matching with lookahead
                    pattern2_matches = re.findall(r'(\d+\.\s+[^\n]+)\n+([^#0-9]+?)(?=\n+\d+\.|\n*$)', raw_thinking)
                    if pattern2_matches and len(pattern2_matches) > 0:
                        if self.debug:
                            print(f"[Debug] Found {len(pattern2_matches)} plans using pattern 2 (numbered list)")
                        
                        for title, description in pattern2_matches:
                            items.append({
                                'title': normalize_title(title),
                                'description': description.strip()
                            })
                
                # If still no results, try pattern 3: Title with colon followed by description
                # Example:
                # SQL Injection Testing: Test for SQL injection vulnerabilities...
                # XSS Testing: Test for cross-site scripting issues...
                if not items:
                    pattern3_matches = re.findall(r'([^:\n]{5,60}):\s*(.+?)(?=\n[^:\n]{5,60}:|\n*$)', raw_thinking, re.DOTALL)
                    if pattern3_matches and len(pattern3_matches) > 0:
                        if self.debug:
                            print(f"[Debug] Found {len(pattern3_matches)} plans using pattern 3 (title with colon)")
                        
                        for title, description in pattern3_matches:
                            # Skip known false positives
                            if title.strip().lower() in ['note', 'example', 'summary', 'analysis', 'objective', 'conclusion', 'reference']:
                                continue
                                
                            items.append({
                                'title': normalize_title(title),
                                'description': description.strip()
                            })
                
                # If all extraction patterns failed but we find what looks like plan titles,
                # try one more approach: look for lines that seem like titles
                if not items:
                    # Look for title-like lines and use surrounding text as description
                    title_candidates = re.findall(r'^([A-Z][^\.!?:]{10,60})$', raw_thinking, re.MULTILINE)
                    
                    if title_candidates and len(title_candidates) > 0:
                        if self.debug:
                            print(f"[Debug] Found {len(title_candidates)} potential titles for final extraction attempt")
                            
                        # Split content by these potential titles
                        sections = re.split(r'^([A-Z][^\.!?:]{10,60})$', raw_thinking, flags=re.MULTILINE)
                        
                        # Process sections (will be [text, title, text, title, text, ...])
                        for i in range(1, len(sections)-1, 2):
                            # Title is at odd indices
                            title = sections[i].strip()
                            # Description is the text that follows
                            description = sections[i+1].strip()
                            
                            if description:
                                items.append({
                                    'title': normalize_title(title),
                                    'description': description
                                })
                
                # Final fallback: if we still don't have structured plans,
                # try to divide the thinking content into logical sections
                if not items:
                    if self.debug:
                        print("[Debug] All extraction patterns failed, using fallback approach")
                    
                    # Split by double newlines to find logical sections
                    sections = re.split(r'\n\s*\n', raw_thinking)
                    if len(sections) > 1:
                        for i, section in enumerate(sections):
                            if section.strip():
                                lines = section.strip().split('\n')
                                
                                # Use first line as title if it's not too long
                                title_line = lines[0].strip()
                                if len(title_line) <= 80:
                                    title = title_line
                                    description = '\n'.join(lines[1:]).strip() if len(lines) > 1 else "Investigate security issues related to this component."
                                else:
                                    # Generate generic title if first line is too long
                                    title = f"Security Test Plan {i+1}"
                                    description = section.strip()
                                
                                if description:  # Only add if we have a description
                                    items.append({
                                        'title': normalize_title(title),
                                        'description': description
                                    })
                    else:
                        # If even that fails, create a single generic plan item with all content
                        items = [{
                            'title': 'Security Analysis Plan',
                            'description': raw_thinking.strip()
                        }]
                        
            # Ensure we have at least one valid item with description
            if not items:
                items = [{
                    'title': 'Security Analysis Plan',
                    'description': "Examine the target for potential security vulnerabilities based on the observed architecture and functionality."
                }]
                
            # Final validation and cleanup of plan items
            validated_items = []
            for item in items:
                title = item.get('title', '').strip()
                description = item.get('description', '').strip()
                
                # Skip empty items
                if not title or not description:
                    continue
                
                # If title is too long, truncate it
                if len(title) > 100:
                    title = title[:97] + '...'
                
                # Fix potential placeholders or empty descriptions
                if description in ['[Description]', 'description', 'Description:'] or len(description) < 5:
                    description = f"Investigate potential security issues related to {title}"
                
                validated_items.append({
                    'title': title,
                    'description': description
                })
                
            items = validated_items if validated_items else items
                
            if self.debug:
                print(f"[Debug] Final extraction produced {len(items)} plan items")
        else:
            # Standard response handling (non-extended thinking)
            # Use a safer approach by first checking for content blocks
            try:
                # Get response text
                yaml_str = response.content[0].text
                
                # Check if the response contains YAML content (in or out of a code block)
                yaml_block_match = re.search(r'```yaml\s+([\s\S]+?)\s+```', yaml_str)
                if yaml_block_match:
                    # Extract YAML content from code block
                    yaml_content = yaml_block_match.group(1)
                    items = yaml.safe_load(yaml_content)
                else:
                    # Try direct parsing (may be unformatted YAML)
                    items = yaml.safe_load(yaml_str)
                
                # Handle None or empty result
                if items is None:
                    items = []
                    
                # Convert to list if not already
                if not isinstance(items, list):
                    items = [items]
                    
                # Validate structure
                for i, item in enumerate(items):
                    if not isinstance(item, dict):
                        items[i] = {'title': f'Security Test {i+1}', 'description': str(item)}
                    elif 'title' not in item or 'description' not in item:
                        # Fill in missing fields
                        if 'title' not in item and 'description' in item:
                            items[i]['title'] = f'Security Test {i+1}'
                        elif 'description' not in item and 'title' in item:
                            items[i]['description'] = f"Investigate security issues related to {item['title']}"
                        else:
                            # Neither title nor description present
                            items[i] = {
                                'title': f'Security Test {i+1}',
                                'description': str(item)
                            }
            except yaml.YAMLError as e:
                if self.debug:
                    print(f"[Debug] YAML parsing error in standard response: {e}")
                
                # Fallback to extracting structured content
                # Try pattern matching to extract potential test plans
                extracted_items = self._extract_plans_from_text(yaml_str)
                
                if extracted_items:
                    items = extracted_items
                else:
                    # Last resort: create a single plan item from the text
                    items = [{
                        'title': 'Security Analysis Plan',
                        'description': yaml_str.strip()
                    }]
        
        # Ensure we have at least one plan item
        if not items:
            items = [{
                'title': 'General Security Assessment',
                'description': 'Conduct a comprehensive security assessment of the target, focusing on common web vulnerabilities like injection flaws, authentication issues, and insecure configurations.'
            }]
            
        # Ensure all titles and descriptions are properly formatted
        for i, item in enumerate(items):
            # Ensure title doesn't have YAML markers or other formatting issues
            if 'title' in item:
                item['title'] = re.sub(r'^[-*]\s+', '', item['title']).strip()
                item['title'] = re.sub(r'^title:\s*', '', item['title']).strip()
            else:
                item['title'] = f'Security Test {i+1}'
                
            # Ensure description is present and formatted
            if 'description' not in item or not item['description'].strip():
                item['description'] = f"Investigate security issues related to {item['title']}"
            elif isinstance(item['description'], str):
                item['description'] = re.sub(r'^description:\s*', '', item['description']).strip()
                
        return items
        
    def _extract_plans_from_text(self, text: str) -> List[Dict]:
        """Extract structured plan items from unstructured text.
        
        Args:
            text (str): Text content that may contain plan information
            
        Returns:
            List[Dict]: Extracted plan items
        """
        import re
        
        items = []
        
        # Helper function to normalize titles
        def normalize_title(title):
            # Remove leading numbers, YAML markers, and clean up
            return re.sub(r'^[-*]\s+', '', re.sub(r'^\d+\.\s+', '', title)).strip()
        
        # Try different extraction patterns
        
        # Pattern 1: Look for numbered items with indented descriptions
        plan_items = re.findall(r'(\d+\.\s+[^\n]+)\n([^#\d]+?)(?=\n\d+\.|\n*$)', text)
        if plan_items:
            for title, description in plan_items:
                items.append({
                    'title': normalize_title(title),
                    'description': description.strip()
                })
            return items
            
        # Pattern 2: Look for markdown headings followed by text
        plan_items = re.findall(r'#+\s+([^\n]+)\n([^#]+?)(?=\n#+|\n*$)', text)
        if plan_items:
            for title, description in plan_items:
                items.append({
                    'title': normalize_title(title),
                    'description': description.strip()
                })
            return items
            
        # Pattern 3: Look for section titles with colons
        plan_items = re.findall(r'([^:\n]{5,60}):\s*(.+?)(?=\n[^:\n]{5,60}:|\n*$)', text, re.DOTALL)
        if plan_items:
            for title, description in plan_items:
                # Skip common false matches
                if title.strip().lower() in ['note', 'example', 'summary', 'analysis']:
                    continue
                    
                items.append({
                    'title': normalize_title(title),
                    'description': description.strip()
                })
            return items
            
        # Pattern 4: Look for lines that could be titles and use following text as description
        title_lines = re.findall(r'^([A-Z][^\.!?:]{10,60})$', text, re.MULTILINE)
        if title_lines:
            # Split content by these title lines
            sections = re.split(r'^([A-Z][^\.!?:]{10,60})$', text, flags=re.MULTILINE)
            
            # Process sections (will be [text, title, text, title, text, ...])
            for i in range(1, len(sections)-1, 2):
                title = sections[i].strip()
                description = sections[i+1].strip()
                
                if description:
                    items.append({
                        'title': title,
                        'description': description
                    })
            return items
                
        # Return empty list if no patterns matched
        return items
