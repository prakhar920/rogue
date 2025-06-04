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
    
    def __init__(self):
        """Initialize the Planner with OpenAI client and system prompt."""
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        
        self.system_prompt = f"""
        You are an expert bug bounty hunter with years of experience finding critical vulnerabilities in web applications. Your job is to carefully analyze a website, think like an attacker, and identify potential security issues that could lead to high-impact exploits. You will be provided details about our internal company that we're testing, so think creatively about how the application could be abused.

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
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": message}
        ]
        
        response = self.client.chat.completions.create(
            model="o3-mini",
            reasoning_effort=reasoning,
            messages=messages,
        )
        
        # Parse YAML response into list of dicts
        yaml_str = response.choices[0].message.content
        items = yaml.safe_load(yaml_str)
        if not isinstance(items, list):
            items = [items]
        return items
