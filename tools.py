# tools.py
import sys
from io import StringIO
from llm import LLM # Import LLM


class Tools:
    """
    Collection of tools for interacting with web pages and executing code.
    Provides methods for page manipulation, JavaScript execution, and Python code evaluation.
    """

    def __init__(self, llm_instance: LLM):
        """
        Initialize Tools with an existing LLM instance.
        
        Args:
            llm_instance (LLM): An initialized LLM instance from the Agent.
        """
        self.llm = llm_instance
        
    def execute_js(self, page, js_code: str) -> str:
        """Execute JavaScript code on the page.
        
        Args:
            page: Playwright page object
            js_code: JavaScript code to execute
            
        Returns:
            Result of JavaScript evaluation
        """
        return page.evaluate(js_code)

    def click(self, page, css_selector: str) -> str:
        """Click an element on the page.
        
        Args:
            page: Playwright page object
            css_selector: CSS selector for element to click
            
        Returns:
            Page HTML after click
        """
        page.click(css_selector, timeout=5000)
        return page.inner_html("html")

    def fill(self, page, css_selector: str, value: str) -> str:
        """Fill a form field.
        
        Args:
            page: Playwright page object
            css_selector: CSS selector for input field
            value: Value to fill
            
        Returns:
            Page HTML after filling
        """
        page.fill(css_selector, value, timeout=5000)
        return page.inner_html("html")

    def submit(self, page, css_selector: str) -> str:
        """Submit a form by clicking an element.
        
        Args:
            page: Playwright page object
            css_selector: CSS selector for submit element
            
        Returns:
            Page HTML after submission
        """
        page.locator(css_selector).click()
        return page.inner_html("html")

    def presskey(self, page, key: str) -> str:
        """Press a keyboard key.
        
        Args:
            page: Playwright page object
            key: Key to press
            
        Returns:
            Page HTML after key press
        """
        page.keyboard.press(key)
        return page.inner_html("html")

    def goto(self, page, url: str) -> str:
        """Navigate to a URL.
        
        Args:
            page: Playwright page object
            url: URL to navigate to
            
        Returns:
            Page HTML after navigation
        """
        page.goto(url)
        return page.inner_html("html")

    def refresh(self, page) -> str:
        """Refresh the current page.
        
        Args:
            page: Playwright page object
            
        Returns:
            Page HTML after refresh
        """
        page.reload()
        return page.inner_html("html")

    def python_interpreter(self, code: str, page=None) -> str:
        """Execute Python code and capture output.
        
        Args:
            code: Python code to execute
            page: Optional Playwright page object for browser context access
            
        Returns:
            Output from code execution
        """
        output_buffer = StringIO()
        old_stdout = sys.stdout
        sys.stdout = output_buffer
        
        # Make page and browser context available to the executed code
        exec_globals = {'page': page}
        if page:
            exec_globals.update({
                'browser_context': page.context,
                'cookies': page.context.cookies(),
                'current_url': page.url,
                'user_agent': page.evaluate('navigator.userAgent')
            })
        
        try:
            exec(code, exec_globals)
            output = output_buffer.getvalue()
            return output
        finally:
            sys.stdout = old_stdout
            output_buffer.close()

    def get_user_input(self, prompt: str) -> str:
        """Get input from user.
        
        Args:
            prompt: Prompt to display to user
            
        Returns:
            Confirmation message
        """
        input(prompt)
        return "Input done!"

    def auth_needed(self) -> str:
        """Prompt for user authentication.
        
        Returns:
            Confirmation message
        """
        input("Authentication needed. Please login and press enter to continue.")
        return "Authentication done!"

    def complete(self) -> str:
        """Mark current task as complete.
        
        Returns:
            Completion message
        """
        return "Completed"

    def execute_tool(self, page, tool_use: str):
        """Execute a tool command.
        
        Args:
            page: Playwright page object
            tool_use: Tool command to execute
            
        Returns:
            Result of tool execution or error message
        """
        try:
            # IMPORTANT: We must pass 'page' to eval's local context
            # so the tool_use string (e.g., "click(page, '#btn')") can find it.
            local_context = {'self': self, 'page': page}
            return eval(tool_use, globals(), local_context)
        except Exception as e:
            return f"Error executing tool '{tool_use}': {str(e)}"

    def extract_tool_use(self, action: str) -> str:
        """Extract tool command from action description.
        
        Args:
            action: Description of action to take
            
        Returns:
            Tool command to execute
        """
        system_prompt = f"""
            You are an agent who is tasked to build a tool use output based on users plan and action. Here are the tools we can generate. You just need to generate the code, we will run it in an eval in a sandboxed environment.

            ## Tools
            You are an agent and have access to plenty of tools. In your output, you can basically select what you want to do next by selecting one of the tools below. You must strictly only use the tools listed below. Details are given next.
            
            - execute_js(page, js_code)
            - click(page, css_selector)
            - fill(page, css_selector, value)
            - auth_needed()
            - get_user_input(prompt)
            - presskey(page, key)
            - submit(page, css_selector)
            - goto(page, url)
            - refresh(page)
            - python_interpreter(code, page=None)
            - complete()

            ----

            ## Inputs
            Below you are provided a plan and an action. Extract the relevant tool use from the text and only return it without any prefix, sufix, or anything else.

            ```
            {action}
            ```

            ## Output format:
            Your output must exactly be a tool use. 
            
            Examples:
            execute_js(page, 'fetch("/api/create-job", {{ "param": "value" }})')
            goto(page, "https://example.com")
            fill(page, "#username", "admin")
            submit(page, "#login")
            python_interpreter('import requests; print("Hello")')
            python_interpreter('print(current_url, len(cookies))', page=page)
            complete()
            auth_needed()

            We must not return anything else. Remember that your output is going to be eval'd in a sandboxed environment.
            Remember, no prefixes or suffixes, no ```, no ```python, no ```javascript. Start directly with the actual functions and tools that are given above. I will take care of the rest. Make sure the params to the functions are wrapped in quotes or single quotes, not in backticks. We need to respect the syntax of the language.
        """
        
        # FIX: Format as messages and use reason()
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": action} # Pass the action as the user message
        ]
        return self.llm.reason(messages)