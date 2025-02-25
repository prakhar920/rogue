import sys
from io import StringIO
from llm import LLM


class Tools:
    """
    Collection of tools for interacting with web pages and executing code.
    Provides methods for page manipulation, JavaScript execution, and Python code evaluation.
    """

    def __init__(self):
        """Initialize Tools with LLM instance."""
        self.llm = LLM()
        
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
        page.click(css_selector)
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
        page.fill(css_selector, value)
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

    def python_interpreter(self, code: str) -> str:
        """Execute Python code and capture output.
        
        Args:
            code: Python code to execute
            
        Returns:
            Output from code execution
        """
        output_buffer = StringIO()
        old_stdout = sys.stdout
        sys.stdout = output_buffer
        
        try:
            exec(code)
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

    def execute_tool(self, page, tool_use: str):
        """Execute a tool command.
        
        Args:
            page: Playwright page object
            tool_use: Tool command to execute
            
        Returns:
            Result of tool execution or error message
        """
        try:
            return eval("self." + tool_use)
        except Exception as e:
            return f"Error executing tool: {str(e)}"

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

    def extract_tool_use(self, action: str) -> str:
        """Extract tool command from action description.
        
        Args:
            action: Description of action to take
            
        Returns:
            Tool command to execute
        """
        prompt = f"""
            You are an agent who is tasked to build a tool use output based on users plan and action. Here are the tools we can generate. You just need to generate the code, we will run it in an eval in a sandboxed environment.

            ## Tools
            You are an agent and have access to plenty of tools. In your output, you can basically select what you want to do next by selecting one of the tools below. You must strictly only use the tools listed below. Details are given next.

            - execute_js(js_code)
                We are working with python's playwright library and you have access to the page object. You can execute javascript code on the page by passing in the javascript code you want to execute. The execute_js function will simply call the page.evaluate function and get the output of your code. 
                    - Since you are given the request and the response data, if you want to fuzz the API endpoint, you can simply pass in the modified request data and replay the request. Only do this if you are already seeing requests data in some recent conversation.
                    - Remember: when running page.evaluate, we need to return some variable from the js code instead of doing console logs. Otherwise, we can't access it back in python. The backend for analysis is all python.
                    - Playwright uses async functions, just remember that. You know how its evaluate function works, so write code accordingly.
            - click(css_selector)
                If you want to click on a button or link, you can simply pass in the css selector of the element you want to click on.
            - fill(css_selector, value)
                If you want to fill in a form, you can simply pass in the css selector of the element you want to fill in and the value you want to fill in.
            - auth_needed()
                If you are on a page where authentication is needed, simply call this function. We will let the user know to manually authenticate and then we can continue.
            - get_user_input(prompt)
                If you need to get some input from the user, you can simply call this function. We will let the user know to manually input the data and then we can continue. For instance, if you are looking for a username, password, etc, just call this function and ask the user e.g get_user_input("Enter the username: ")
            - presskey(key)
                If you want to press a key, you can simply pass in the key you want to press. This is a playwright function so make sure key works.
            - submit(css_selector)
                If you want to submit a form, you can simply pass in the css selector of the element you want to submit.
            - goto(url)
                If you want to go to a different url, you can simply pass in the url you want to go to.
                If you want to go back to the previous page, you can simply call this function.
            - refresh()
                If you want to refresh the current page, you can simply call this function.
            - python_interpreter(code)
                If you want to run some python code, you can simply pass in the code you want to run. This will be run in a python interpreter and the output will be returned. For instance, if you want to create a new file, run some system commands, whatever you want, you can. We will run it with exec and give you the output so make sure to print stuff in case you need an output.
            - complete()
                If you think you have explored all possible concerns and avenues and we want to move to some other page, you can simply call this function. This will just take whatever next url we have for analysis and go to it.

            ----

            ## Inputs
            Below you are provided a plan and an action. Extract the relevant tool use from the text and only return it without any prefix, sufix, or anything else.

            ```
            {action}
            ```

            ## Output format:
            Your output must exactly be a tool use. You must pass the first argument as the page object always, and the second argument comes from the action given above. For instance:

            execute_js(page, 'fetch("/api/create-job", {{the params and what not go here}})')
            goto(page, "https://example.com")
            fill(page, "#username", "admin")
            submit(page, "#login")
            complete() # dont pass in anything
            auth_needed() # dont pass in anything

            We must not return anything else. Remember that your output is going to be eval'd in a sandboxed environment.
            Remember, no prefixes or suffixes, no ```, no ```python, no ```javascript. Start directly with the actual functions and tools that are given above. I will take care of the rest. Make sure the params to the functions are wrapped in quotes or single quotes, not in backticks. We need to respect the syntax of the language.
        """
        return self.llm.output(prompt)