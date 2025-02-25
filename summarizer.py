from llm import LLM


class Summarizer:
    def __init__(self):
        self.llm = LLM()

    def summarize(self, llm_response, tool_use, tool_output):
        prompt = f"""
        You are a summarizer agent. Your job is to analyze and summarize the following information:

        1. LLM Agent Response: This is what the agent was trying to do
        {llm_response}

        2. Tool Use: This is the actual command that was executed
        {tool_use}

        3. Tool Output: This is what we got back from executing the command
        {tool_output[:100000]}

        Please provide a concise one-paragraph summary that explains:
        - What the agent was attempting to do
        - What command was actually executed
        - What the result was and if it was successful

        If the tool output is less than 200 words, you can return it as-is.
        If it's longer than 200 words, summarize it while preserving key information and technical details.

        Focus on security-relevant details and any potential findings or issues discovered.

        The summary should be 2 sentences at min, 4 at max. Keep specific/technical details in the summary. If not needed, don't make it long. Succint and to the point.
        """
        return self.llm.output(prompt)

    def summarize_conversation(self, conversation):
        # Convert conversation list to string format
        conversation_str = "\n".join([f"{msg['role']}: {msg['content']}" for msg in conversation])
        
        prompt = f"""
        You are a summarizer agent. Your job is to summarize the following conversation:

        {conversation_str}

        Please provide a bullet point summary that includes:
        - What security tests were attempted
        - What specific commands/payloads were used
        - What the results of each test were
        - Any potential security findings discovered

        Keep the summary focused on technical details and actual actions taken. Each bullet point should be 1-2 sentences max. Keep the overall summary short.
        """

        output = self.llm.output(prompt)
        output = "To reduce context, here is a summary of the previous part of the conversation:\n" + output
        return [{"role": "user", "content": output}]

    def summarize_page_source(self, page_source, url):
        prompt = f"""
        You are a summarizer agent. Your job is to analyze and summarize the following page source from URL: {url}

        {page_source[:200000]}

        Please provide a structured summary with the following sections:

        1. Page Overview
        - Brief 2-3 sentence description of what this page does/contains
        - Main functionality and purpose

        2. Important Interactive Elements
        - Links: List key links with their text, and their href
        - Forms: List forms with their purpose and CSS selectors for the form and key inputs
        - Buttons: List important buttons with their purpose and CSS selectors
        - Input fields: List important input fields with their purpose and CSS selectors

        3. Dynamic Elements
        - List any AJAX endpoints or API calls found
        - Note any JavaScript event handlers or dynamic content loading
        - Identify any state changes or dynamic updates

        4. Security-Relevant Items
        - Authentication/authorization elements
        - File upload capabilities
        - API endpoints
        - Form submissions
        - User input fields

        For each element, provide:
        1. A brief description of its purpose/functionality
        2. The exact CSS selector to target it
        3. Any relevant attributes or properties

        Keep the summary focused and technical. Prioritize elements that are security-relevant or core to the page's functionality.
        """
        return self.llm.output(prompt)
