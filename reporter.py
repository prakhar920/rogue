
import json
import traceback # Import traceback for better error logging
from llm import LLM # Make sure correct LLM class is imported
from pathlib import Path

class Reporter:
    """
    Analyzes findings using an LLM instance and generates reports.
    """

    # --- THIS IS THE FIX ---
    # Change __init__ to accept llm_instance and output_dir
    def __init__(self, starting_url: str, llm_instance: LLM, output_dir: str = 'security_results'):
        """
        Initialize the reporter.

        Args:
            starting_url: Base URL that was tested.
            llm_instance: An initialized instance of the LLM class (passed from Agent).
            output_dir: The directory to save reports in.
        """
        if not isinstance(llm_instance, LLM):
             # Make this error more informative
             raise TypeError(f"Reporter initialization failed: Expected an LLM instance, but got {type(llm_instance)}.")

        self.llm = llm_instance # Use the LLM instance passed from the Agent
        self.reports = [] # Stores validated reports for the current scan session
        self.starting_url = starting_url
        self.output_dir = Path(output_dir)

        # Sanitize the URL to create a valid filename, robustly
        safe_filename = str(self.starting_url)
        # Replace protocol first
        safe_filename = safe_filename.replace("https://", "").replace("http://", "")
        # Replace common problematic characters found in URLs with underscores
        for char in ['/', ':', '?', '=', '&', '#', '%', '\\', '*', '"', '<', '>', '|', ' ']: # Added space
             safe_filename = safe_filename.replace(char, "_")
        # Replace multiple underscores with single one and remove leading/trailing
        safe_filename = "_".join(filter(None, safe_filename.split('_')))
        self.filename_base = safe_filename.strip('_')[:150] # Limit length

        # Ensure the output directory exists
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            print(f"[Info] Reporter using output directory: {self.output_dir.resolve()}")
        except Exception as e:
             print(f"[Error] Reporter could not create output directory {self.output_dir}: {e}. Using current directory.")
             self.output_dir = Path(".") # Fallback to current directory
    # --- END FIX ---


    def report(self, history: list) -> tuple[bool, str]:
        """
        Analyze conversation history using the LLM judge to validate if a real vulnerability was found.
        Returns (bool: success, str: analysis_report from judge)
        """
        if not isinstance(history, list):
            print("[Error] Reporter.report() received invalid history format (expected list).")
            return False, "[Error] Invalid history format provided to Reporter."

        # Define the strict judging prompt
        system_prompt_judge = """
        You are an extremely strict security vulnerability judge. Analyze the provided conversation history between a security agent and a target system. Determine if a REAL, HIGH-IMPACT, WORKING exploit was definitively PROVEN based ONLY on the evidence within this history.

        **VALID EXPLOIT CRITERIA (ALL MUST BE MET):**
        1.  **Clear Attack Vector:** What specific input, parameter, or action was manipulated?
        2.  **Concrete Proof of Success:** Did the agent *actually* retrieve sensitive data (e.g., user passwords, database content - not just table names)? Did the agent *actually* execute a command or achieve unauthorized access (e.g., showing output from `id` or `whoami`, accessing an admin page)? Show the specific part of the history as evidence.
        3.  **Exact Payload/Steps:** What precise input (`<script>...`, `' OR 1=1--`) or sequence of tool actions led to the successful exploit?
        4.  **High Impact:** Is this significantly more than just an error message, verbose output (like stack traces or version numbers), missing security headers (like X-Frame-Options), theoretical possibilities ("could lead to...", "might allow..."), or self-inflicted issues (self-XSS)? Would this realistically justify a significant bug bounty payout (think >$500)?

        **IMMEDIATELY REJECT if:**
        * The finding is theoretical or potential, lacking concrete proof from the history.
        * Only error messages, unexpected behavior, or configuration information (like directory listings without file access) are shown.
        * The agent *claims* success but provides no verifiable output from the target system confirming it.
        * It's a low-severity finding (e.g., missing informational headers, self-XSS, version disclosure, clickjacking on a static page).
        * The proof relies on assumptions or external knowledge not present in the provided history.

        **OUTPUT FORMAT:**
        * **If a VALID, high-impact exploit is found:** Provide a concise report starting EXACTLY with "VALID EXPLOIT:". Include:
            * `Vulnerability:` [Type, e.g., Authenticated Remote Code Execution]
            * `Endpoint:` [Affected URL/parameter]
            * `Payload/Steps:` [Exact input/actions]
            * `Evidence:` [Quote or describe the specific output from the history proving success]
            * `Impact:` [Briefly state the consequence, e.g., Gained shell access as www-data]
        * **If NO VALID, high-impact exploit is found:** Start EXACTLY with "NO VALID EXPLOIT:". State clearly why it was rejected based on the criteria (e.g., "Lacked concrete proof of data retrieval," "Only showed a generic error message," "Low severity finding - missing header").
        """

        # Prepare messages for the judge LLM call
        messages_judge = [{"role": "system", "content": system_prompt_judge}]
        # Add history, ensuring it's not excessively long (optional truncation might be needed)
        messages_judge.extend(history[-self.llm.keep_messages:] if hasattr(self.llm, 'keep_messages') else history) # Limit history if needed
        messages_judge.append({"role": "user", "content": "Analyze the preceding conversation history strictly based on the criteria. Was a high-impact exploit proven? Start your response with 'VALID EXPLOIT:' or 'NO VALID EXPLOIT:'."})

        successful_exploit = False # Default to False
        analysis_report = "[Error] Analysis not performed." # Default report

        try:
            # print("[Debug] Reporter calling LLM judge...") # Optional debug
            analysis_report = self.llm.reason(messages_judge)
            # print(f"[Debug] Reporter received judge analysis: {analysis_report[:150]}...") # Optional debug

            # Check if the reason() method itself returned an error
            if analysis_report.startswith("[Error]"):
                 print(f"[Error] Reporter received error directly from LLM during validation: {analysis_report}")
                 # successful_exploit remains False

            # --- PARSE THE JUDGE'S DECISION ---
            # Check if the judge's report explicitly starts with "VALID EXPLOIT:"
            elif analysis_report.strip().startswith("VALID EXPLOIT:"):
                 successful_exploit = True
                 print(f"[Info] Reporter JUDGE VALIDATED an exploit: {analysis_report[:100]}...")
                 self.reports.append(analysis_report) # Add the detailed judge report
                 self.save_reports() # Save immediately after validation
            else:
                 # Assume any other response means no valid exploit was found
                 successful_exploit = False
                 print(f"[Info] Reporter judge DID NOT validate exploit: {analysis_report[:100]}...") # Log rejection reason

        except Exception as e:
            # Catch errors during the LLM call or processing
            print(f"[Error] Reporter failed during report analysis: {e}")
            traceback.print_exc() # Print full traceback for debugging
            successful_exploit = False
            analysis_report = f"[Error] Reporter encountered an exception during analysis: {e}"

        # Return the boolean success status and the full analysis text from the judge
        return successful_exploit, analysis_report


    # Remove the separate parse_report function as parsing is now integrated above


    def save_reports(self):
        """Save all successful vulnerability reports found SO FAR to a text file."""
        if not self.reports: # Don't save if there are no reports yet
            # print("[Debug] No validated reports to save yet.") # Optional debug
            return

        report_path = self.output_dir / f"{self.filename_base}.txt"
        try:
            # Write all collected VALIDATED reports (overwrites previous file for this run)
            with open(report_path, "w", encoding='utf-8') as f:
                f.write("\n\n------ VULNERABILITY REPORT ------\n\n".join(self.reports))
            print(f"[Info] Saved {len(self.reports)} validated report(s) to: {report_path}")
        except Exception as e:
            print(f"[Error] Failed to save report file {report_path}: {e}")


    def generate_summary_report(self):
        """
        Generate a comprehensive markdown summary based on the collected validated reports.
        This should be called ONCE at the end of the entire scan.
        """
        print("[Info] Attempting to generate final summary report...")
        # Use the reports collected in self.reports during the scan
        if not self.reports:
            report_content = "No validated vulnerabilities were found or reported during this scan session."
            print("[Info] No validated reports collected during this session to summarize.")
        else:
            # Combine all validated reports for the summary LLM
            report_content = "\n\n------ VULNERABILITY REPORT ------\n\n".join(self.reports)
            print(f"[Info] Summarizing {len(self.reports)} validated report(s).")


        system_prompt_summarizer = """
        You are a security report summarizer. You will be given a block of text containing one or more previously validated vulnerability reports. Create a single, comprehensive, professional markdown summary document.

        **Structure:**
        1.  **Executive Summary:** Briefly state the overall security posture based on the findings (e.g., "Critical vulnerabilities found," "No high-impact issues identified"). Mention the number of validated findings.
        2.  **Table of Contents (Optional):** If multiple vulnerabilities are present, list them with links (e.g., `[SQL Injection](#sql-injection)`).
        3.  **Detailed Findings:** For EACH validated vulnerability reported in the input:
            * Create a clear heading (e.g., `## SQL Injection Authentication Bypass`). Use the vulnerability type from the input report for the heading ID (e.g., `{#sql-injection-authentication-bypass}`).
            * **Severity:** Estimate (e.g., Critical, High, Medium, Low) based on the impact described.
            * **Endpoint/Component:** Extract from the input report.
            * **Description:** Briefly explain the vulnerability based on the input report.
            * **Payload/Steps:** Extract the exact payload or steps from the input report and place them in a markdown code block (```).
            * **Evidence:** Briefly summarize or quote the evidence from the input report.
            * **Impact:** Extract or infer the potential impact from the input report.
            * **Recommendation:** Provide a general recommendation (e.g., "Implement parameterized queries," "Validate user input," "Apply proper access controls").

        **Important:**
        * Only include information from the VALIDATED reports provided in the input.
        * If the input states "No validated vulnerabilities...", reflect that accurately in the executive summary and omit the detailed findings section.
        * Use clear markdown formatting (headings, code blocks, bullet points).
        * Be concise and professional.
        """

        messages_summarizer = [
            {"role": "system", "content": system_prompt_summarizer},
            {"role": "user", "content": f"Please summarize the following validated vulnerability reports:\n\n{report_content}"}
        ]

        summary_content_to_write = "[Error] Summary generation failed." # Default
        try:
            summary = self.llm.reason(messages_summarizer)
            # Check if the reason() method itself returned an error
            if summary.startswith("[Error]"):
                 print(f"[Error] Summary generation failed by LLM: {summary}")
                 summary_content_to_write = f"# Report Summary Generation Failed\n\nLLM Error: {summary}"
            else:
                 summary_content_to_write = summary
                 print("[Info] Summary report content generated.")

        except Exception as e:
             print(f"[Error] Exception during summary generation LLM call: {e}")
             traceback.print_exc() # Log full traceback
             summary_content_to_write = f"# Report Summary Generation Failed\n\nException: {e}"

        # --- Save the Summary Report ---
        summary_path = self.output_dir / f"{self.filename_base}_summary.md"
        try:
            with open(summary_path, "w", encoding='utf-8') as f:
                f.write(summary_content_to_write)
            print(f"[Info] Saved final summary report to: {summary_path}")
        except Exception as e:
             print(f"[Error] Failed to save final summary report to {summary_path}: {e}")

