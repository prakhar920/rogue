# agent.py
import os
import traceback # Import traceback for better error logging
from logger import Logger
from proxy import WebProxy
from llm import LLM
from scanner import Scanner
from planner import Planner
from tools import Tools
from summarizer import Summarizer
from utils import check_hostname, enumerate_subdomains, wait_for_network_idle, count_tokens
from reporter import Reporter # Ensure reporter is imported
import copy # Import copy for deepcopy

logger = Logger()

class Agent:
    """
    AI-powered security testing agent that scans web applications for vulnerabilities.
    Orchestrates scanning, planning, execution, and reporting.
    """

    def __init__(self, starting_url: str, expand_scope: bool = False,
                 enumerate_subdomains: bool = False, model: str = 'o4-mini',
                 output_dir: str = 'security_results', max_iterations: int = 25,
                 num_plans: int = 1, disable_rag: bool = False,
                 enable_baseline_checks: bool = True, max_plans: int = None,
                 disable_iterative: bool = False, additional_instructions: str = ''):
        """
        Initialize the security testing agent and its components.
        Raises RuntimeError if critical components (LLM, Planner, Reporter) fail to initialize.
        """
        self.starting_url = starting_url
        self.expand_scope = expand_scope
        self.should_enumerate_subdomains = enumerate_subdomains
        self.model = model
        self.output_dir = output_dir
        self.max_iterations = max_iterations
        self.num_plans_requested = num_plans # Store the requested number (-1 for unlimited)
        self.disable_iterative = disable_iterative
        self.additional_instructions = additional_instructions
        self.keep_messages = 15 # Max messages in plan history before potential summary

        knowledge_summary = None  # Placeholder for RAG feature
        if not disable_rag:
            print("[Info] 🧠 RAG feature currently disabled. Would initialize here.")
        else:
             print("[Info] 🚫 RAG knowledge fetching explicitly disabled.")

        # --- Initialize LLM (CRITICAL) ---
        # llm.py now handles DEMO_MODE checks during its initialization
        try:
            # Pass the selected model name from args
            self.llm = LLM(model=self.model, knowledge_content=knowledge_summary)
            # Add keep_messages to LLM instance if not already there (it is in the provided llm.py)
            if not hasattr(self.llm, 'keep_messages'):
                 self.llm.keep_messages = self.keep_messages
            print("[Info] LLM component initialized.")
        except Exception as e:
             # Make LLM initialization failure fatal for the Agent
             error_msg = f"Agent cannot start: LLM initialization failed - {e}"
             print(f"[Error] CRITICAL: {error_msg}")
             traceback.print_exc()
             raise RuntimeError(error_msg) # Re-raise to stop execution

        # --- Initialize Planner (CRITICAL) ---
        try:
            self.planner = Planner(
                llm_instance=self.llm, # Pass the initialized LLM
                knowledge_summary=knowledge_summary,
                enable_baseline_checks=enable_baseline_checks,
                max_plans=max_plans, # Pass max_plans correctly
                num_plans_target=self.num_plans_requested, # Pass requested plans (-1 for unlimited)
                additional_instructions=additional_instructions
            )
            print("[Info] Planner component initialized.")
        except Exception as e:
            error_msg = f"Agent cannot start: Planner initialization failed - {e}"
            print(f"[Error] CRITICAL: {error_msg}")
            traceback.print_exc()
            raise RuntimeError(error_msg)

        # --- Initialize Other Components ---
        self.proxy = WebProxy(starting_url, logger)
        self.scanner = None # Initialized later in run() after browser page is ready
        
        # --- FIX: Pass the initialized LLM instance to Tools ---
        self.tools = Tools(llm_instance=self.llm) 
        # history is reset per URL in run()

        # --- FINAL REPORTER INITIALIZATION FIX (CRITICAL) ---
        # Ensure Reporter gets the correct llm_instance and output_dir
        try:
            self.reporter = Reporter(
                starting_url=self.starting_url,
                llm_instance=self.llm, # Pass the SAME LLM instance created above
                output_dir=self.output_dir
            )
            print("[Info] Reporter component initialized successfully.")
        except Exception as e:
            error_msg = f"Agent cannot start: Reporter initialization failed - {e}"
            print(f"[Error] CRITICAL: {error_msg}")
            traceback.print_exc()
            raise RuntimeError(error_msg)
        # --- END FINAL REPORTER FIX ---


    def run(self):
        """
        Execute the main security scan loop.
        Handles browser setup/teardown, URL iteration, planning, execution, and reporting.
        """
        playwright = None # Define for finally block
        browser = None # Define for finally block
        page = None # Define for finally block

        try:
            logger.info("Setting up browser and proxy...", color='yellow')
            # Assuming create_proxy returns these values and handles potential errors
            browser, context, page, playwright = self.proxy.create_proxy()
            if not page:
                 raise RuntimeError("Failed to create Playwright page. Cannot continue scan.")

            urls_to_parse = [self.starting_url] # Queue of URLs to visit
            scanned_urls = set() # Set to track URLs already processed to prevent loops

            # --- Subdomain Enumeration (if enabled) ---
            if self.should_enumerate_subdomains:
                logger.info("Enumerating subdomains (this might take a minute)...", color='yellow')
                try:
                    subdomains = enumerate_subdomains(self.starting_url)
                    # Add unique subdomains that haven't been queued or scanned yet
                    new_subs = [s for s in subdomains if s not in urls_to_parse and s not in scanned_urls]
                    if new_subs:
                        urls_to_parse.extend(new_subs)
                        logger.info(f"Added {len(new_subs)} unique subdomains to the scan queue.", color='green')
                except Exception as e:
                    logger.warning(f"Subdomain enumeration failed: {e}") # Non-fatal

            # --- Initialize Scanner ---
            self.scanner = Scanner(page) # Scanner needs the page object
            logger.info("Scanner initialized.", color='green')

            # --- Main URL Processing Loop ---
            while urls_to_parse:
                current_url = urls_to_parse.pop(0) # Get the next URL
                if current_url in scanned_urls:
                     logger.info(f"Skipping already processed URL: {current_url}", color='dim')
                     continue # Avoid redundant work

                logger.info(f"--- Starting analysis for URL: {current_url} ---", color='blue')

                # --- Scan Current URL ---
                try:
                    # Navigate and scan the page content
                    scan_results = self.scanner.scan(current_url)
                    scanned_urls.add(current_url) # Mark as scanned *after* successful scan
                    logger.info(f"Initial page scan completed for {current_url}.", color='green')
                except Exception as e:
                    logger.error(f"Failed to scan page {current_url}: {type(e).__name__} - {e}")
                    # Log traceback for detailed debugging if needed
                    # traceback.print_exc()
                    continue # Skip to the next URL if scanning this one failed

                # --- Scope Expansion (add newly found URLs) ---
                if self.expand_scope:
                    found_links = scan_results.get("parsed_data", {}).get("urls", [])
                    new_urls_added_count = 0
                    for link_info in found_links:
                         link_href = link_info.get("href")
                         # Basic validation: check it's http/https, in scope, and not already processed/queued
                         if link_href and link_href.startswith(('http://', 'https://')) and check_hostname(self.starting_url, link_href):
                             absolute_link = link_href # Assuming links are absolute; add urljoin if needed
                             if absolute_link not in urls_to_parse and absolute_link not in scanned_urls:
                                 urls_to_parse.append(absolute_link)
                                 new_urls_added_count += 1
                    if new_urls_added_count > 0:
                         logger.info(f"Added {new_urls_added_count} newly discovered in-scope URLs to queue.", color='green')

                # --- Prepare Page Context for LLM Planning ---
                page_source = scan_results.get("html_content", "")
                if not page_source:
                     logger.warning(f"No HTML content retrieved for {current_url}. Skipping LLM planning/execution for this URL.")
                     continue # Cannot proceed without page content

                # --- FIX: Initialize Summarizer with the LLM instance ---
                summarizer_instance = Summarizer(llm_instance=self.llm)
                page_summary = summarizer_instance.summarize_page_source(page_source, current_url)
                
                # Format context clearly for the LLM
                page_data_for_llm = f"**Page Analysis Summary:**\n{page_summary}\n\n**Raw HTML (Partial):**\n{page_source[:5000]}..."
                
                # --- Execute Security Test Plan(s) for this URL ---
                self.execute_plan(page, current_url, page_data_for_llm)

                logger.info(f"--- Finished analysis for URL: {current_url} ---", color='blue')

            # --- End of all URL processing ---
            logger.info("All URLs processed. Generating final summary report...", color='green')
            # Generate the final summary report *once* after all URLs are done
            self.reporter.generate_summary_report()
            logger.info("Scan complete.", color='green')

        except Exception as e:
            logger.error(f"An unexpected error occurred during the scan: {e}")
            traceback.print_exc()
        finally:
            # --- Graceful Shutdown ---
            if page:
                 try:
                     page.close()
                 except Exception as e:
                     logger.warning(f"Error closing page: {e}")
            if browser:
                 try:
                     browser.close()
                 except Exception as e:
                     logger.warning(f"Error closing browser: {e}")
            if playwright:
                 try:
                     playwright.stop()
                 except Exception as e:
                     logger.warning(f"Error stopping Playwright: {e}")
            logger.info("Browser and proxy shut down.", color='yellow')


    def execute_plan(self, page, url: str, page_data: str):
        """
        Generates and executes security testing plans for a single URL.
        Manages planning, tool execution, and reporting for the given page context.
        """
        logger.info(f"Generating security test plans for {url}...", color='yellow')
        # This history will be unique for this URL's planning/execution phase
        url_master_history = [] 

        try:
            # --- Generate Test Plans ---
            # self.planner.plan_batch() is assumed to be the correct method name based on planner.py
            # Use num_plans_requested for the batch size
            batch_size = self.num_plans_requested if self.num_plans_requested != -1 else 5 # Request 5 if unlimited, to start
            test_plans = self.planner.plan_batch(page_data, batch_size=batch_size)
            
            if not test_plans:
                 logger.warning(f"No test plans generated by LLM for {url}. Skipping execution.")
                 return
            
            logger.info(f"Generated {len(test_plans)} test plans for {url}.", color='green')

            # --- Execute Each Plan Iteratively ---
            for i, plan in enumerate(test_plans):
                plan_title = plan.get('title', f'Plan {i+1}')
                plan_desc = plan.get('description', 'No description.')
                logger.info(f"--- Executing Plan: '{plan_title}' ---", color='magenta')
                
                # Use a deepcopy of the master history for this specific plan's execution
                # This isolates the plan's history for the judge
                current_plan_history = copy.deepcopy(url_master_history)
                
                # Add the initial context and the new plan to this plan's history
                current_plan_history.append({"role": "user", "content": f"**New Page Context:**\n{page_data}"})
                current_plan_history.append({"role": "assistant", "content": f"**Plan:** {plan_title}\n**Methodology:** {plan_desc}"})
                
                is_complete = False
                
                for iteration in range(self.max_iterations):
                    if is_complete:
                         logger.info(f"Plan '{plan_title}' marked complete by agent.", color='green')
                         break # Exit this plan's iteration loop

                    logger.info(f"Plan '{plan_title}' [Iteration {iteration + 1}/{self.max_iterations}]", color='cyan')

                    # --- 1. Get Action from LLM ---
                    # The LLM's system prompt is already part of the LLM instance
                    try:
                        # Limit history length to keep token count manageable
                        llm_response = self.llm.reason(current_plan_history[-self.keep_messages:])
                        current_plan_history.append({"role": "assistant", "content": llm_response})
                    except Exception as e:
                        logger.error(f"LLM reason() call failed: {e}")
                        traceback.print_exc()
                        break # Stop this plan

                    # --- 2. Extract Tool Call ---
                    try:
                        # Extract the ACTION part from the LLM's response
                        action_match = re.search(r'\* ACTION\n(.*?)$', llm_response, re.DOTALL | re.MULTILINE)
                        if not action_match:
                             logger.warning(f"No '* ACTION' block found in LLM response. Skipping plan.")
                             logger.debug(f"LLM Response was: {llm_response}")
                             break # Stop this plan
                        
                        action_text = action_match.group(1).strip()
                        
                        # Use Tools to convert natural language action to tool call
                        # self.tools.extract_tool_use is assumed from tools.py
                        tool_call = self.tools.extract_tool_use(action_text)
                    except Exception as e:
                        logger.error(f"Tool extraction failed: {e}")
                        traceback.print_exc()
                        break # Stop this plan

                    # --- 3. Execute Tool ---
                    logger.info(f"Executing: {tool_call}", color='yellow')
                    try:
                        # self.tools.execute_tool is assumed from tools.py
                        tool_output = self.tools.execute_tool(page, tool_call)
                        
                        # Check for completion signal
                        if tool_call.strip() == "complete()":
                             is_complete = True
                             tool_output = "Agent signaled completion of this plan."
                        
                        # Truncate long outputs (like full HTML) for history
                        tool_output_truncated = (tool_output[:2000] + '... (truncated)') if len(tool_output) > 2000 else tool_output
                        current_plan_history.append({"role": "user", "content": f"**Tool Output:**\n{tool_output_truncated}"})
                    
                    except Exception as e:
                         logger.error(f"Tool execution failed: {tool_call} - {e}")
                         traceback.print_exc()
                         current_plan_history.append({"role": "user", "content": f"**Error executing tool:** {tool_call}\n**Exception:** {e}"})
                         break # Stop this plan
                
                # --- 4. Report & Judge ---
                # After max_iterations or `complete()`, send this plan's isolated history to the judge
                logger.info(f"Plan '{plan_title}' finished. Sending to judge for analysis...", color='yellow')
                try:
                    # self.reporter.report uses the LLM judge
                    was_success, judge_report = self.reporter.report(current_plan_history)
                    
                    if was_success:
                         logger.info(f"VULNERABILITY CONFIRMED for '{plan_title}'!", color='light_red')
                         # The reporter.report() method now handles saving
                    else:
                         logger.info(f"Judge rejected finding for '{plan_title}'.", color='green')
                    
                    # Add judge's report to the *master* history for this URL
                    # This informs future *plans* (if iterative planning was enabled)
                    url_master_history.append({"role": "user", "content": f"**Previous Plan Judge Analysis:**\n{judge_report}"})

                except Exception as e:
                    logger.error(f"Reporter failed for plan '{plan_title}': {e}")
                    traceback.print_exc()

                # Add a separator to master history
                url_master_history.append({"role": "system", "content": "--- END OF PREVIOUS PLAN ---"})
                
                # --- 5. TODO: Iterative Planning (if not disabled) ---
                # if not self.disable_iterative and self.num_plans_requested == -1:
                #    ... (logic to generate new plans based on url_master_history) ...

        except Exception as e:
            logger.error(f"An error occurred during plan execution for {url}: {e}")
            traceback.print_exc()