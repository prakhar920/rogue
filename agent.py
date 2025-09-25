# agent.py
import os
from logger import Logger
from proxy import WebProxy
from llm import LLM
from scanner import Scanner
from planner import Planner
from tools import Tools
from summarizer import Summarizer
from utils import check_hostname, enumerate_subdomains, wait_for_network_idle, count_tokens
from reporter import Reporter

logger = Logger()

class Agent:
    """
    AI-powered security testing agent that scans web applications for vulnerabilities.
    """

    def __init__(self, starting_url: str, expand_scope: bool = False, 
                 enumerate_subdomains: bool = False, model: str = 'o4-mini',
                 output_dir: str = 'security_results', max_iterations: int = 25,
                 num_plans: int = 1, disable_rag: bool = False,
                 enable_baseline_checks: bool = True, max_plans: int = None,
                 disable_iterative: bool = False, additional_instructions: str = ''):
        """
        Initialize the security testing agent.
        """
        self.starting_url = starting_url
        self.expand_scope = expand_scope
        self.should_enumerate_subdomains = enumerate_subdomains
        self.model = model
        self.output_dir = output_dir
        self.max_iterations = max_iterations
        self.num_plans = num_plans
        self.disable_iterative = disable_iterative
        self.additional_instructions = additional_instructions
        self.keep_messages = 15

        knowledge_summary = None  # RAG logic can be re-added here if needed
        if not disable_rag:
            print("[Info] 🧠 RAG would be initialized here (currently disabled).")
        else:
             print("[Info] 🚫 RAG knowledge fetching disabled")
        
        # Initialize the correct LLM based on the model selected
        self.llm = LLM(model=self.model, knowledge_content=knowledge_summary)
        
        # Pass the initialized LLM instance to the Planner
        self.planner = Planner(
            llm_instance=self.llm,
            knowledge_summary=knowledge_summary,
            enable_baseline_checks=enable_baseline_checks,
            max_plans=max_plans,
            num_plans_target=num_plans,
            additional_instructions=additional_instructions
        )
        
        self.proxy = WebProxy(starting_url, logger)
        self.scanner = None
        self.tools = Tools()
        self.history = []
        self.reporter = Reporter(starting_url)

    def run(self):
        """
        Execute the security scan.
        """
        logger.info("Creating web proxy to monitor requests", color='yellow')
        browser, context, page, playwright = self.proxy.create_proxy()
        urls_to_parse = [self.starting_url]

        if self.should_enumerate_subdomains:
            logger.info("Enumerating subdomains...", color='yellow')
            subdomains = enumerate_subdomains(self.starting_url)
            urls_to_parse.extend(subdomains)
        
        self.scanner = Scanner(page)

        while urls_to_parse:
            url = urls_to_parse.pop(0)
            logger.info(f"Starting scan: {url}", color='cyan')
            scan_results = self.scanner.scan(url)

            if self.expand_scope:
                # Logic to add more URLs to the queue
                pass

            page_source = scan_results["html_content"]
            page_summary = Summarizer().summarize_page_source(page_source, url)
            page_data = f"Page information: {page_summary}\nURL: {url}"

            self.history = [
                {"role": "system", "content": self.llm.system_prompt},
                {"role": "user", "content": page_data}
            ]
            
            # --- Iterative Planning Loop ---
            total_plans_executed = 0
            execution_insights = ""
            batch_size = max(1, self.num_plans // 3) if self.num_plans > 1 else 1
            max_batches = 3

            for batch_num in range(max_batches):
                if self.num_plans != -1 and total_plans_executed >= self.num_plans:
                    break

                logger.info(f"🔄 Batch {batch_num + 1}/{max_batches}: Generating plans...", color='cyan')
                
                batch_context = page_data
                if execution_insights:
                    batch_context += f"\n\n*** INSIGHTS FROM PREVIOUS BATCH ***\n{execution_insights}"
                
                try:
                    batch_plans = self.planner.plan_batch(batch_context, batch_size)
                    if not batch_plans:
                        logger.info(f"No more plans generated for batch {batch_num + 1}. Moving on.", color='yellow')
                        break
                    
                    batch_results = []
                    for i, plan in enumerate(batch_plans):
                        total_plans_executed += 1
                        plan_num = total_plans_executed
                        result = self._execute_single_plan(plan, page, plan_num, self.num_plans)
                        batch_results.append(result)

                    execution_insights = "\n".join(batch_results)
                except Exception as e:
                    logger.info(f"Error in batch {batch_num + 1}: {e}", color='red')
                    break
        
        logger.info("Generating summary report", color='yellow')
        self.reporter.generate_summary_report()

    def _execute_single_plan(self, plan: dict, page, plan_index: int, total_plans: int) -> str:
        """Execute a single security test plan and return a summary of results."""
        plan_title = plan.get('title', 'Untitled Plan')
        plan_desc = plan.get('description', 'No description.')
        logger.info(f"Executing Plan {plan_index}/{total_plans}: {plan_title}", color='cyan')

        # Create a clean history for this specific plan, but keep the initial context
        plan_history = self.history[:2] # Keep system prompt and initial page data
        plan_history.append({"role": "user", "content": f"Current plan: {plan_title} - {plan_desc}"})

        iterations = 0
        result_summary = f"TIMEOUT: {plan_title} - Max iterations reached"

        while iterations < self.max_iterations:
            llm_response = self.llm.reason(plan_history)
            plan_history.append({"role": "assistant", "content": llm_response})
            logger.info(f"{llm_response}", color='light_blue')

            tool_use = self.tools.extract_tool_use(llm_response)
            logger.info(f"ACTION: {tool_use}", color='yellow')

            tool_output = str(self.tools.execute_tool(page, tool_use))
            logger.info(f"OUTPUT: {tool_output[:250]}...", color='yellow')
            
            if "Completed" in tool_output:
                successful_exploit, report = self.reporter.report(plan_history)
                logger.info(f"ANALYSIS: {report}", color='green' if successful_exploit else 'red')
                result_summary = f"SUCCESS: {plan_title}" if successful_exploit else f"ATTEMPTED: {plan_title}"
                break
            
            summarized_output = Summarizer().summarize(llm_response, tool_use, tool_output)
            plan_history.append({"role": "user", "content": summarized_output})
            iterations += 1

        return result_summary