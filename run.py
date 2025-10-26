# run.py
import argparse
import os
from agent import Agent
# Import the constants, INCLUDING DEMO_MODE
from constants import OPENAI_API_KEY, GEMINI_API_KEY, DEMO_MODE # Make sure DEMO_MODE is imported
import traceback # Import traceback for better error logging

def main():
    banner = """
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                 Rogue - LLM Powered Security Scanner                 ║
    ║        Automated Penetration Testing with LLM Intelligence           ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """

    parser = argparse.ArgumentParser(
        description='AI-Powered Web Application Security Testing Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Quick scan with Gemini Flash (Demo Mode ON)
  # No API key needed if DEMO_MODE=1 in .env or via checkbox
  python run.py -u https://example.com -p 3 -i 5 -m gemini-1.5-flash

  # Comprehensive scan with OpenAI GPT-4o (Demo Mode OFF)
  # Requires OPENAI_API_KEY in .env
  python run.py -u https://example.com -p -1 -i 10 -m o4-mini
        '''
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL to test')
    parser.add_argument('-e', '--expand', action='store_true', help='Expand testing to discovered URLs')
    parser.add_argument('-s', '--subdomains', action='store_true', help='Perform subdomain enumeration')

    # Add Gemini models to the choices
    parser.add_argument(
        '-m', '--model',
        choices=['o4-mini', 'o3-mini', 'gemini-1.5-pro', 'gemini-1.5-flash'],
        default='o4-mini',
        help='LLM model to use'
    )

    parser.add_argument('-o', '--output', default='security_results', help='Output directory for results')
    parser.add_argument('-i', '--max-iterations', type=int, default=10, help='Maximum iterations per plan')
    parser.add_argument('-p', '--num-plans', type=int, default=1, help='Number of security testing plans per page (-1 for unlimited)')
    parser.add_argument('--disable-baseline-checks', action='store_true', help='Disable OWASP Top 10 baseline checks')
    parser.add_argument('--max-plans', type=int, default=None, help='Maximum total number of plans to generate')
    parser.add_argument('--disable-rag', action='store_true', default=True, help='Disable RAG knowledge fetching')
    parser.add_argument('--disable-iterative', action='store_true', help='Disable iterative planning (legacy mode)')
    parser.add_argument('--additional-instructions', type=str, default='', help='Additional instructions for the agent')

    args = parser.parse_args()

    # --- Pre-run Validation ---
    if not args.url.startswith(('http://', 'https://')):
        parser.error("URL must start with http:// or https://")

    # --- FINAL API KEY CHECK FIX ---
    # DEMO_MODE is now correctly imported from constants.py
    # This check happens *before* any potentially crashing LLM initializations
    is_demo_mode = DEMO_MODE # Get the value determined by constants.py loading .env
    if not is_demo_mode:
        print("[Info] Live mode active (DEMO_MODE is False). Checking for necessary API keys in .env...")
        key_found_for_model = False
        model_is_gemini = 'gemini' in args.model
        model_is_openai = 'o' in args.model # Assuming 'o' prefix means OpenAI

        if model_is_gemini:
            if GEMINI_API_KEY:
                print("[Info] Gemini API Key found in environment.")
                key_found_for_model = True
            else:
                # This error message will now correctly appear only in live mode
                print("\n[Error] FATAL: GEMINI_API_KEY is not set in .env or environment variables. Required for Gemini models in live mode.")
                return # Stop execution
        elif model_is_openai:
            if OPENAI_API_KEY:
                print("[Info] OpenAI API Key found in environment.")
                key_found_for_model = True
            else:
                # This error message will now correctly appear only in live mode
                print("\n[Error] FATAL: OPENAI_API_KEY is not set in .env or environment variables. Required for OpenAI models in live mode.")
                return # Stop execution
        else:
             # Should not happen with current choices, but good failsafe
             print(f"\n[Error] Unknown model type for '{args.model}'. Cannot check API key.")
             return

        # Redundant check, but ensures clarity if somehow the specific checks failed
        if not key_found_for_model:
             print(f"\n[Error] Could not find required API key for model '{args.model}' in .env file for live mode.")
             return # Stop execution
    else:
        # Confirm Demo Mode status based on the imported constant
        print("[Info] DEMO_MODE is active (determined by .env or environment). API key check skipped.")
    # --- END FINAL API KEY CHECK FIX ---


    # Banner printing (wrapped in try-except for safety)
    try:
        print(banner)
    except UnicodeEncodeError:
        print("[Warning] Could not print banner due to encoding issues. Using simple banner.")
        print("--- Rogue - LLM Powered Security Scanner ---")

    print(f"[*] Starting scan on: {args.url}")
    print(f"[*] Using model: {args.model}")
    if is_demo_mode: # Use the variable determined earlier
        print("[*] CONFIRMED: DEMO MODE IS ACTIVE. NO API CALLS WILL BE MADE.")
    print(f"[*] Max iterations per plan: {args.max_iterations}")
    print(f"[*] Results will be saved to: {args.output}")

    try:
        # Agent initialization should now succeed in both modes IF llm.py/reporter.py/agent.py are correct
        agent = Agent(
            starting_url=args.url,
            expand_scope=args.expand,
            enumerate_subdomains=args.subdomains,
            model=args.model,
            output_dir=args.output,
            max_iterations=args.max_iterations,
            num_plans=args.num_plans,
            enable_baseline_checks=not args.disable_baseline_checks,
            max_plans=args.max_plans,
            disable_rag=args.disable_rag,
            disable_iterative=args.disable_iterative,
            additional_instructions=args.additional_instructions
        )
        agent.run()
        print(f"\n[✅] Scan completed successfully! Results saved to: {args.output}")
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user.")
    except Exception as e:
        # Print full traceback for better debugging
        print(f"\n[❌] Scan failed during execution: {e}")
        traceback.print_exc() # Show exactly where the error occurred

if __name__ == "__main__":
    main()