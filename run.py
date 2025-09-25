# run.py
import argparse
import os
from agent import Agent
from constants import OPENAI_API_KEY, GEMINI_API_KEY

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
  # Quick scan with Gemini Flash
  python run.py -u https://example.com -p 3 -i 5 -m gemini-1.5-flash

  # Comprehensive scan with OpenAI GPT-4o
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

    # Check for the required API key based on the selected model
    if 'gemini' in args.model and not GEMINI_API_KEY:
        print("\n[Error] GEMINI_API_KEY is not set. Please set it to use a Gemini model.")
        return
    if 'o' in args.model and not OPENAI_API_KEY:
        print("\n[Error] OPENAI_API_KEY is not set. Please set it to use an OpenAI model.")
        return

    print(banner)
    print(f"[*] Starting scan on: {args.url}")
    print(f"[*] Using model: {args.model}")
    print(f"[*] Max iterations per plan: {args.max_iterations}")
    print(f"[*] Results will be saved to: {args.output}")

    try:
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
        print(f"\n[❌] Scan failed: {e}")

if __name__ == "__main__":
    main()