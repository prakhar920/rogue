import argparse
import os
from agent import Agent

def main():
    banner = """
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║                  Rogue - LLM Powered Security Scanner                ║
    ║                                                                      ║
    ║           Automated Penetration Testing with LLM Intelligence        ║
    ║                                                                      ║
    ║     [+] Intelligent vulnerability discovery                          ║
    ║     [+] Advanced payload generation                                  ║
    ║     [+] Context-aware testing                                        ║
    ║     [+] Automated exploit verification                               ║
    ║                                                                      ║
    ║                -- Happy hunting, use responsibly! --                 ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """
    
    parser = argparse.ArgumentParser(description='Rogue - LLM Powered Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-o', '--output', default='security_results', help='Output directory for results')
    parser.add_argument('-m', '--model', default='o4-mini', help='LLM model to use')
    parser.add_argument('--expand-scope', action='store_true', help='Expand scope to discovered URLs')
    parser.add_argument('--enumerate-subdomains', action='store_true', help='Enumerate and test subdomains')
    parser.add_argument('--max-iterations', type=int, default=10, help='Maximum iterations per plan')
    parser.add_argument('--disable-baseline-checks', action='store_true', 
                        help='Disable OWASP Top 10 baseline security checks')
    parser.add_argument('--max-plans', type=int, default=None,
                        help='Maximum number of plans to generate (default: unlimited)')
    parser.add_argument('--disable-rag', action='store_true',
                        help='Disable RAG knowledge fetcher for faster startup')
    
    args = parser.parse_args()

    # Validation
    if not args.url:
        parser.error("URL is required. Use -u or --url to specify the target URL.")
    
    if not args.url.startswith(('http://', 'https://')):
        parser.error("URL must start with http:// or https://")

    print(banner)
    
    print(f"[*] Starting security scan...")
    print(f"[*] Target URL: {args.url}")
    print(f"[*] Using model: {args.model}")
    
    if args.max_plans:
        print(f"[*] Plans per page: {args.max_plans}")
    else:
        print(f"[*] Plans per page: Dynamic (based on page complexity)")
    
    print(f"[*] Results will be saved to: {args.output}")
    
    # Check if OpenAI API key is set
    if not os.getenv('OPENAI_API_KEY'):
        print("\n[Error] OPENAI_API_KEY environment variable is not set!")
        print("Please set your OpenAI API key:")
        print("export OPENAI_API_KEY='your-api-key-here'")
        return
    
    # Create agent with options
    agent = Agent(
        starting_url=args.url,
        expand_scope=args.expand_scope,
        enumerate_subdomains=args.enumerate_subdomains,
        model=args.model,
        output_dir=args.output,
        max_iterations=args.max_iterations,
        enable_baseline_checks=not args.disable_baseline_checks,
        max_plans=args.max_plans,
        enable_rag=not args.disable_rag
    )
    
    # Run the scan
    try:
        agent.run()
        print(f"\n[✅] Scan completed successfully!")
        print(f"[*] Results saved to: {args.output}")
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user")
    except Exception as e:
        print(f"\n[❌] Scan failed: {e}")

if __name__ == "__main__":
    main()