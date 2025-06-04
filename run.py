import argparse
import os
from agent import Agent

def print_banner():
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
    print(banner)

def parse_args():
    parser = argparse.ArgumentParser(
        description='AI-Powered Web Application Security Testing Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Basic scan of a single URL
    python run.py -u https://example.com -m o3-mini -o results

    # Advanced scan with subdomain enumeration and URL discovery
    python run.py -u https://example.com -e -s -m o3-preview -i 10
        '''
    )
    
    parser.add_argument('-u', '--url', 
                        required=True,
                        help='Target URL to test')

    parser.add_argument('-e', '--expand',
                        action='store_true',
                        default=False,
                        help='Expand testing to discovered URLs')
    
    parser.add_argument('-s', '--subdomains',
                        action='store_true',
                        default=False,
                        help='Perform subdomain enumeration')

    parser.add_argument('-m', '--model',
                        choices=['o3-mini', 'o1-preview'],
                        default='o3-mini',
                        help='LLM model to use (default: o3-mini)')
    
    parser.add_argument('-o', '--output',
                        default='security_results',
                        help='Output directory for results (default: security_results)')
    
    parser.add_argument('-i', '--max-iterations',
                        type=int,
                        default=10,
                        help='Maximum iterations per plan of attack (default: 10)')

    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)
    
    return args

if __name__ == "__main__":
    print_banner()
    args = parse_args()
    print("\n[*] Starting security scan...")
    print(f"[*] Target URL: {args.url}")
    print(f"[*] Using model: {args.model}")
    print(f"[*] Results will be saved to: {args.output}\n")
    
    agent = Agent(
        starting_url=args.url,
        expand_scope=args.expand,
        enumerate_subdomains=args.subdomains,
        model=args.model,
        output_dir=args.output,
        max_iterations=args.max_iterations
    )
    agent.run()