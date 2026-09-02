#!/usr/bin/env python3
import argparse
import re
import sys
import urllib.parse

# VaultMedia Corporate Executive Branding - Console Palette
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# Standardized Trusted Enterprise Domain Whitelist
TRUSTED_DOMAINS = ["google.com", "microsoft.com", "adobe.com", "linkedin.com", "apple.com", "spotify.com"]

def print_executive_banner():
    """Renders the VaultMedia enterprise gatekeeper terminal banner."""
    print(f"{BLUE}============================================================{RESET}")
    print(f"{BLUE}        VAULTMEDIA SECURITY | SPONSORSHIP TRIAGE ENGINE    {RESET}")
    print(f"{BLUE}   Infrastructure Gatekeeper Block - Operational Control     {RESET}")
    print(f"{BLUE}============================================================{RESET}")

def parse_executive_arguments():
    """Handles command-line arguments for scanning options."""
    parser = argparse.ArgumentParser(
        description="Automated structural interrogation of inbound business correspondence."
    )
    parser.add_argument("-f", "--file", help="Path to the raw inbound email file text dump")
    parser.add_argument("-t", "--text", help="Raw string copy-pasted from suspicious proposal")
    return parser.parse_args()

def analyze_structural_routing(raw_content):
    """Interrogates text blobs looking for identity spoofing and untrusted domains."""
    print(f"\n[*] Commencing Phase 1: Structural Extraction Pipeline...")
    
    # Isolate all standard web URL structures from the payload text
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]))+'
    found_urls = re.findall(url_pattern, raw_content)
    unique_urls = list(set(found_urls))  # Eliminate redundancy arrays
    
    print(f"[+] Extracted {len(unique_urls)} unique domain pathways for interrogation.")
    
    flagged_indicators = 0
    
    print(f"\n[*] Commencing Phase 2: Domain Integrity Evaluation...")
    print("-" * 60)
    
    for url in unique_urls:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Clean subdomains for flat matching boundaries
        clean_domain = ".".join(domain.split(".")[-2:])
        
        if clean_domain in TRUSTED_DOMAINS:
            print(f" {GREEN}[✓] TRUSTED PARTNER:{RESET} {domain} sits inside authorized enterprise parameters.")
        else:
            print(f" {RED}[!] RISK DETECTED:{RESET} {domain} is an unverified external third-party infrastructure.")
            flagged_indicators += 1
            
            # Look for high-risk top-level domain extensions common in malware campaigns
            if domain.endswith(('.zip', '.mov', '.top', '.xyz', '.click', '.download')):
                print(f"     {RED}[CRITICAL]: Utilizes high-risk TLD suspension extension ({domain}){RESET}")
                flagged_indicators += 2

    # Phase 3: Look for high-pressure call-to-action indicators (Social Engineering signatures)
    print("-" * 60 + f"\n[*] Commencing Phase 3: Linguistic Threat Signature Scan...")
    malicious_lexicon = [
        "wire transfer", "click below", "update banking", 
        "immediate action required", "login link", "contract attached",
        "review NDA", "unreleased track", "download stems"
    ]
    
    for word in malicious_lexicon:
        if re.search(r'\b' + re.escape(word) + r'\b', raw_content.lower()):
            print(f" {YELLOW}[!] THREAT KEYWORD IDENTIFIED:{RESET} Exposed signature matching phrase -> '{word}'")
            flagged_indicators += 1

    # Final Risk Ledger Classification Summary
    print("=" * 60)
    print(f"[*] Gateway Assessment Completed.")
    if flagged_indicators >= 3:
        print(f"STATUS: {RED}REJECT / BLOCK ACCESS{RESET} (Score: {flagged_indicators} Threat Metrics Tripped)")
        return False
    elif flagged_indicators > 0:
        print(f"STATUS: {YELLOW}HOLD / ISOLATE PATHWAY{RESET} (Score: {flagged_indicators} Mild Anomalies)")
        return False
    else:
        print(f"STATUS: {GREEN}CLEAR / PASS TO LEGAL{RESET} (Score: 0 Structural Flags)")
        return True

if __name__ == "__main__":
    print_executive_banner()
    args = parse_executive_arguments()
    
    content_to_analyze = ""
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                content_to_analyze = f.read()
        except Exception as e:
            print(f"{RED}[-] Operational Fault reading source file:{RESET} {e}")
            sys.exit(1)
    elif args.text:
        content_to_analyze = args.text
    else:
        print(f"{YELLOW}[!] Missing execution payload parameters. Input string text block via -t flag.{RESET}")
        sys.exit(1)
        
    analyze_structural_routing(content_to_analyze)
