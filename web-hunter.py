
#!/usr/bin/env python3
"""
Web-Hunter - Advanced Security Reconnaissance Tool
Created by Nabaraj Lamichhane
GitHub: https://github.com/knobrazz

CAUTION: This tool is for ethical security testing only. Use responsibly and only on systems you have permission to test.
"""

import os
import sys
import argparse
import time
import random
import signal
import json
import platform
from datetime import datetime
from colorama import Fore, Back, Style, init
from tqdm import tqdm
from modules.banner import display_banner, display_thanks
from modules.utils import (
    create_project_directory,
    parse_cidr,
    validate_domain,
    validate_ip,
    print_colored,
    animate_text,
    load_targets_from_file
)
from modules.subdomain_enum import (
    passive_subdomain_enum,
    active_subdomain_enum,
    validate_subdomains
)
from modules.port_scanner import perform_port_scan
from modules.tech_detection import detect_technologies
from modules.endpoint_finder import (
    extract_endpoints,
    filter_endpoints,
    filter_js_files,
    extract_sensitive_info
)
from modules.vulnerability_scanner import (
    scan_sqli,
    scan_xss,
    scan_rce,
    scan_lfi,
    scan_csrf,
    scan_ssrf,
    scan_idor,
    scan_xxe,
    scan_ssti,
    scan_jwt,
    scan_broken_auth,
    run_nuclei_scan,
    run_vulnerability_scan
)
from modules.bypass_techniques import (
    status_code_bypass,
    waf_bypass
)
from modules.cloud_assets import (
    discover_cloud_assets,
    api_fuzzing
)
from modules.osint import (
    whois_lookup,
    email_finder,
    check_leaks,
    azure_tenant_mapper,
    find_metadata,
    search_api_leaks,
    run_google_dorks,
    run_github_dorks,
    analyze_github_repos,
    check_misconfigurations,
    check_spoofable_domains
)
from modules.dependency_analyzer import analyze_dependencies
from modules.auto_wordlist import harvest_wordlist_from_sources
from modules.combinatorial_attacks import run_combinatorial_attacks
from modules.advanced_http_analysis import analyze_http_behaviors
from modules.auto_payload import generate_and_test_payloads
from modules.reporting import rich_summary
from modules.login_finder import fuzz_login_panels
from modules.endpoint_analyze import analyze_source_code_endpoints
from modules.ai_analysis import ai_analyze_endpoints
from modules.smart_detection import run_smart_detection
from modules.risk_scoring import run_risk_analysis
from modules.open_source_integrations import run_open_source_integrations

# Initialize colorama
init(autoreset=True)

# Extended: Pretty risk flagging for findings
RISK_COLOR = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.MAGENTA + Style.BRIGHT,
    "medium": Fore.YELLOW + Style.BRIGHT,
    "low": Fore.CYAN,
    "info": Fore.WHITE
}

def print_finding(msg, risk="info"):
    print_colored(f"[{risk.upper()}] ", RISK_COLOR.get(risk, Fore.WHITE), end="")
    print(msg)

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print_colored("\n\n[!] Interrupted by user. Exiting gracefully...", Fore.YELLOW)
    display_thanks()
    sys.exit(0)

def find_existing_scans(base_dir):
    """Find existing scan directories"""
    scan_dirs = []
    if os.path.exists(base_dir):
        for dir_name in os.listdir(base_dir):
            full_path = os.path.join(base_dir, dir_name)
            if os.path.isdir(full_path) and '_' in dir_name:
                if any([os.path.exists(os.path.join(full_path, subdir)) for subdir in 
                        ['subdomains', 'endpoints', 'ports', 'technologies', 'vulnerabilities']]):
                    scan_dirs.append(full_path)
    return scan_dirs

def load_scan_data(scan_dir):
    """Load existing scan data from a directory"""
    scan_data = {
        'domain': None,
        'subdomains': [],
        'endpoints': [],
        'critical_endpoints': [],
        'js_files': [],
        'ports': [],
        'technologies': [],
        'vulnerabilities': {}
    }
    dir_name = os.path.basename(scan_dir)
    if '_' in dir_name:
        scan_data['domain'] = dir_name.split('_')[0]
    subdomains_file = os.path.join(scan_dir, 'subdomains', 'valid_subdomains.txt')
    if os.path.exists(subdomains_file):
        scan_data['subdomains'] = load_targets_from_file(subdomains_file)
    endpoints_file = os.path.join(scan_dir, 'endpoints', 'all_endpoints.txt')
    if os.path.exists(endpoints_file):
        scan_data['endpoints'] = load_targets_from_file(endpoints_file)
    critical_endpoints_file = os.path.join(scan_dir, 'endpoints', 'critical_endpoints.txt')
    if os.path.exists(critical_endpoints_file):
        scan_data['critical_endpoints'] = load_targets_from_file(critical_endpoints_file)
    js_files_file = os.path.join(scan_dir, 'endpoints', 'js_files.txt')
    if os.path.exists(js_files_file):
        scan_data['js_files'] = load_targets_from_file(js_files_file)
    vuln_dir = os.path.join(scan_dir, 'vulnerabilities')
    if os.path.exists(vuln_dir):
        for vuln_type in ['sqli', 'xss', 'rce', 'lfi', 'csrf', 'ssrf', 'idor', 'xxe', 'ssti', 'jwt', 'broken_auth']:
            vuln_file = os.path.join(vuln_dir, vuln_type, f"vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                scan_data['vulnerabilities'][vuln_type] = load_targets_from_file(vuln_file)
    return scan_data

def continue_scan_from_directory(scan_dir):
    """Continue scanning from an existing scan directory"""
    print_colored(f"[+] Continuing scan from directory: {scan_dir}", Fore.CYAN)
    scan_data = load_scan_data(scan_dir)
    if not scan_data['domain']:
        print_colored("[!] Could not determine domain from directory name", Fore.RED)
        return
    domain = scan_data['domain']
    print_colored(f"[+] Detected domain: {domain}", Fore.GREEN)
    print_colored("\nSelect operations to continue:", Fore.CYAN)
    print_colored("[1] Extract more endpoints (requires existing subdomains)", Fore.WHITE)
    print_colored("[2] Extract sensitive information from endpoints", Fore.WHITE)
    print_colored("[3] Continue vulnerability scanning", Fore.WHITE)
    print_colored("[4] Run specialized vulnerability scanners", Fore.WHITE)
    print_colored("[5] Run advanced analysis (AI, Risk Scoring, Open Source Integrations)", Fore.WHITE)
    print_colored("[6] All of the above", Fore.WHITE)
    choice = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter your choice (1-6): ")
    if choice in ['1', '6']:
        if scan_data['subdomains']:
            print_colored("\n[+] Extracting more endpoints from subdomains...", Fore.CYAN)
            new_endpoints = extract_endpoints(scan_data['subdomains'], scan_dir)
            combined_endpoints = list(set(scan_data['endpoints'] + new_endpoints))
            print_colored(f"[+] Found {len(combined_endpoints)} total endpoints ({len(new_endpoints)} new)", Fore.GREEN)
            critical_endpoints = filter_endpoints(combined_endpoints, scan_dir)
            js_files = filter_js_files(combined_endpoints, scan_dir)
            scan_data['endpoints'] = combined_endpoints
            scan_data['critical_endpoints'] = critical_endpoints
            scan_data['js_files'] = js_files
        else:
            print_colored("[!] No subdomains found in previous scan", Fore.YELLOW)
    if choice in ['2', '6']:
        if scan_data['endpoints']:
            print_colored("\n[+] Extracting sensitive information from endpoints...", Fore.CYAN)
            extract_sensitive_info(scan_data['endpoints'], scan_dir)
            
            # Get advanced HTTP analysis
            print_colored("\n[+] Running advanced HTTP analysis...", Fore.CYAN)
            analyze_http_behaviors(scan_data['endpoints'], scan_dir)
            
            # Enhanced source code endpoint analysis
            print_colored("\n[+] Running enhanced source code endpoint analysis...", Fore.CYAN)
            source_endpoints = analyze_source_code_endpoints(scan_data['subdomains'], scan_dir)
            scan_data['endpoints'].extend(source_endpoints)
            scan_data['endpoints'] = list(set(scan_data['endpoints']))
        else:
            print_colored("[!] No endpoints found in previous scan", Fore.YELLOW)
    if choice in ['3', '6']:
        if scan_data['critical_endpoints']:
            print_colored("\n[+] Continuing vulnerability scanning on critical endpoints...", Fore.CYAN)
            run_vulnerability_scan(scan_data['critical_endpoints'], scan_dir)
        elif scan_data['endpoints']:
            print_colored("\n[+] No critical endpoints found. Scanning all endpoints...", Fore.CYAN)
            critical_endpoints = filter_endpoints(scan_data['endpoints'], scan_dir)
            if critical_endpoints:
                run_vulnerability_scan(critical_endpoints, scan_dir)
            else:
                sample_size = min(50, len(scan_data['endpoints']))
                sample_endpoints = random.sample(scan_data['endpoints'], sample_size)
                print_colored(f"[+] Scanning sample of {sample_size} endpoints", Fore.CYAN)
                run_vulnerability_scan(sample_endpoints, scan_dir)
        else:
            print_colored("[!] No endpoints found in previous scan", Fore.YELLOW)
    if choice in ['4', '6']:
        if scan_data['endpoints'] or scan_data['critical_endpoints']:
            targets = scan_data['critical_endpoints'] if scan_data['critical_endpoints'] else scan_data['endpoints']
            print_colored("\n[+] Select specialized vulnerability scanners to run:", Fore.CYAN)
            print_colored("[1] SQL Injection", Fore.WHITE)
            print_colored("[2] Cross-Site Scripting (XSS)", Fore.WHITE)
            print_colored("[3] Remote Code Execution (RCE)", Fore.WHITE)
            print_colored("[4] Local/Remote File Inclusion (LFI/RFI)", Fore.WHITE)
            print_colored("[5] Cross-Site Request Forgery (CSRF)", Fore.WHITE)
            print_colored("[6] Server-Side Request Forgery (SSRF)", Fore.WHITE)
            print_colored("[7] Insecure Direct Object References (IDOR)", Fore.WHITE)
            print_colored("[8] XML External Entity (XXE)", Fore.WHITE)
            print_colored("[9] Server-Side Template Injection (SSTI)", Fore.WHITE)
            print_colored("[10] JWT Vulnerabilities", Fore.WHITE)
            print_colored("[11] Authentication Vulnerabilities", Fore.WHITE)
            print_colored("[12] Comprehensive Nuclei Scan", Fore.WHITE)
            print_colored("[13] All of the above", Fore.WHITE)
            scanner_choice = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter your choice (1-13, or comma-separated list): ")
            if scanner_choice == '13':
                scanner_choices = list(range(1, 13))
            else:
                try:
                    scanner_choices = [int(c.strip()) for c in scanner_choice.split(',') if c.strip().isdigit()]
                except:
                    scanner_choices = []
                    if scanner_choice.isdigit():
                        scanner_choices = [int(scanner_choice)]
            for choice in scanner_choices:
                if choice == 1:
                    print_colored("\n[+] Running SQL Injection scanner...", Fore.CYAN)
                    scan_sqli(targets, scan_dir)
                elif choice == 2:
                    print_colored("\n[+] Running XSS scanner...", Fore.CYAN)
                    scan_xss(targets, scan_dir)
                elif choice == 3:
                    print_colored("\n[+] Running RCE scanner...", Fore.CYAN)
                    scan_rce(targets, scan_dir)
                elif choice == 4:
                    print_colored("\n[+] Running LFI/RFI scanner...", Fore.CYAN)
                    scan_lfi(targets, scan_dir)
                elif choice == 5:
                    print_colored("\n[+] Running CSRF scanner...", Fore.CYAN)
                    scan_csrf(targets, scan_dir)
                elif choice == 6:
                    print_colored("\n[+] Running SSRF scanner...", Fore.CYAN)
                    scan_ssrf(targets, scan_dir)
                elif choice == 7:
                    print_colored("\n[+] Running IDOR scanner...", Fore.CYAN)
                    scan_idor(targets, scan_dir)
                elif choice == 8:
                    print_colored("\n[+] Running XXE scanner...", Fore.CYAN)
                    scan_xxe(targets, scan_dir)
                elif choice == 9:
                    print_colored("\n[+] Running SSTI scanner...", Fore.CYAN)
                    scan_ssti(targets, scan_dir)
                elif choice == 10:
                    print_colored("\n[+] Running JWT vulnerability scanner...", Fore.CYAN)
                    scan_jwt(targets, scan_dir)
                elif choice == 11:
                    print_colored("\n[+] Running authentication vulnerability scanner...", Fore.CYAN)
                    scan_broken_auth(targets, scan_dir)
                elif choice == 12:
                    print_colored("\n[+] Running comprehensive Nuclei scan...", Fore.CYAN)
                    run_nuclei_scan(targets, scan_dir)
        else:
            print_colored("[!] No endpoints found in previous scan", Fore.YELLOW)
    
    if choice in ['5', '6']:
        if scan_data['endpoints'] or scan_data['critical_endpoints']:
            targets = scan_data['critical_endpoints'] if scan_data['critical_endpoints'] else scan_data['endpoints']
            
            # Run AI analysis if environment variables are set
            if os.environ.get("AI_API_KEY"):
                print_colored("\n[+] Running AI-powered vulnerability analysis...", Fore.CYAN)
                ai_analyze_endpoints(targets[:20], scan_dir)  # Limit to 20 to prevent excessive API usage
            else:
                print_colored("\n[!] AI analysis skipped. Set AI_API_KEY environment variable to enable.", Fore.YELLOW)
            
            # Run smart detection
            print_colored("\n[+] Running smart anomaly detection...", Fore.CYAN)
            run_smart_detection(targets, scan_dir)
            
            # Run risk analysis and scoring
            print_colored("\n[+] Running intelligent risk scoring and analysis...", Fore.CYAN)
            run_risk_analysis(scan_dir)
            
            # Run open source integrations
            print_colored("\n[+] Running open source tool integrations...", Fore.CYAN)
            run_open_source_integrations(targets, scan_dir, domain=scan_data['domain'])
            
            # Advanced wordlist generation
            print_colored("\n[+] Building enhanced wordlists from sources...", Fore.CYAN)
            wordlist = harvest_wordlist_from_sources(targets, scan_dir)
            
            # Generate and test payloads
            print_colored("\n[+] Generating and testing automated payloads...", Fore.CYAN)
            generate_and_test_payloads(targets, wordlist, scan_dir)
            
            # Run combinatorial attacks
            print_colored("\n[+] Running combinatorial and multi-vector attacks...", Fore.CYAN)
            run_combinatorial_attacks(targets, scan_dir, wordlist)
        else:
            print_colored("[!] No endpoints found in previous scan", Fore.YELLOW)
    
    print_colored("\n[+] Continued scan completed successfully!", Fore.GREEN)

def run_nuclei_and_show(targets, project_dir):
    """Run Nuclei scan and show results"""
    print_colored(f"[*] Running Nuclei scan for {len(targets)} targets...", Fore.BLUE)
    run_nuclei_scan(targets, project_dir)

def run_domain_recon(domain, output_dir, options=None):
    # Set default options if none provided
    if options is None:
        options = {"all": True}
        
    display_banner()
    print_colored(f"\n[*] Starting reconnaissance for domain: {domain}", Fore.BLUE)
    project_dir = create_project_directory(output_dir, domain)
    
    # Step 1: Subdomain Enumeration
    if options.get("subdomain_enum", False) or options.get("all", False):
        print_colored("\n[*] Step 1: Subdomain Enumeration", Fore.BLUE)
        passive_subdomains = passive_subdomain_enum(domain, project_dir)
        active_subdomains = active_subdomain_enum(domain, project_dir)
        all_subdomains = list(set(passive_subdomains + active_subdomains))
        valid_subdomains = validate_subdomains(all_subdomains, project_dir)
        if not valid_subdomains:
            print_colored("[!] No valid subdomains found. Adding base domain for scanning.", Fore.YELLOW)
            valid_subdomains = [domain]
        run_nuclei_and_show(valid_subdomains, project_dir)
    else:
        print_colored("\n[*] Skipping subdomain enumeration...", Fore.YELLOW)
        valid_subdomains = [domain]
    
    # Step 2: Port Scanning
    if options.get("port_scan", False) or options.get("all", False):
        print_colored("\n[*] Step 2: Port Scanning", Fore.BLUE)
        perform_port_scan(valid_subdomains, project_dir)
    else:
        print_colored("\n[*] Skipping port scanning...", Fore.YELLOW)
    
    # Step 3: Technology Detection
    if options.get("tech_detect", False) or options.get("all", False):
        print_colored("\n[*] Step 3: Technology Detection", Fore.BLUE)
        tech_results = detect_technologies(valid_subdomains, project_dir)
    else:
        print_colored("\n[*] Skipping technology detection...", Fore.YELLOW)
        tech_results = []
    
    # Step 4: Endpoint Discovery
    if options.get("endpoints", False) or options.get("all", False):
        print_colored("\n[*] Step 4: Endpoint Discovery", Fore.BLUE)
        all_endpoints = extract_endpoints(valid_subdomains, project_dir)
        critical_endpoints = filter_endpoints(all_endpoints, project_dir)
        js_files = filter_js_files(all_endpoints, project_dir)
        extract_sensitive_info(all_endpoints, project_dir)
        
        # Enhanced endpoint analysis
        if options.get("advanced", False) or options.get("all", False):
            print_colored("\n[*] Running enhanced source code endpoint analysis...", Fore.BLUE)
            source_endpoints = analyze_source_code_endpoints(valid_subdomains, project_dir)
            all_endpoints.extend(source_endpoints)
            all_endpoints = list(set(all_endpoints))
            
            print_colored("\n[*] Running advanced HTTP analysis...", Fore.BLUE)
            analyze_http_behaviors(all_endpoints, project_dir)
            
            # Identify login panels
            print_colored("\n[*] Finding login panels and admin interfaces...", Fore.BLUE)
            login_panels = fuzz_login_panels(valid_subdomains, project_dir)
    else:
        print_colored("\n[*] Skipping endpoint discovery...", Fore.YELLOW)
        all_endpoints = []
        critical_endpoints = []
        js_files = []
        login_panels = []
    
    # Step 5: Auto-learning and wordlist generation
    if options.get("autolearn", False) or options.get("all", False):
        print_colored("\n[*] Step 5: Auto-learning and Wordlist Generation", Fore.BLUE)
        learned_wordlist = harvest_wordlist_from_sources(all_endpoints or valid_subdomains, project_dir)
    else:
        print_colored("\n[*] Skipping auto-learning...", Fore.YELLOW)
        learned_wordlist = []
    
    # Step 6: Dependency Analysis
    if options.get("dependencies", False) or options.get("all", False):
        print_colored("\n[*] Step 6: Analyzing JavaScript Dependencies", Fore.BLUE)
        dependencies = analyze_dependencies(all_endpoints or valid_subdomains, project_dir)
    else:
        print_colored("\n[*] Skipping dependency analysis...", Fore.YELLOW)
        dependencies = []
    
    # Step 7: Vulnerability Scanning
    if options.get("vuln_scan", False) or options.get("all", False):
        print_colored("\n[*] Step 7: Vulnerability Scanning", Fore.BLUE)
        if critical_endpoints:
            run_vulnerability_scan(critical_endpoints, project_dir)
        elif all_endpoints:
            sample_size = min(50, len(all_endpoints))
            print_colored(f"[*] No critical endpoints found. Scanning sample of {sample_size} random endpoints...", Fore.YELLOW)
            sample_endpoints = random.sample(all_endpoints, sample_size)
            run_vulnerability_scan(sample_endpoints, project_dir)
        else:
            print_colored("[!] No endpoints found for vulnerability scanning.", Fore.YELLOW)
    else:
        print_colored("\n[*] Skipping vulnerability scanning...", Fore.YELLOW)
    
    # Step 8: Advanced Analysis (when all is selected)
    if options.get("advanced", False) or options.get("all", False):
        scan_targets = critical_endpoints or all_endpoints or valid_subdomains
        
        # Run payload generation and testing
        if scan_targets:
            print_colored("\n[*] Step 8: Generating and Testing Payloads", Fore.BLUE)
            generate_and_test_payloads(scan_targets, learned_wordlist, project_dir)
            
            # Run combinatorial attacks
            print_colored("\n[*] Running Combinatorial and Multi-Vector Attacks", Fore.BLUE)
            run_combinatorial_attacks(scan_targets, project_dir, learned_wordlist)
            
            # Smart detection
            print_colored("\n[*] Running Smart Anomaly Detection", Fore.BLUE)
            run_smart_detection(scan_targets, project_dir)
            
            # Run open source integrations
            print_colored("\n[*] Running Open Source Tool Integrations", Fore.BLUE)
            run_open_source_integrations(scan_targets, project_dir, domain=domain)
            
            # AI-powered analysis if API key is set
            if os.environ.get("AI_API_KEY"):
                print_colored("\n[*] Running AI-Powered Vulnerability Analysis", Fore.BLUE)
                ai_analyze_endpoints(scan_targets[:20], project_dir)  # Limit to 20 to save API costs
            
            # Risk analysis and scoring
            print_colored("\n[*] Running Intelligent Risk Scoring and Analysis", Fore.BLUE)
            run_risk_analysis(project_dir)
    
    # Step 9: OSINT Information Gathering
    if options.get("osint", False) or options.get("all", False):
        print_colored("\n[*] Step 9: OSINT Information Gathering", Fore.BLUE)
        whois_data = whois_lookup(domain, project_dir)
        emails = email_finder(domain, project_dir)
        leaks = check_leaks(domain, project_dir)
    else:
        print_colored("\n[*] Skipping OSINT information gathering...", Fore.YELLOW)
        
    # Generate rich summary
    if all_endpoints or valid_subdomains:
        print_colored("\n[*] Generating Final Report", Fore.GREEN)
        vulns_dict = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        
        # Collect vulnerability findings
        for vuln_type in ["sqli", "rce", "lfi", "xxe"]:
            vuln_file = os.path.join(project_dir, f"vulnerabilities/{vuln_type}/vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                with open(vuln_file) as f:
                    vulns_dict["critical"].extend([l.strip() for l in f.readlines()])
                    
        for vuln_type in ["xss", "ssrf", "ssti"]:
            vuln_file = os.path.join(project_dir, f"vulnerabilities/{vuln_type}/vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                with open(vuln_file) as f:
                    vulns_dict["high"].extend([l.strip() for l in f.readlines()])
                    
        for vuln_type in ["idor", "csrf", "jwt", "broken_auth"]:
            vuln_file = os.path.join(project_dir, f"vulnerabilities/{vuln_type}/vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                with open(vuln_file) as f:
                    vulns_dict["medium"].extend([l.strip() for l in f.readlines()])
                    
        rich_summary(all_endpoints or valid_subdomains, vulns_dict, project_dir)
    
    print_colored("\n[+] Reconnaissance completed successfully!", Fore.GREEN)
    return {
        'project_dir': project_dir,
        'domain': domain,
        'subdomains': valid_subdomains,
        'endpoints': all_endpoints,
        'critical_endpoints': critical_endpoints,
        'js_files': js_files,
        'login_panels': login_panels if 'login_panels' in locals() else []
    }

def run_ip_recon(ip, output_dir, options=None):
    # Set default options if none provided
    if options is None:
        options = {"all": True}
        
    display_banner()
    print_colored(f"\n[*] Starting reconnaissance for IP: {ip}", Fore.BLUE)
    project_dir = create_project_directory(output_dir, ip)
    
    # Step 1: Port Scanning
    if options.get("port_scan", False) or options.get("all", False):
        print_colored("\n[*] Step 1: Port Scanning", Fore.BLUE)
        perform_port_scan([ip], project_dir)
    else:
        print_colored("\n[*] Skipping port scanning...", Fore.YELLOW)
    
    # Create HTTP URLs for the IP
    http_targets = [f"http://{ip}", f"https://{ip}"]
    
    # Step 2: Technology Detection
    if options.get("tech_detect", False) or options.get("all", False):
        print_colored("\n[*] Step 2: Technology Detection", Fore.BLUE)
        tech_results = detect_technologies(http_targets, project_dir)
    else:
        print_colored("\n[*] Skipping technology detection...", Fore.YELLOW)
    
    # Step 3: Endpoint Discovery
    if options.get("endpoints", False) or options.get("all", False):
        print_colored("\n[*] Step 3: Endpoint Discovery", Fore.BLUE)
        all_endpoints = extract_endpoints(http_targets, project_dir)
        critical_endpoints = filter_endpoints(all_endpoints, project_dir)
        js_files = filter_js_files(all_endpoints, project_dir)
        extract_sensitive_info(all_endpoints, project_dir)
        
        # Enhanced endpoint analysis
        if options.get("advanced", False) or options.get("all", False):
            print_colored("\n[*] Running enhanced source code endpoint analysis...", Fore.BLUE)
            source_endpoints = analyze_source_code_endpoints(http_targets, project_dir)
            all_endpoints.extend(source_endpoints)
            all_endpoints = list(set(all_endpoints))
            
            print_colored("\n[*] Running advanced HTTP analysis...", Fore.BLUE)
            analyze_http_behaviors(all_endpoints, project_dir)
    else:
        print_colored("\n[*] Skipping endpoint discovery...", Fore.YELLOW)
        all_endpoints = []
        critical_endpoints = []
        js_files = []
    
    # Step 4: Vulnerability Scanning
    if options.get("vuln_scan", False) or options.get("all", False):
        print_colored("\n[*] Step 4: Vulnerability Scanning", Fore.BLUE)
        if critical_endpoints:
            run_vulnerability_scan(critical_endpoints, project_dir)
        elif all_endpoints:
            sample_size = min(50, len(all_endpoints))
            print_colored(f"[*] No critical endpoints found. Scanning sample of {sample_size} random endpoints...", Fore.YELLOW)
            sample_endpoints = random.sample(all_endpoints, sample_size)
            run_vulnerability_scan(sample_endpoints, project_dir)
        else:
            print_colored("[!] No endpoints found for vulnerability scanning. Trying direct nuclei scan on IP...", Fore.YELLOW)
            run_nuclei_scan(http_targets, project_dir)
    else:
        print_colored("\n[*] Skipping vulnerability scanning...", Fore.YELLOW)
    
    # Advanced Analysis (when all is selected)
    if options.get("advanced", False) or options.get("all", False) and (critical_endpoints or all_endpoints or http_targets):
        scan_targets = critical_endpoints or all_endpoints or http_targets
        
        # Auto-learning and wordlist generation
        print_colored("\n[*] Auto-learning and Wordlist Generation", Fore.BLUE)
        learned_wordlist = harvest_wordlist_from_sources(scan_targets, project_dir)
        
        # Run dependency analysis
        print_colored("\n[*] Analyzing JavaScript Dependencies", Fore.BLUE)
        analyze_dependencies(scan_targets, project_dir)
        
        # Run payload generation and testing
        print_colored("\n[*] Generating and Testing Payloads", Fore.BLUE)
        generate_and_test_payloads(scan_targets, learned_wordlist, project_dir)
        
        # Run combinatorial attacks
        print_colored("\n[*] Running Combinatorial and Multi-Vector Attacks", Fore.BLUE)
        run_combinatorial_attacks(scan_targets, project_dir, learned_wordlist)
        
        # Smart detection
        print_colored("\n[*] Running Smart Anomaly Detection", Fore.BLUE)
        run_smart_detection(scan_targets, project_dir)
        
        # Run open source integrations
        print_colored("\n[*] Running Open Source Tool Integrations", Fore.BLUE)
        run_open_source_integrations(scan_targets, project_dir)
        
        # AI-powered analysis if API key is set
        if os.environ.get("AI_API_KEY"):
            print_colored("\n[*] Running AI-Powered Vulnerability Analysis", Fore.BLUE)
            ai_analyze_endpoints(scan_targets[:10], project_dir)  # Limit to 10 to save API costs
        
        # Risk analysis and scoring
        print_colored("\n[*] Running Intelligent Risk Scoring and Analysis", Fore.BLUE)
        run_risk_analysis(project_dir)
    
    # Generate summary
    if all_endpoints or http_targets:
        print_colored("\n[*] Generating Final Report", Fore.GREEN)
        vulns_dict = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        
        # Collect vulnerability findings
        for vuln_type in ["sqli", "rce", "lfi", "xxe"]:
            vuln_file = os.path.join(project_dir, f"vulnerabilities/{vuln_type}/vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                with open(vuln_file) as f:
                    vulns_dict["critical"].extend([l.strip() for l in f.readlines()])
                    
        for vuln_type in ["xss", "ssrf", "ssti"]:
            vuln_file = os.path.join(project_dir, f"vulnerabilities/{vuln_type}/vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                with open(vuln_file) as f:
                    vulns_dict["high"].extend([l.strip() for l in f.readlines()])
                    
        for vuln_type in ["idor", "csrf", "jwt", "broken_auth"]:
            vuln_file = os.path.join(project_dir, f"vulnerabilities/{vuln_type}/vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                with open(vuln_file) as f:
                    vulns_dict["medium"].extend([l.strip() for l in f.readlines()])
                    
        rich_summary(all_endpoints or http_targets, vulns_dict, project_dir)
    
    print_colored("\n[+] Reconnaissance completed successfully!", Fore.GREEN)
    return {
        'project_dir': project_dir,
        'ip': ip,
        'endpoints': all_endpoints,
        'critical_endpoints': critical_endpoints,
        'js_files': js_files
    }

def run_cidr_recon(cidr, output_dir, options=None):
    # Set default options if none provided
    if options is None:
        options = {"all": True}
        
    display_banner()
    print_colored(f"\n[*] Starting reconnaissance for CIDR range: {cidr}", Fore.BLUE)
    ips = parse_cidr(cidr)
    if not ips:
        print_colored("[!] No valid IPs found in the CIDR range", Fore.RED)
        return None
    project_dir = create_project_directory(output_dir, cidr.replace('/', '_'))
    
    # Limit IPs to scan to avoid overload
    max_ips_to_scan = min(100, len(ips))
    ip_sample = ips[:max_ips_to_scan] if len(ips) > max_ips_to_scan else ips
    print_colored(f"[*] Scanning {len(ip_sample)} out of {len(ips)} IPs", Fore.YELLOW)
    
    # Step 1: Port Scanning
    if options.get("port_scan", False) or options.get("all", False):
        print_colored("\n[*] Step 1: Port Scanning", Fore.BLUE)
        perform_port_scan(ip_sample, project_dir)
    else:
        print_colored("\n[*] Skipping port scanning...", Fore.YELLOW)
    
    # Create HTTP URLs for the IPs
    http_targets = []
    for ip in ip_sample:
        http_targets.append(f"http://{ip}")
        http_targets.append(f"https://{ip}")
    
    # Step 2: Technology Detection
    if options.get("tech_detect", False) or options.get("all", False):
        print_colored("\n[*] Step 2: Technology Detection", Fore.BLUE)
        tech_results = detect_technologies(http_targets, project_dir)
    else:
        print_colored("\n[*] Skipping technology detection...", Fore.YELLOW)
    
    # Step 3: Endpoint Discovery
    if options.get("endpoints", False) or options.get("all", False):
        print_colored("\n[*] Step 3: Endpoint Discovery", Fore.BLUE)
        all_endpoints = extract_endpoints(http_targets, project_dir)
        critical_endpoints = filter_endpoints(all_endpoints, project_dir)
        js_files = filter_js_files(all_endpoints, project_dir)
        extract_sensitive_info(all_endpoints, project_dir)
    else:
        print_colored("\n[*] Skipping endpoint discovery...", Fore.YELLOW)
        all_endpoints = []
        critical_endpoints = []
        js_files = []
    
    # Step 4: Vulnerability Scanning
    if options.get("vuln_scan", False) or options.get("all", False):
        print_colored("\n[*] Step 4: Vulnerability Scanning", Fore.BLUE)
        if critical_endpoints:
            run_vulnerability_scan(critical_endpoints, project_dir)
        elif all_endpoints:
            sample_size = min(50, len(all_endpoints))
            print_colored(f"[*] No critical endpoints found. Scanning sample of {sample_size} random endpoints...", Fore.YELLOW)
            sample_endpoints = random.sample(all_endpoints, sample_size)
            run_vulnerability_scan(sample_endpoints, project_dir)
        else:
            print_colored("[!] No endpoints found for vulnerability scanning. Trying direct nuclei scan on IPs...", Fore.YELLOW)
            sample_size = min(50, len(http_targets))
            http_sample = random.sample(http_targets, sample_size)
            run_nuclei_scan(http_sample, project_dir)
    else:
        print_colored("\n[*] Skipping vulnerability scanning...", Fore.YELLOW)
    
    # Advanced Analysis (when all is selected)
    if options.get("advanced", False) or options.get("all", False) and (critical_endpoints or all_endpoints or http_targets):
        scan_targets = critical_endpoints or all_endpoints or http_targets[:50]  # Limit targets
        
        # Auto-learning and wordlist generation
        print_colored("\n[*] Auto-learning and Wordlist Generation", Fore.BLUE)
        learned_wordlist = harvest_wordlist_from_sources(scan_targets, project_dir)
        
        # Run dependency analysis
        print_colored("\n[*] Analyzing JavaScript Dependencies", Fore.BLUE)
        analyze_dependencies(scan_targets, project_dir)
        
        # Run payload generation and testing
        print_colored("\n[*] Generating and Testing Payloads", Fore.BLUE)
        generate_and_test_payloads(scan_targets, learned_wordlist, project_dir)
        
        # Run combinatorial attacks
        print_colored("\n[*] Running Combinatorial and Multi-Vector Attacks", Fore.BLUE)
        run_combinatorial_attacks(scan_targets, project_dir, learned_wordlist)
        
        # Run open source integrations
        print_colored("\n[*] Running Open Source Tool Integrations", Fore.BLUE)
        run_open_source_integrations(scan_targets, project_dir)
        
        # Risk analysis and scoring
        print_colored("\n[*] Running Intelligent Risk Scoring and Analysis", Fore.BLUE)
        run_risk_analysis(project_dir)
    
    # Generate summary
    if all_endpoints or http_targets:
        print_colored("\n[*] Generating Final Report", Fore.GREEN)
        vulns_dict = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        
        # Collect vulnerability findings
        for vuln_type in ["sqli", "rce", "lfi", "xxe"]:
            vuln_file = os.path.join(project_dir, f"vulnerabilities/{vuln_type}/vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                with open(vuln_file) as f:
                    vulns_dict["critical"].extend([l.strip() for l in f.readlines()])
                    
        for vuln_type in ["xss", "ssrf", "ssti"]:
            vuln_file = os.path.join(project_dir, f"vulnerabilities/{vuln_type}/vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                with open(vuln_file) as f:
                    vulns_dict["high"].extend([l.strip() for l in f.readlines()])
                    
        rich_summary(all_endpoints or http_targets[:100], vulns_dict, project_dir)
    
    print_colored("\n[+] Reconnaissance completed successfully!", Fore.GREEN)
    return {
        'project_dir': project_dir,
        'cidr': cidr,
        'ips': ips,
        'endpoints': all_endpoints,
        'critical_endpoints': critical_endpoints,
        'js_files': js_files
    }

def run_wildcard_recon(wildcard, output_dir, options=None):
    # Set default options if none provided
    if options is None:
        options = {"all": True}
        
    base_domain = wildcard.replace('*.', '')
    display_banner()
    print_colored(f"\n[*] Starting reconnaissance for wildcard domain: {wildcard}", Fore.BLUE)
    project_dir = create_project_directory(output_dir, f"wildcard_{base_domain}")
    
    # Step 1: Extensive Subdomain Enumeration
    print_colored("\n[*] Step 1: Subdomain Enumeration (Extended)", Fore.BLUE)
    passive_subdomains = passive_subdomain_enum(base_domain, project_dir)
    active_subdomains = active_subdomain_enum(base_domain, project_dir, wordlist_size='large')
    all_subdomains = list(set(passive_subdomains + active_subdomains))
    valid_subdomains = validate_subdomains(all_subdomains, project_dir)
    
    if not valid_subdomains:
        print_colored("[!] No valid subdomains found. Adding base domain for scanning.", Fore.YELLOW)
        valid_subdomains = [base_domain]
    
    # Run initial Nuclei scan
    run_nuclei_and_show(valid_subdomains, project_dir)
    
    # Comprehensive scanning with all modules
    
    # Step 2: Port Scanning
    print_colored("\n[*] Step 2: Port Scanning", Fore.BLUE)
    perform_port_scan(valid_subdomains, project_dir)
    
    # Step 3: Technology Detection
    print_colored("\n[*] Step 3: Technology Detection", Fore.BLUE)
    tech_results = detect_technologies(valid_subdomains, project_dir)
    
    # Step 4: Enhanced Endpoint Discovery
    print_colored("\n[*] Step 4: Enhanced Endpoint Discovery", Fore.BLUE)
    all_endpoints = extract_endpoints(valid_subdomains, project_dir)
    
    # Auto-learning wordlist
    print_colored("\n[*] Generating Smart Wordlist from Sources", Fore.BLUE)
    learned_wordlist = harvest_wordlist_from_sources(valid_subdomains, project_dir)
    
    # JavaScript Dependency Analysis
    print_colored("\n[*] Analyzing JavaScript Dependencies", Fore.BLUE)
    analyze_dependencies(valid_subdomains, project_dir)
    
    # Filter critical endpoints
    critical_endpoints = filter_endpoints(all_endpoints, project_dir)
    js_files = filter_js_files(all_endpoints, project_dir)
    
    # Advanced HTTP Analysis
    print_colored("\n[*] Running Advanced HTTP/Endpoint Analysis", Fore.BLUE)
    analyze_http_behaviors(all_endpoints, project_dir)
    
    # Auto Payload Generation and Testing
    print_colored("\n[*] Generating and Testing Smart Payloads", Fore.BLUE)
    generate_and_test_payloads(all_endpoints, learned_wordlist, project_dir)
    
    # Combinatorial Attacks
    print_colored("\n[*] Running Combinatorial and Multi-Vector Attacks", Fore.BLUE)
    run_combinatorial_attacks(all_endpoints, project_dir, learned_wordlist)
    
    # Extract Sensitive Information
    print_colored("\n[*] Extracting Sensitive Information from Endpoints", Fore.BLUE)
    extract_sensitive_info(all_endpoints, project_dir)
    
    # Additional Nuclei scan on all endpoints
    print_colored("\n[*] Running Nuclei on all Endpoints", Fore.BLUE)
    run_nuclei_and_show(all_endpoints, project_dir)
    
    # Enhanced source code endpoint analysis
    print_colored("\n[*] Running Enhanced Source Code Endpoint Analysis", Fore.BLUE)
    source_endpoints = analyze_source_code_endpoints(valid_subdomains, project_dir)
    all_endpoints.extend(source_endpoints)
    all_endpoints = list(set(all_endpoints))
    
    # Smart detection
    print_colored("\n[*] Running Smart Anomaly Detection", Fore.BLUE)
    run_smart_detection(all_endpoints, project_dir)
    
    # Step 5: Vulnerability Scanning
    print_colored("\n[*] Step 5: Comprehensive Vulnerability Scanning", Fore.BLUE)
    run_vulnerability_scan(critical_endpoints, project_dir)
    
    # AI-powered analysis if API key is set
    if os.environ.get("AI_API_KEY"):
        print_colored("\n[*] Running AI-Powered Vulnerability Analysis", Fore.BLUE)
        ai_analyze_endpoints(critical_endpoints[:20], project_dir)  # Limit to 20 to save API costs
    
    # Run open source integrations
    print_colored("\n[*] Running Open Source Tool Integrations", Fore.BLUE)
    run_open_source_integrations(critical_endpoints, project_dir, domain=base_domain)
    
    # Risk Analysis
    print_colored("\n[*] Running Intelligent Risk Scoring and Analysis", Fore.BLUE)
    run_risk_analysis(project_dir)
    
    # Login Panel Finding
    print_colored("\n[*] Finding Login Panels and Admin Interfaces", Fore.BLUE)
    login_panels = fuzz_login_panels(valid_subdomains, project_dir)
    
    # Collect vulnerability findings for the report
    vulns_dict = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    
    if os.path.exists(os.path.join(project_dir, "vulnerabilities/sqli/vulnerable_urls.txt")):
        with open(os.path.join(project_dir, "vulnerabilities/sqli/vulnerable_urls.txt")) as f:
            vulns_dict["critical"].extend([l.strip() for l in f.readlines()])
            
    if os.path.exists(os.path.join(project_dir, "vulnerabilities/xss/vulnerable_urls.txt")):
        with open(os.path.join(project_dir, "vulnerabilities/xss/vulnerable_urls.txt")) as f:
            vulns_dict["high"].extend([l.strip() for l in f.readlines()])
    
    # Generate rich summary report
    rich_summary(all_endpoints, vulns_dict, project_dir)
    
    # Step 6: OSINT Information Gathering
    print_colored("\n[*] Step 6: OSINT Information Gathering", Fore.BLUE)
    whois_data = whois_lookup(base_domain, project_dir)
    emails = email_finder(base_domain, project_dir)
    leaks = check_leaks(base_domain, project_dir)
    
    if login_panels:
        print_finding(f"Found {len(login_panels)} possible login/admin/dev panels. Saved as login_urls.txt.", risk="high")
    
    print_colored("\n[+] Reconnaissance completed successfully!", Fore.GREEN)
    return {
        'project_dir': project_dir,
        'wildcard': wildcard,
        'base_domain': base_domain,
        'subdomains': valid_subdomains,
        'endpoints': all_endpoints,
        'critical_endpoints': critical_endpoints,
        'js_files': js_files,
        'login_panels': login_panels
    }

def parse_arguments():
    parser = argparse.ArgumentParser(description="Web-Hunter - Advanced Security Reconnaissance Tool")
    parser.add_argument("--domain", help="Target domain to scan")
    parser.add_argument("--cidr", help="Target CIDR range to scan")
    parser.add_argument("--ip", help="Target IP address to scan")
    parser.add_argument("--wildcard", help="Wildcard domain to scan")
    parser.add_argument("--wildcard-list", help="File containing wildcard domains")
    parser.add_argument("--output", help="Output directory", default="results")
    parser.add_argument("--continue-from", help="Continue from existing scan directory")
    parser.add_argument("--load-endpoints", help="Load endpoints from file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--subdomain-enum", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--port-scan", action="store_true", help="Run port scanning")
    parser.add_argument("--tech-detect", action="store_true", help="Run technology detection")
    parser.add_argument("--endpoints", action="store_true", help="Run endpoint discovery")
    parser.add_argument("--vuln-scan", action="store_true", help="Run vulnerability scanning")
    parser.add_argument("--bypass", action="store_true", help="Run bypass techniques")
    parser.add_argument("--cloud-assets", action="store_true", help="Run cloud asset discovery")
    parser.add_argument("--osint", action="store_true", help="Run OSINT modules")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("--advanced", action="store_true", help="Run advanced analysis modules")
    parser.add_argument("--dependencies", action="store_true", help="Run dependency analysis")
    parser.add_argument("--autolearn", action="store_true", help="Run auto-learning modules")
    parser.add_argument("--version", action="store_true", help="Show version information")
    return parser.parse_args()

def show_version():
    """Show version and system information"""
    version = "2.0.0"
    edition = "Enterprise Edition"
    system_info = platform.system()
    system_release = platform.release()
    if system_info == "Linux":
        distro = platform.platform()
    elif system_info == "Windows":
        distro = f"Windows {platform.win32_ver()[0]}"
    else:
        distro = f"{system_info} {system_release}"
    
    print_colored("\nWeb-Hunter - Advanced Security Reconnaissance Tool", Fore.CYAN + Style.BRIGHT)
    print_colored("CAUTION: This tool is for ethical security testing only. Use responsibly and only on systems you have permission to test.", Fore.RED)
    print_colored(f"Version: {version} | Type: {edition}", Fore.GREEN)
    print_colored(f"Running on: {distro}", Fore.YELLOW)
    print_colored("Created by Nabaraj Lamichhane | GitHub: https://github.com/knobrazz\n", Fore.CYAN)

def interactive_menu():
    options = {
        "1": "Domain Reconnaissance",
        "2": "IP/CIDR Reconnaissance",
        "3": "Wildcard Domain Reconnaissance",
        "4": "Continue from Existing Scan",
        "5": "Load Endpoints and Scan",
        "6": "Version Information",
        "7": "Exit"
    }
    while True:
        print_colored("\n" + "╔" + "═" * 50 + "╗", Fore.MAGENTA)
        print_colored("║        Web-Hunter - Interactive Menu          ║", Fore.CYAN + Style.BRIGHT)
        print_colored("╚" + "═" * 50 + "╝", Fore.MAGENTA)
        for key, value in options.items():
            print_colored(f" [{Fore.CYAN}{key}{Fore.WHITE}] {value}", Fore.WHITE)
        choice = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter your choice (1-7): ")
        if choice == "1":
            domain = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter target domain: ")
            if validate_domain(domain):
                print_colored(f"\n[+] Setting up reconnaissance for {domain}", Fore.GREEN)
                
                # Ask for scan options
                print_colored("\nSelect scan type:", Fore.CYAN)
                print_colored("[1] Full scan (all modules - recommended)", Fore.WHITE)
                print_colored("[2] Quick scan (faster, less comprehensive)", Fore.WHITE)
                print_colored("[3] Custom scan (select modules)", Fore.WHITE)
                scan_type = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter scan type (1-3): ")
                
                if scan_type == "1":
                    run_domain_recon(domain, "results", {"all": True, "advanced": True})
                elif scan_type == "2":
                    run_domain_recon(domain, "results", {"subdomain_enum": True, "tech_detect": True, "endpoints": True, "vuln_scan": True})
                elif scan_type == "3":
                    # Custom scan options
                    options = {}
                    options["subdomain_enum"] = input("Include subdomain enumeration? (y/n): ").lower() == 'y'
                    options["port_scan"] = input("Include port scanning? (y/n): ").lower() == 'y'
                    options["tech_detect"] = input("Include technology detection? (y/n): ").lower() == 'y'
                    options["endpoints"] = input("Include endpoint discovery? (y/n): ").lower() == 'y'
                    options["vuln_scan"] = input("Include vulnerability scanning? (y/n): ").lower() == 'y'
                    options["osint"] = input("Include OSINT gathering? (y/n): ").lower() == 'y'
                    options["advanced"] = input("Include advanced analysis modules? (y/n): ").lower() == 'y'
                    options["dependencies"] = input("Include dependency analysis? (y/n): ").lower() == 'y'
                    options["autolearn"] = input("Include auto-learning modules? (y/n): ").lower() == 'y'
                    
                    run_domain_recon(domain, "results", options)
                break
            else:
                print_colored("[!] Invalid domain format. Please try again.", Fore.RED)
        elif choice == "2":
            ip_or_cidr = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter target IP or CIDR: ")
            if "/" in ip_or_cidr and parse_cidr(ip_or_cidr):
                print_colored(f"\n[+] Setting up reconnaissance for CIDR {ip_or_cidr}", Fore.GREEN)
                run_cidr_recon(ip_or_cidr, "results")
                break
            elif validate_ip(ip_or_cidr):
                print_colored(f"\n[+] Setting up reconnaissance for IP {ip_or_cidr}", Fore.GREEN)
                run_ip_recon(ip_or_cidr, "results")
                break
            else:
                print_colored("[!] Invalid IP or CIDR format. Please try again.", Fore.RED)
        elif choice == "3":
            wildcard = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter wildcard domain (e.g., *.example.com): ")
            if "*." in wildcard and validate_domain(wildcard.replace("*.", "")):
                print_colored(f"\n[+] Setting up reconnaissance for {wildcard}", Fore.GREEN)
                run_wildcard_recon(wildcard, "results")
                break
            else:
                print_colored("[!] Invalid wildcard format. Please try again.", Fore.RED)
        elif choice == "4":
            existing_scans = find_existing_scans("results")
            if not existing_scans:
                print_colored("[!] No existing scan directories found in 'results' folder", Fore.YELLOW)
                continue
            print_colored("\nFound existing scan directories:", Fore.CYAN)
            for i, scan_dir in enumerate(existing_scans):
                print_colored(f"[{i+1}] {scan_dir}", Fore.WHITE)
            scan_choice = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter the number of the scan to continue from (or 'c' to cancel): ")
            if scan_choice.lower() == 'c':
                continue
            try:
                scan_index = int(scan_choice) - 1
                if 0 <= scan_index < len(existing_scans):
                    scan_dir = existing_scans[scan_index]
                    continue_scan_from_directory(scan_dir)
                    break
                else:
                    print_colored("[!] Invalid selection. Please choose a valid scan number.", Fore.RED)
                    continue
            except ValueError:
                print_colored("[!] Please enter a valid number or 'c' to cancel.", Fore.RED)
                continue
        elif choice == "5":
            file_path = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter the path to the endpoints file: ")
            if os.path.exists(file_path):
                endpoints = load_targets_from_file(file_path)
                print_colored(f"\n[+] Loading {len(endpoints)} endpoints from file...", Fore.GREEN)
                continue_scan_from_directory("results")
                break
            else:
                print_colored("[!] File not found. Please try again.", Fore.RED)
        elif choice == "6":
            show_version()
        elif choice == "7":
            print_colored("\n[+] Exiting Web-Hunter...", Fore.GREEN)
            sys.exit(0)
    
def main():
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    args = parse_arguments()
    
    # Show version if requested
    if args.version:
        show_version()
        sys.exit(0)
        
    # Build options dictionary from arguments
    options = {
        "all": args.all,
        "subdomain_enum": args.subdomain_enum,
        "port_scan": args.port_scan,
        "tech_detect": args.tech_detect,
        "endpoints": args.endpoints,
        "vuln_scan": args.vuln_scan,
        "bypass": args.bypass,
        "cloud_assets": args.cloud_assets,
        "osint": args.osint,
        "advanced": args.advanced,
        "dependencies": args.dependencies,
        "autolearn": args.autolearn
    }
    
    # Process command-line arguments and run appropriate mode
    if args.domain:
        run_domain_recon(args.domain, args.output, options)
    elif args.ip:
        run_ip_recon(args.ip, args.output, options)
    elif args.cidr:
        run_cidr_recon(args.cidr, args.output, options)
    elif args.wildcard:
        run_wildcard_recon(args.wildcard, args.output, options)
    elif args.wildcard_list and os.path.exists(args.wildcard_list):
        wildcards = load_targets_from_file(args.wildcard_list)
        for wildcard in wildcards:
            if "*." in wildcard and validate_domain(wildcard.replace("*.", "")):
                run_wildcard_recon(wildcard, args.output, options)
    elif args.continue_from and os.path.exists(args.continue_from):
        continue_scan_from_directory(args.continue_from)
    elif args.all and args.wildcard:
        # Special case for --all with wildcard domains
        run_wildcard_recon(args.wildcard, args.output, {"all": True, "advanced": True})
    else:
        # No valid arguments provided, show interactive menu
        interactive_menu()

if __name__ == "__main__":
    main()
