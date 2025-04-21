
#!/usr/bin/env python3
"""
Technology detection module for Web-Hunter
"""

import os
import json
import subprocess
import concurrent.futures
from colorama import Fore, Style
from .utils import print_colored, show_progress, save_to_file, check_command, get_command_output

def detect_technologies(targets, output_dir):
    """Detect technologies used by targets"""
    print_colored("[*] Starting technology detection...", Fore.CYAN)
    
    tech_dir = os.path.join(output_dir, "technologies")
    if not os.path.exists(tech_dir):
        os.makedirs(tech_dir)
    
    # Check for tools
    tools = {
        "whatweb": check_command("whatweb"),
        "wappalyzer": check_command("wappalyzer"),
        "httpx": check_command("httpx")
    }
    
    if not any(tools.values()):
        print_colored("[!] No technology detection tools found. Using basic detection...", Fore.YELLOW)
    
    results = {}
    
    # Function to normalize URLs
    def normalize_url(url):
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url
    
    # Create a normalized list of targets
    normalized_targets = [normalize_url(target) for target in targets]
    
    # Progress bar
    progress = show_progress(len(normalized_targets), "Technology detection")
    
    def detect_tech_for_target(target):
        """Detect technologies for a single target"""
        target_name = target.replace('https://', '').replace('http://', '').replace('/', '_')
        target_results = {}
        
        # Run whatweb
        if tools.get("whatweb"):
            whatweb_output = os.path.join(tech_dir, f"{target_name}_whatweb.json")
            whatweb_cmd = f"whatweb -a 3 --log-json={whatweb_output} {target}"
            
            try:
                subprocess.run(whatweb_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Parse whatweb output
                with open(whatweb_output, 'r') as f:
                    whatweb_data = json.load(f)
                    
                target_results["whatweb"] = whatweb_data
            
            except Exception as e:
                print_colored(f"[!] Error running whatweb on {target}: {str(e)}", Fore.RED)
        
        # Run wappalyzer CLI if available
        if tools.get("wappalyzer"):
            wappalyzer_output = os.path.join(tech_dir, f"{target_name}_wappalyzer.json")
            wappalyzer_cmd = f"wappalyzer {target} -P -o json > {wappalyzer_output}"
            
            try:
                subprocess.run(wappalyzer_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Parse wappalyzer output
                with open(wappalyzer_output, 'r') as f:
                    wappalyzer_data = json.load(f)
                    
                target_results["wappalyzer"] = wappalyzer_data
            
            except Exception as e:
                print_colored(f"[!] Error running wappalyzer on {target}: {str(e)}", Fore.RED)
        
        # Use httpx tech detection
        if tools.get("httpx"):
            httpx_output = os.path.join(tech_dir, f"{target_name}_httpx.txt")
            httpx_cmd = f"echo {target} | httpx -tech-detect -o {httpx_output}"
            
            try:
                subprocess.run(httpx_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Parse httpx output
                with open(httpx_output, 'r') as f:
                    httpx_data = f.read().strip()
                    
                target_results["httpx"] = httpx_data
            
            except Exception as e:
                print_colored(f"[!] Error running httpx on {target}: {str(e)}", Fore.RED)
        
        # If no tools are available, use basic detection
        if not any(tools.values()):
            import requests
            from bs4 import BeautifulSoup
            
            basic_output = os.path.join(tech_dir, f"{target_name}_basic.txt")
            
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                response = requests.get(target, headers=headers, timeout=10, verify=False)
                
                # Check headers
                server = response.headers.get('Server', '')
                powered_by = response.headers.get('X-Powered-By', '')
                
                # Check HTML
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for common JS frameworks
                js_frameworks = []
                for script in soup.find_all('script'):
                    src = script.get('src', '')
                    if 'jquery' in src.lower():
                        js_frameworks.append('jQuery')
                    elif 'react' in src.lower():
                        js_frameworks.append('React')
                    elif 'vue' in src.lower():
                        js_frameworks.append('Vue.js')
                    elif 'angular' in src.lower():
                        js_frameworks.append('Angular')
                
                # Check for CMS indicators
                cms = None
                if soup.find_all(attrs={"name": "generator"}):
                    cms_meta = soup.find(attrs={"name": "generator"})
                    if cms_meta:
                        cms = cms_meta.get('content', '')
                
                # WordPress indicators
                wp_content = soup.find_all(href=lambda href: href and '/wp-content/' in href)
                if wp_content:
                    cms = 'WordPress'
                
                # Save basic detection results
                with open(basic_output, 'w') as f:
                    f.write(f"Target: {target}\n")
                    f.write(f"Server: {server}\n")
                    f.write(f"X-Powered-By: {powered_by}\n")
                    f.write(f"CMS: {cms}\n")
                    f.write(f"JS Frameworks: {', '.join(js_frameworks)}\n")
                
                target_results["basic"] = {
                    "server": server,
                    "powered_by": powered_by,
                    "cms": cms,
                    "js_frameworks": js_frameworks
                }
            
            except Exception as e:
                print_colored(f"[!] Error during basic detection on {target}: {str(e)}", Fore.RED)
        
        progress.update(1)
        return (target, target_results)
    
    # Run detection in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        detection_results = list(executor.map(detect_tech_for_target, normalized_targets))
    
    progress.close()
    
    # Process and save results
    for target, target_results in detection_results:
        results[target] = target_results
    
    # Save summary report
    summary_file = os.path.join(tech_dir, "tech_detection_summary.txt")
    with open(summary_file, 'w') as f:
        f.write("Technology Detection Summary\n")
        f.write("=========================\n\n")
        
        for target, techs in results.items():
            f.write(f"Target: {target}\n")
            f.write("-" * 50 + "\n")
            
            if "whatweb" in techs:
                f.write("WhatWeb Results:\n")
                for item in techs["whatweb"]:
                    f.write(f"  - {item.get('plugin', 'Unknown')}: {item.get('version', 'Unknown version')}\n")
            
            if "wappalyzer" in techs:
                f.write("Wappalyzer Results:\n")
                for tech, details in techs["wappalyzer"].items():
                    versions = details.get("versions", ["Unknown version"])
                    f.write(f"  - {tech}: {', '.join(versions)}\n")
            
            if "httpx" in techs:
                f.write("HTTPX Results:\n")
                f.write(f"  {techs['httpx']}\n")
            
            if "basic" in techs:
                f.write("Basic Detection Results:\n")
                f.write(f"  - Server: {techs['basic']['server']}\n")
                f.write(f"  - Powered By: {techs['basic']['powered_by']}\n")
                f.write(f"  - CMS: {techs['basic']['cms']}\n")
                f.write(f"  - JS Frameworks: {', '.join(techs['basic']['js_frameworks'])}\n")
            
            f.write("\n")
    
    print_colored(f"[+] Technology detection completed for {len(targets)} targets", Fore.GREEN)
    print_colored(f"[+] Results saved to {tech_dir}", Fore.GREEN)
