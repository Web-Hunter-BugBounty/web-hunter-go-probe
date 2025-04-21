
#!/usr/bin/env python3
"""
Open Source Integrations Module: Integrates with various open source security tools and enhances scanning.
"""
import os
import re
import json
import subprocess
import shutil
import time
import requests
from colorama import Fore
from tqdm import tqdm
from .utils import print_colored, save_to_file, check_command, get_command_output

class OpenSourceIntegrator:
    """Class for integrating with open source security tools"""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.integrations_dir = os.path.join(output_dir, "integrations")
        
        if not os.path.exists(self.integrations_dir):
            os.makedirs(self.integrations_dir)
            
        # List of integrated tools and their detection functions
        self.tools = {
            "nuclei": self.check_nuclei,
            "wfuzz": self.check_wfuzz,
            "ffuf": self.check_ffuf,
            "sqlmap": self.check_sqlmap,
            "nikto": self.check_nikto,
            "wapiti": self.check_wapiti,
            "cmseek": self.check_cmseek,
            "waybackurls": self.check_waybackurls,
            "wafw00f": self.check_wafw00f,
            "subfinder": self.check_subfinder,
            "git-hound": self.check_githound,
            "amass": self.check_amass,
            "hakrawler": self.check_hakrawler,
            "photon": self.check_photon,
            "dnsgen": self.check_dnsgen,
            "massdns": self.check_massdns,
            "whatweb": self.check_whatweb,
            "httprobe": self.check_httprobe,
            "cors-scanner": self.check_cors_scanner,
            "jwt_tool": self.check_jwt_tool
        }
    
    def check_nuclei(self):
        """Check for Nuclei installation"""
        return check_command("nuclei -version")
    
    def check_wfuzz(self):
        """Check for WFuzz installation"""
        return check_command("wfuzz -h")
    
    def check_ffuf(self):
        """Check for FFuf installation"""
        return check_command("ffuf -V")
    
    def check_sqlmap(self):
        """Check for SQLMap installation"""
        return check_command("sqlmap --version")
    
    def check_nikto(self):
        """Check for Nikto installation"""
        return check_command("nikto -Version")
    
    def check_wapiti(self):
        """Check for Wapiti installation"""
        return check_command("wapiti --version")
    
    def check_cmseek(self):
        """Check for CMSeeK installation"""
        return os.path.exists("/usr/bin/cmseek") or os.path.exists("/usr/local/bin/cmseek")
    
    def check_waybackurls(self):
        """Check for waybackurls installation"""
        return check_command("waybackurls -h")
    
    def check_wafw00f(self):
        """Check for WAFW00F installation"""
        return check_command("wafw00f -h")
    
    def check_subfinder(self):
        """Check for Subfinder installation"""
        return check_command("subfinder -version")
    
    def check_githound(self):
        """Check for GitHound installation"""
        return check_command("git-hound -h")
    
    def check_amass(self):
        """Check for Amass installation"""
        return check_command("amass -version")
    
    def check_hakrawler(self):
        """Check for Hakrawler installation"""
        return check_command("hakrawler -h")
    
    def check_photon(self):
        """Check for Photon installation"""
        return check_command("photon -h")
    
    def check_dnsgen(self):
        """Check for DNSGen installation"""
        return check_command("dnsgen -h")
    
    def check_massdns(self):
        """Check for MassDNS installation"""
        return check_command("massdns --help")
    
    def check_whatweb(self):
        """Check for WhatWeb installation"""
        return check_command("whatweb --version")
    
    def check_httprobe(self):
        """Check for HTTProbe installation"""
        return check_command("httprobe -h")
    
    def check_cors_scanner(self):
        """Check for CORS Scanner installation"""
        return check_command("cors-scanner -h") or os.path.exists("tools/cors-scanner/cors_scan.py")
    
    def check_jwt_tool(self):
        """Check for JWT Tool installation"""
        return check_command("jwt_tool.py -h") or check_command("python3 -m jwt_tool -h")
    
    def detect_available_tools(self):
        """Detect which integrated tools are available on the system"""
        print_colored("[*] Detecting available security tools...", Fore.BLUE)
        
        available_tools = {}
        for tool_name, check_func in tqdm(self.tools.items(), desc="Checking tools"):
            available = check_func()
            available_tools[tool_name] = available
            status = "Available" if available else "Not found"
            color = Fore.GREEN if available else Fore.YELLOW
            print_colored(f"  - {tool_name}: {status}", color)
        
        return available_tools
    
    def run_nuclei_scan(self, targets, templates=None):
        """Run Nuclei scanner with specified templates"""
        if not self.tools["nuclei"]():
            print_colored("[!] Nuclei not found. Skipping scan.", Fore.YELLOW)
            return None
            
        print_colored("[*] Running Nuclei scan...", Fore.BLUE)
        
        # Prepare targets file
        targets_file = os.path.join(self.integrations_dir, "nuclei_targets.txt")
        save_to_file(targets, targets_file)
        
        # Prepare output file
        output_file = os.path.join(self.integrations_dir, "nuclei_results.json")
        
        # Build command
        cmd = ["nuclei", "-l", targets_file, "-o", output_file, "-silent"]
        
        # Add templates if specified
        if templates:
            cmd.extend(["-t", ",".join(templates)])
        else:
            # Use default templates for critical and high severity
            cmd.extend(["-severity", "critical,high,medium"])
        
        # Add JSON output
        cmd.append("-json")
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print_colored(f"[+] Nuclei scan completed. Results saved to {output_file}", Fore.GREEN)
            
            # Parse results
            if os.path.exists(output_file):
                results = []
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            results.append(json.loads(line))
                        except:
                            continue
                return results
            return None
        except subprocess.CalledProcessError as e:
            print_colored(f"[!] Error running Nuclei: {e}", Fore.RED)
            return None
    
    def run_wfuzz_scan(self, target, wordlist=None):
        """Run WFuzz for directory/file discovery"""
        if not self.tools["wfuzz"]():
            print_colored("[!] WFuzz not found. Skipping scan.", Fore.YELLOW)
            return None
            
        print_colored(f"[*] Running WFuzz on {target}...", Fore.BLUE)
        
        # Use default wordlist if none specified
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            if not os.path.exists(wordlist):
                wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
                if not os.path.exists(wordlist):
                    print_colored("[!] No suitable wordlist found for WFuzz. Skipping scan.", Fore.YELLOW)
                    return None
        
        # Prepare output file
        output_file = os.path.join(self.integrations_dir, "wfuzz_results.json")
        
        # Build command
        cmd = [
            "wfuzz", 
            "-c", 
            "--hc", "404",
            "-w", wordlist,
            "-f", output_file,
            "-o", "json",
            f"{target}/FUZZ"
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print_colored(f"[+] WFuzz scan completed. Results saved to {output_file}", Fore.GREEN)
            
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    try:
                        return json.load(f)
                    except:
                        return None
            return None
        except subprocess.CalledProcessError as e:
            print_colored(f"[!] Error running WFuzz: {e}", Fore.RED)
            return None
    
    def run_sqlmap_scan(self, target):
        """Run SQLMap for SQL injection vulnerabilities"""
        if not self.tools["sqlmap"]():
            print_colored("[!] SQLMap not found. Skipping scan.", Fore.YELLOW)
            return None
            
        print_colored(f"[*] Running SQLMap on {target}...", Fore.BLUE)
        
        # Prepare output directory
        output_dir = os.path.join(self.integrations_dir, "sqlmap")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Build command
        cmd = [
            "sqlmap", 
            "-u", target,
            "--batch", 
            "--level", "3",
            "--risk", "2",
            "--output-dir", output_dir,
            "--forms",
            "--crawl", "1"
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print_colored(f"[+] SQLMap scan completed. Results saved to {output_dir}", Fore.GREEN)
            
            # Check for results
            target_dir = os.path.join(output_dir, urlparse(target).netloc)
            if os.path.exists(target_dir):
                log_file = os.path.join(target_dir, "log")
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        log_content = f.read()
                        if "sqlmap identified" in log_content:
                            print_colored("[!] SQL injection vulnerabilities found!", Fore.RED)
                        return log_content
            return None
        except subprocess.CalledProcessError as e:
            print_colored(f"[!] Error running SQLMap: {e}", Fore.RED)
            return None
    
    def run_wafw00f_scan(self, targets):
        """Run WAFW00F to detect WAF presence"""
        if not self.tools["wafw00f"]():
            print_colored("[!] WAFW00F not found. Skipping scan.", Fore.YELLOW)
            return None
            
        print_colored("[*] Running WAFW00F to detect WAFs...", Fore.BLUE)
        
        # Prepare targets file
        targets_file = os.path.join(self.integrations_dir, "wafw00f_targets.txt")
        save_to_file(targets, targets_file)
        
        # Prepare output file
        output_file = os.path.join(self.integrations_dir, "wafw00f_results.json")
        
        # Build command
        cmd = [
            "wafw00f", 
            "-i", targets_file,
            "-o", output_file,
            "-f", "json"
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print_colored(f"[+] WAFW00F scan completed. Results saved to {output_file}", Fore.GREEN)
            
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    try:
                        return json.load(f)
                    except:
                        return None
            return None
        except subprocess.CalledProcessError as e:
            print_colored(f"[!] Error running WAFW00F: {e}", Fore.RED)
            return None
    
    def run_whatweb_scan(self, target):
        """Run WhatWeb for technology detection"""
        if not self.tools["whatweb"]():
            print_colored("[!] WhatWeb not found. Skipping scan.", Fore.YELLOW)
            return None
            
        print_colored(f"[*] Running WhatWeb on {target}...", Fore.BLUE)
        
        # Prepare output file
        output_file = os.path.join(self.integrations_dir, "whatweb_results.json")
        
        # Build command
        cmd = [
            "whatweb", 
            "-v",
            "--log-json", output_file,
            target
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print_colored(f"[+] WhatWeb scan completed. Results saved to {output_file}", Fore.GREEN)
            
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    try:
                        return json.load(f)
                    except:
                        return None
            return None
        except subprocess.CalledProcessError as e:
            print_colored(f"[!] Error running WhatWeb: {e}", Fore.RED)
            return None
    
    def run_jwt_tool(self, jwt_token):
        """Run JWT Tool to analyze JWT tokens"""
        if not self.tools["jwt_tool"]():
            print_colored("[!] JWT Tool not found. Skipping analysis.", Fore.YELLOW)
            return None
            
        print_colored(f"[*] Analyzing JWT token...", Fore.BLUE)
        
        # Prepare output file
        output_file = os.path.join(self.integrations_dir, "jwt_analysis.txt")
        
        # Build command - check which command works
        if check_command("jwt_tool.py -h"):
            cmd = ["jwt_tool.py", jwt_token, "-A"]
        else:
            cmd = ["python3", "-m", "jwt_tool", jwt_token, "-A"]
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            output = result.stdout
            
            # Save output
            with open(output_file, 'w') as f:
                f.write(output)
                
            print_colored(f"[+] JWT analysis completed. Results saved to {output_file}", Fore.GREEN)
            
            # Check for vulnerabilities
            if "Vulnerability" in output:
                print_colored("[!] JWT vulnerabilities detected!", Fore.RED)
            
            return output
        except subprocess.CalledProcessError as e:
            print_colored(f"[!] Error running JWT Tool: {e}", Fore.RED)
            return None
    
    def run_cmseek_scan(self, target):
        """Run CMSeeK for CMS detection and vulnerability scanning"""
        if not self.tools["cmseek"]():
            print_colored("[!] CMSeeK not found. Skipping scan.", Fore.YELLOW)
            return None
            
        print_colored(f"[*] Running CMSeeK on {target}...", Fore.BLUE)
        
        # Prepare output directory
        output_dir = os.path.join(self.integrations_dir, "cmseek")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Build command
        cmd = [
            "cmseek",
            "--batch",
            "-u", target,
            "--random-agent",
            "--follow-redirect"
        ]
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            output = result.stdout
            
            # Save output
            output_file = os.path.join(output_dir, "cmseek_results.txt")
            with open(output_file, 'w') as f:
                f.write(output)
                
            print_colored(f"[+] CMSeeK scan completed. Results saved to {output_file}", Fore.GREEN)
            
            # Check for CMS detection
            if "CMS Detected" in output:
                print_colored("[+] CMS detected by CMSeeK!", Fore.GREEN)
            
            return output
        except subprocess.CalledProcessError as e:
            print_colored(f"[!] Error running CMSeeK: {e}", Fore.RED)
            return None
    
    def run_integrations(self, targets, domain=None):
        """Run various integrations based on available tools"""
        print_colored("[*] Running open source tool integrations...", Fore.MAGENTA)
        
        # First, detect available tools
        available_tools = self.detect_available_tools()
        
        results = {
            "available_tools": available_tools,
            "scan_results": {}
        }
        
        # Run nuclei for vulnerability scanning
        if available_tools["nuclei"]:
            results["scan_results"]["nuclei"] = self.run_nuclei_scan(targets[:50])  # Limit to 50 targets
        
        # Run WhatWeb on the main domain
        if domain and available_tools["whatweb"]:
            results["scan_results"]["whatweb"] = self.run_whatweb_scan(domain)
        
        # Run WAFW00F for WAF detection
        if available_tools["wafw00f"]:
            results["scan_results"]["wafw00f"] = self.run_wafw00f_scan(targets[:20])  # Limit to 20 targets
        
        # If JWT Tool is available, look for JWT tokens in targets
        if available_tools["jwt_tool"]:
            jwt_found = False
            for target in targets[:10]:  # Check first 10 targets
                try:
                    resp = requests.get(target, timeout=5, verify=False)
                    
                    # Check Authorization header
                    auth_header = resp.headers.get("Authorization", "")
                    if auth_header.startswith("Bearer "):
                        jwt_token = auth_header.split(" ")[1]
                        if "." in jwt_token and len(jwt_token) > 20:
                            print_colored(f"[+] Found JWT token in Authorization header: {target}", Fore.GREEN)
                            results["scan_results"]["jwt_tool"] = self.run_jwt_tool(jwt_token)
                            jwt_found = True
                            break
                            
                    # Check cookies
                    for cookie in resp.cookies:
                        if "token" in cookie.name.lower() or "jwt" in cookie.name.lower() or "auth" in cookie.name.lower():
                            if "." in cookie.value and len(cookie.value) > 20:
                                print_colored(f"[+] Found JWT token in cookie: {target}", Fore.GREEN)
                                results["scan_results"]["jwt_tool"] = self.run_jwt_tool(cookie.value)
                                jwt_found = True
                                break
                                
                    if jwt_found:
                        break
                        
                except:
                    continue
        
        # Save summary of all scans
        summary_file = os.path.join(self.integrations_dir, "integrations_summary.json")
        with open(summary_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        print_colored(f"[+] Open source integrations complete. Summary saved to {summary_file}", Fore.GREEN)
        
        return results

def run_open_source_integrations(targets, output_dir, domain=None):
    """Run open source integrations with the specified targets"""
    integrator = OpenSourceIntegrator(output_dir)
    return integrator.run_integrations(targets, domain)
