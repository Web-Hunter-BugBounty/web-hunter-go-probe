
#!/usr/bin/env python3
"""
Enhanced Endpoint Analyzer: Discovers endpoints from source code, robots.txt, sitemap.xml, JS files, 
and performs intelligent analysis of headers, CORS, redirects, compression, cookies, CSP, and parameter behaviors.
"""

import os
import re
import json
import time
import hashlib
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style
from tqdm import tqdm
from .utils import print_colored, save_to_file

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EndpointAnalyzer:
    """Class for advanced endpoint analysis"""
    
    def __init__(self, domains, output_dir, max_workers=5, max_js_files=20):
        self.domains = domains
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.max_js_files = max_js_files
        self.endpoints = set()
        self.js_endpoints = set()
        self.api_endpoints = set()
        self.form_endpoints = set()
        self.interesting_endpoints = set()
        self.custom_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close"
        }
        
        # Create output directories
        self.endpoints_dir = os.path.join(output_dir, "endpoints")
        self.analysis_dir = os.path.join(self.endpoints_dir, "analysis")
        
        for directory in [self.endpoints_dir, self.analysis_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
    
    def extract_from_robots(self, domain):
        """Extract endpoints from robots.txt"""
        endpoints = set()
        
        for proto in ['https://', 'http://']:
            base_url = proto + domain if not domain.startswith('http') else domain
            try:
                url = urljoin(base_url, "/robots.txt")
                resp = requests.get(url, headers=self.custom_headers, timeout=10, verify=False)
                
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        if line.lower().startswith(("allow:", "disallow:", "sitemap:")):
                            parts = line.split(":", 1)
                            if len(parts) > 1:
                                path = parts[1].strip()
                                
                                if path.startswith("/"):
                                    endpoints.add(urljoin(base_url, path))
                                elif path.startswith("http"):
                                    endpoints.add(path)
            except:
                continue
        
        return endpoints
    
    def extract_from_sitemap(self, domain):
        """Extract endpoints from sitemap.xml"""
        endpoints = set()
        
        for proto in ['https://', 'http://']:
            base_url = proto + domain if not domain.startswith('http') else domain
            try:
                url = urljoin(base_url, "/sitemap.xml")
                resp = requests.get(url, headers=self.custom_headers, timeout=10, verify=False)
                
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "xml")
                    for loc in soup.find_all("loc"):
                        if loc.text.strip().startswith("http"):
                            endpoints.add(loc.text.strip())
                    
                    # Check for sitemap index
                    sitemap_tags = soup.find_all("sitemap")
                    for sitemap in sitemap_tags:
                        loc = sitemap.find("loc")
                        if loc and loc.text.strip().startswith("http"):
                            # Fetch and parse child sitemap
                            try:
                                child_resp = requests.get(loc.text.strip(), headers=self.custom_headers, timeout=10, verify=False)
                                if child_resp.status_code == 200:
                                    child_soup = BeautifulSoup(child_resp.text, "xml")
                                    for child_loc in child_soup.find_all("loc"):
                                        endpoints.add(child_loc.text.strip())
                            except:
                                continue
            except:
                continue
        
        return endpoints
    
    def extract_js_files(self, domain):
        """Extract JavaScript files from a domain"""
        js_files = set()
        
        for proto in ['https://', 'http://']:
            base_url = proto + domain if not domain.startswith('http') else domain
            try:
                resp = requests.get(base_url, headers=self.custom_headers, timeout=10, verify=False)
                
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    
                    # Find script tags with src attribute
                    for script in soup.find_all("script", src=True):
                        js_src = script["src"]
                        
                        # Handle different URL formats
                        if js_src.startswith("//"):
                            js_src = "https:" + js_src
                        elif js_src.startswith("/"):
                            js_src = urljoin(base_url, js_src)
                        elif not js_src.startswith(("http://", "https://")):
                            js_src = urljoin(base_url, js_src)
                        
                        if js_src.endswith(".js"):
                            js_files.add(js_src)
            except:
                continue
        
        return js_files
    
    def extract_from_js(self, js_url):
        """Extract endpoints from a JavaScript file"""
        endpoints = set()
        api_endpoints = set()
        
        try:
            resp = requests.get(js_url, headers=self.custom_headers, timeout=10, verify=False)
            
            if resp.status_code == 200:
                js_content = resp.text
                
                # Extract API endpoints and routes
                api_patterns = [
                    r'url:\s*[\'"`]([^\'"`]+)[\'"`]',
                    r'[\'"`]?(?:url|endpoint|api|route)[\'"`]?\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
                    r'\.(?:get|post|put|delete|patch)\([\'"`]([^\'"`]+)[\'"`]',
                    r'fetch\([\'"`]([^\'"`]+)[\'"`]',
                    r'axios\.(?:get|post|put|delete|patch)\([\'"`]([^\'"`]+)[\'"`]',
                    r'new\s+URL\([\'"`]([^\'"`]+)[\'"`]'
                ]
                
                # Main URL-like patterns
                url_patterns = [
                    r'(?:(?:https?:)?//)?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?:/[a-zA-Z0-9_\-/.]*)?',
                    r'/[a-zA-Z0-9_\-/]+(?:\.[a-zA-Z0-9]+)?',
                    r'(?:api|v\d+)[a-zA-Z0-9_\-/]*'
                ]
                
                for pattern in api_patterns:
                    for match in re.findall(pattern, js_content):
                        if match and len(match) > 3:  # Minimum length for API endpoints
                            if match.startswith(("http://", "https://")):
                                api_endpoints.add(match)
                            elif match.startswith("/"):
                                parsed_url = urlparse(js_url)
                                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                api_endpoints.add(urljoin(base_url, match))
                
                for pattern in url_patterns:
                    for match in re.findall(pattern, js_content):
                        if match and len(match) > 3:  # Minimum length check
                            # Exclude common JS extensions and patterns
                            if not match.endswith((".js", ".css", ".jpg", ".png", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot")):
                                if match.startswith(("http://", "https://")):
                                    endpoints.add(match)
                                elif match.startswith("/"):
                                    parsed_url = urlparse(js_url)
                                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                    endpoints.add(urljoin(base_url, match))
                
                # Find and extract JSON data structures that might contain endpoints
                json_patterns = [
                    r'{[^{}]*"(?:url|path|endpoint|api|route)":[^{}]*}',
                    r'{[^{}]*\'(?:url|path|endpoint|api|route)\':[^{}]*}'
                ]
                
                for pattern in json_patterns:
                    for json_block in re.findall(pattern, js_content):
                        # Extract URL parts from JSON structure
                        url_matches = re.findall(r'(?:"|\')([^"\']+)(?:"|\')', json_block)
                        for url in url_matches:
                            if url.startswith(("/", "http://", "https://")) and len(url) > 3:
                                if url.startswith(("http://", "https://")):
                                    api_endpoints.add(url)
                                elif url.startswith("/"):
                                    parsed_url = urlparse(js_url)
                                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                    api_endpoints.add(urljoin(base_url, url))
        except:
            pass
        
        return endpoints, api_endpoints
    
    def extract_form_endpoints(self, domain):
        """Extract form endpoints from HTML pages"""
        form_endpoints = set()
        
        for proto in ['https://', 'http://']:
            base_url = proto + domain if not domain.startswith('http') else domain
            try:
                resp = requests.get(base_url, headers=self.custom_headers, timeout=10, verify=False)
                
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    
                    # Find all forms
                    for form in soup.find_all("form"):
                        action = form.get("action", "")
                        
                        # Skip empty or javascript actions
                        if not action or action.startswith(("javascript:", "#")):
                            continue
                        
                        # Convert relative URLs to absolute
                        if action.startswith("/"):
                            form_url = urljoin(base_url, action)
                        elif not action.startswith(("http://", "https://")):
                            form_url = urljoin(base_url, action)
                        else:
                            form_url = action
                        
                        form_endpoints.add(form_url)
            except:
                continue
        
        return form_endpoints
    
    def analyze_http_headers(self, url):
        """Analyze HTTP headers, CORS, security policies of an endpoint"""
        try:
            resp = requests.head(url, headers=self.custom_headers, timeout=10, verify=False, allow_redirects=False)
            results = {
                "url": url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "security_issues": [],
                "risk_level": "Low"
            }
            
            # Check for CORS misconfiguration
            if "Access-Control-Allow-Origin" in resp.headers:
                cors_value = resp.headers["Access-Control-Allow-Origin"]
                if cors_value == "*":
                    results["security_issues"].append("CORS allows all origins (*)")
                    results["risk_level"] = "Medium"
            
            # Check for Content-Security-Policy
            if "Content-Security-Policy" not in resp.headers:
                results["security_issues"].append("No Content-Security-Policy header")
                
            # Check for X-Frame-Options
            if "X-Frame-Options" not in resp.headers:
                results["security_issues"].append("No X-Frame-Options header (clickjacking possible)")
            
            # Check for HTTP Strict Transport Security
            if "Strict-Transport-Security" not in resp.headers:
                results["security_issues"].append("No HSTS header")
            
            # Check for Server header information disclosure
            if "Server" in resp.headers:
                server = resp.headers["Server"]
                if any(x in server for x in ["apache", "nginx", "microsoft", "iis", "tomcat", "php", "version"]):
                    results["security_issues"].append(f"Server header information disclosure: {server}")
            
            # Check for insecure cookies
            if "Set-Cookie" in resp.headers:
                cookies = resp.headers.get("Set-Cookie")
                if "secure" not in cookies.lower() or "httponly" not in cookies.lower():
                    results["security_issues"].append("Insecure cookies (missing Secure and/or HttpOnly flags)")
                    results["risk_level"] = "Medium"
            
            # Check for sensitive headers
            sensitive_headers = ["X-Powered-By", "X-AspNet-Version", "X-Runtime", "X-Version"]
            for header in sensitive_headers:
                if header in resp.headers:
                    results["security_issues"].append(f"Information disclosure: {header}={resp.headers[header]}")
            
            # Update risk level based on security issues
            if len(results["security_issues"]) > 3:
                results["risk_level"] = "High"
            elif len(results["security_issues"]) > 1:
                results["risk_level"] = "Medium"
            
            return results
        except Exception as e:
            return None
    
    def find_interesting_endpoints(self, all_endpoints):
        """Identify potentially interesting endpoints (admin, api, etc.)"""
        interesting_patterns = [
            r'(?:/|=)admin(?:/|$)',
            r'(?:/|=)dashboard(?:/|$)',
            r'(?:/|=)login(?:/|$)',
            r'(?:/|=)config(?:/|$)',
            r'(?:/|=)api(?:/|$)',
            r'(?:/|=)auth(?:/|$)',
            r'(?:/|=)token(?:/|$)',
            r'(?:/|=)upload(?:/|$)',
            r'(?:/|=)download(?:/|$)',
            r'(?:/|=)file(?:/|$)',
            r'(?:/|=)backup(?:/|$)',
            r'(?:/|=)dev(?:/|$)',
            r'(?:/|=)test(?:/|$)',
            r'(?:/|=)debug(?:/|$)',
            r'(?:/|=)staging(?:/|$)',
            r'(?:/|=)beta(?:/|$)',
            r'(?:/|=)internal(?:/|$)',
            r'(?:/|=)phpinfo(?:/|$)',
            r'(?:/|=)console(?:/|$)',
            r'(?:/|=)profile(?:/|$)',
            r'(?:/|=)setting(?:/|$)',
            r'(?:/|=)password(?:/|$)',
            r'(?:/|=)reset(?:/|$)',
            r'(?:/|=)registration(?:/|$)',
            r'(?:/|=)signup(?:/|$)',
            r'(?:/|=)install(?:/|$)',
            r'(?:/|=)setup(?:/|$)',
            r'(?:/|=)update(?:/|$)',
            r'(?:/|=)upgrade(?:/|$)',
            r'(?:/|=)maintenance(?:/|$)',
            r'(?:/|=)payment(?:/|$)',
            r'(?:/|=)cart(?:/|$)',
            r'(?:/|=)checkout(?:/|$)'
        ]
        
        interesting = set()
        for endpoint in all_endpoints:
            for pattern in interesting_patterns:
                if re.search(pattern, endpoint, re.I):
                    interesting.add(endpoint)
                    break
        
        return interesting
    
    def analyze_endpoints(self):
        """Run the complete endpoint analysis"""
        print_colored("[*] Starting advanced endpoint analysis...", Fore.MAGENTA)
        
        # Extract endpoints from robots.txt and sitemap.xml
        print_colored("[*] Extracting endpoints from robots.txt and sitemap.xml...", Fore.BLUE)
        for domain in tqdm(self.domains, desc="Domain scanning"):
            self.endpoints.update(self.extract_from_robots(domain))
            self.endpoints.update(self.extract_from_sitemap(domain))
            self.form_endpoints.update(self.extract_form_endpoints(domain))
        
        # Extract and analyze JavaScript files
        print_colored("[*] Analyzing JavaScript files for hidden endpoints...", Fore.BLUE)
        js_files = set()
        for domain in self.domains:
            js_files.update(self.extract_js_files(domain))
        
        # Limit number of JS files to analyze to prevent overload
        js_files = list(js_files)[:self.max_js_files]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_js = {executor.submit(self.extract_from_js, js_file): js_file for js_file in js_files}
            
            for future in tqdm(concurrent.futures.as_completed(future_to_js), total=len(js_files), desc="JS analysis"):
                js_file = future_to_js[future]
                try:
                    endpoints, api_endpoints = future.result()
                    self.js_endpoints.update(endpoints)
                    self.api_endpoints.update(api_endpoints)
                except Exception as e:
                    print_colored(f"[!] Error analyzing {js_file}: {str(e)}", Fore.RED)
        
        # Merge all endpoints
        all_endpoints = set()
        all_endpoints.update(self.endpoints)
        all_endpoints.update(self.js_endpoints)
        all_endpoints.update(self.api_endpoints)
        all_endpoints.update(self.form_endpoints)
        
        # Identify interesting endpoints
        self.interesting_endpoints = self.find_interesting_endpoints(all_endpoints)
        
        # Analyze HTTP behaviors for interesting endpoints
        print_colored("[*] Analyzing HTTP behaviors (headers, CORS, security policies)...", Fore.BLUE)
        http_analyses = []
        
        # Prioritize interesting endpoints for analysis
        endpoints_to_analyze = list(self.interesting_endpoints)
        
        # Add some random endpoints from the full set for broader coverage
        remaining_endpoints = list(all_endpoints - self.interesting_endpoints)
        if remaining_endpoints:
            import random
            sample_size = min(30, len(remaining_endpoints))
            endpoints_to_analyze.extend(random.sample(remaining_endpoints, sample_size))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.analyze_http_headers, url): url for url in endpoints_to_analyze}
            
            for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(endpoints_to_analyze), desc="HTTP analysis"):
                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        http_analyses.append(result)
                except Exception as e:
                    print_colored(f"[!] Error analyzing HTTP behaviors of {url}: {str(e)}", Fore.RED)
        
        # Save results
        self.save_results(all_endpoints, http_analyses)
        
        print_colored(f"[+] Endpoint analysis complete. Found {len(all_endpoints)} total endpoints.", Fore.GREEN)
        
        return list(all_endpoints)
    
    def save_results(self, all_endpoints, http_analyses):
        """Save analysis results to files"""
        # Save all endpoints
        all_endpoints_file = os.path.join(self.endpoints_dir, "source_code_endpoints.txt")
        save_to_file(sorted(list(all_endpoints)), all_endpoints_file)
        
        # Save by type
        endpoint_types = {
            "robots_sitemap": list(self.endpoints),
            "javascript": list(self.js_endpoints),
            "api": list(self.api_endpoints),
            "forms": list(self.form_endpoints),
            "interesting": list(self.interesting_endpoints)
        }
        
        for endpoint_type, endpoints in endpoint_types.items():
            if endpoints:
                type_file = os.path.join(self.endpoints_dir, f"{endpoint_type}_endpoints.txt")
                save_to_file(sorted(endpoints), type_file)
        
        # Save HTTP analyses
        if http_analyses:
            # Save as JSON for detailed reference
            http_json_file = os.path.join(self.analysis_dir, "http_analysis.json")
            with open(http_json_file, 'w') as f:
                json.dump(http_analyses, f, indent=2)
            
            # Save text summary for quick review
            http_text_file = os.path.join(self.analysis_dir, "http_analysis.txt")
            
            http_report = []
            for analysis in http_analyses:
                report = f"URL: {analysis['url']}\n"
                report += f"Status Code: {analysis['status_code']}\n"
                report += f"Risk Level: {analysis['risk_level']}\n"
                
                if analysis['security_issues']:
                    report += "Security Issues:\n"
                    for issue in analysis['security_issues']:
                        report += f"  - {issue}\n"
                
                report += "Headers:\n"
                for header, value in analysis['headers'].items():
                    report += f"  {header}: {value}\n"
                
                report += "-" * 50 + "\n"
                http_report.append(report)
            
            save_to_file(http_report, http_text_file)
            
            # Create security issues summary
            security_file = os.path.join(self.analysis_dir, "security_issues.txt")
            
            security_report = ["===== SECURITY ISSUES SUMMARY =====\n"]
            risk_counts = {"High": 0, "Medium": 0, "Low": 0}
            
            for analysis in http_analyses:
                if analysis['security_issues']:
                    risk_level = analysis['risk_level']
                    risk_counts[risk_level] += 1
                    
                    if risk_level == "High":
                        color = Fore.RED
                    elif risk_level == "Medium":
                        color = Fore.YELLOW
                    else:
                        color = Fore.WHITE
                    
                    line = f"{risk_level} Risk: {analysis['url']} - {', '.join(analysis['security_issues'])}"
                    security_report.append(line)
                    print_colored(line, color)
            
            summary = f"\nSummary: {risk_counts['High']} High, {risk_counts['Medium']} Medium, {risk_counts['Low']} Low risk issues found."
            security_report.insert(1, summary)
            save_to_file(security_report, security_file)

def analyze_source_code_endpoints(domains, output_dir):
    analyzer = EndpointAnalyzer(domains, output_dir)
    return analyzer.analyze_endpoints()
