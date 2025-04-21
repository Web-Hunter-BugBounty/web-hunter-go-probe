
#!/usr/bin/env python3
"""
Smart Detection Module: Uses machine learning and pattern recognition techniques to find vulnerabilities
"""
import os
import re
import json
import random
import hashlib
import difflib
import requests
import numpy as np
from urllib.parse import urlparse, parse_qs
from colorama import Fore
from .utils import print_colored, save_to_file

class SmartDetector:
    """Class for smart vulnerability detection"""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.smart_dir = os.path.join(output_dir, "smart_detection")
        
        if not os.path.exists(self.smart_dir):
            os.makedirs(self.smart_dir)
            
        # Response similarity threshold (lower = more sensitive)
        self.similarity_threshold = 0.8
        
        # Learning data
        self.response_patterns = {}
        self.error_signatures = self.load_error_signatures()
    
    def load_error_signatures(self):
        """Load error signatures from file or use defaults"""
        signatures_file = os.path.join("data", "error_signatures.json")
        
        if os.path.exists(signatures_file):
            try:
                with open(signatures_file, 'r') as f:
                    return json.load(f)
            except:
                pass
                
        # Default error signatures
        return {
            "sql": [
                "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite3", 
                "syntax error", "unclosed quotation", "not a valid MySQL", 
                "native exception", "ODBC Driver", "error in your SQL syntax"
            ],
            "php": [
                "Parse error", "Warning: include", "Fatal error", "Call to undefined function",
                "Uncaught exception", "Stack trace", "Fatal error:"
            ],
            "asp": [
                "Microsoft OLE DB Provider", "error '800a", "Microsoft VBScript",
                "ASP.NET_SessionId", "ASP.NET is configured to show verbose error messages"
            ],
            "java": [
                "java.lang.", "java.sql.", "javax.servlet.", "Caused by:", "ROOT::", 
                "org.apache.jasper", "Servlet.service() for servlet"
            ],
            "python": [
                "Traceback (most recent call last)", "File ", "line ", "python", 
                "ModuleNotFoundError", "ImportError", "SyntaxError"
            ],
            "nodejs": [
                "ReferenceError:", "SyntaxError:", "TypeError:", "Error:", 
                "node.js", "npm", "Module not found"
            ]
        }
    
    def compute_response_similarity(self, resp1, resp2):
        """Compute similarity between two responses"""
        # Extract relevant parts for comparison
        content1 = resp1.text[:5000]  # Use the first 5000 chars for efficiency
        content2 = resp2.text[:5000]
        
        # Use difflib for similarity calculation
        similarity = difflib.SequenceMatcher(None, content1, content2).ratio()
        
        return similarity
    
    def analyze_response_for_errors(self, response):
        """Analyze response for common error signatures"""
        findings = []
        
        # Check for standard HTTP error codes
        if 400 <= response.status_code < 600:
            findings.append({
                "type": "http_error",
                "details": f"HTTP error {response.status_code}",
                "confidence": "medium"
            })
        
        # Check response content for error signatures
        content = response.text.lower()
        for error_type, signatures in self.error_signatures.items():
            for signature in signatures:
                if signature.lower() in content:
                    findings.append({
                        "type": f"{error_type}_error",
                        "details": f"Found '{signature}' in response",
                        "confidence": "high"
                    })
        
        # Check for common sensitive data exposures
        sensitive_patterns = [
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email_address"),
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ip_address"),
            (r"password[\'\"]?\s*[:=]\s*[\'\"]([^\'\"]+)", "password"),
            (r"api[_\-]?key[\'\"]?\s*[:=]\s*[\'\"]([^\'\"]+)", "api_key"),
            (r"secret[\'\"]?\s*[:=]\s*[\'\"]([^\'\"]+)", "secret"),
            (r"token[\'\"]?\s*[:=]\s*[\'\"]([^\'\"]+)", "token")
        ]
        
        for pattern, data_type in sensitive_patterns:
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    "type": "data_exposure",
                    "details": f"Possible {data_type} exposure",
                    "matches": matches[:5],  # Limit to first 5 matches
                    "confidence": "high"
                })
        
        return findings
    
    def generate_parameter_mutations(self, url, num_mutations=3):
        """Generate mutations of URL parameters for fuzzing"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return []
            
        mutations = []
        
        # Create a copy of the original parameters
        for _ in range(num_mutations):
            mutated_params = params.copy()
            
            # Randomly select a parameter to mutate
            if mutated_params:
                param = random.choice(list(mutated_params.keys()))
                
                # Apply a random mutation strategy
                strategy = random.choice(["modify", "remove", "duplicate"])
                
                if strategy == "modify":
                    # Modify the parameter value
                    mutations.append({
                        "original": url,
                        "param": param,
                        "strategy": "modify",
                        "new_value": "MODIFIED" + mutated_params[param][0]
                    })
                    
                elif strategy == "remove":
                    # Remove the parameter
                    mutations.append({
                        "original": url,
                        "param": param,
                        "strategy": "remove",
                        "new_value": None
                    })
                    
                elif strategy == "duplicate":
                    # Duplicate the parameter with a different value
                    mutations.append({
                        "original": url,
                        "param": param,
                        "strategy": "duplicate",
                        "new_value": "DUPLICATE" + mutated_params[param][0]
                    })
        
        return mutations
    
    def apply_mutation(self, url, mutation):
        """Apply a parameter mutation to a URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if mutation["strategy"] == "modify":
            params[mutation["param"]] = [mutation["new_value"]]
            
        elif mutation["strategy"] == "remove":
            if mutation["param"] in params:
                del params[mutation["param"]]
                
        elif mutation["strategy"] == "duplicate":
            # Add a duplicate parameter with a different value
            duplicate_param = mutation["param"] + "_dup"
            params[duplicate_param] = [mutation["new_value"]]
        
        # Rebuild query string
        new_query = "&".join(f"{k}={v[0]}" for k, v in params.items())
        
        # Rebuild URL
        new_url = parsed._replace(query=new_query).geturl()
        
        return new_url
    
    def smart_fuzz_endpoint(self, url):
        """Intelligently fuzz an endpoint to detect vulnerabilities"""
        results = []
        
        try:
            # First, get a baseline response
            baseline_resp = requests.get(url, timeout=8, verify=False)
            
            # Generate mutations
            mutations = self.generate_parameter_mutations(url)
            
            for mutation in mutations:
                try:
                    # Apply mutation
                    mutated_url = self.apply_mutation(url, mutation)
                    
                    # Request the mutated URL
                    mutated_resp = requests.get(mutated_url, timeout=8, verify=False)
                    
                    # Compare with baseline
                    similarity = self.compute_response_similarity(baseline_resp, mutated_resp)
                    
                    # If response is significantly different, it might indicate a vulnerability
                    if similarity < self.similarity_threshold:
                        # Analyze for specific errors
                        error_findings = self.analyze_response_for_errors(mutated_resp)
                        
                        results.append({
                            "original_url": url,
                            "mutated_url": mutated_url,
                            "mutation": mutation,
                            "similarity": similarity,
                            "response_code": mutated_resp.status_code,
                            "findings": error_findings
                        })
                except:
                    continue
        except:
            pass
            
        return results
    
    def learn_from_responses(self, url, responses):
        """Learn patterns from valid and invalid responses"""
        # Generate a key for this endpoint pattern
        url_pattern = re.sub(r'\d+', 'X', url)
        pattern_hash = hashlib.md5(url_pattern.encode()).hexdigest()
        
        if pattern_hash not in self.response_patterns:
            self.response_patterns[pattern_hash] = {
                "url_pattern": url_pattern,
                "valid_responses": [],
                "error_responses": []
            }
            
        # Classify responses as valid or error
        for resp in responses:
            if 200 <= resp.status_code < 300:
                # Valid response
                self.response_patterns[pattern_hash]["valid_responses"].append({
                    "status_code": resp.status_code,
                    "content_length": len(resp.text),
                    "content_hash": hashlib.md5(resp.text.encode()).hexdigest()
                })
            elif 400 <= resp.status_code < 600:
                # Error response
                self.response_patterns[pattern_hash]["error_responses"].append({
                    "status_code": resp.status_code,
                    "content_length": len(resp.text),
                    "content_hash": hashlib.md5(resp.text.encode()).hexdigest()
                })
    
    def detect_anomalies(self, endpoints, max_endpoints=30):
        """Detect anomalies across the provided endpoints"""
        print_colored("[*] Running smart anomaly detection on endpoints...", Fore.BLUE)
        
        # Limit number of endpoints to analyze
        if len(endpoints) > max_endpoints:
            selected_endpoints = random.sample(endpoints, max_endpoints)
        else:
            selected_endpoints = endpoints
            
        findings = []
        
        for url in selected_endpoints:
            print_colored(f"[*] Analyzing {url}...", Fore.CYAN)
            
            # Smart fuzzing
            fuzzing_results = self.smart_fuzz_endpoint(url)
            if fuzzing_results:
                findings.extend(fuzzing_results)
                
                # Display interesting findings
                for result in fuzzing_results:
                    if result["findings"]:
                        print_colored(f"[+] Found potential issue in {result['mutated_url']}", Fore.YELLOW)
                        for finding in result["findings"]:
                            print_colored(f"  - {finding['type']}: {finding['details']} ({finding['confidence']} confidence)", Fore.YELLOW)
        
        # Save findings
        if findings:
            findings_file = os.path.join(self.smart_dir, "anomaly_findings.json")
            with open(findings_file, 'w') as f:
                json.dump(findings, f, indent=2)
                
            # Generate a text report
            report_file = os.path.join(self.smart_dir, "anomaly_report.txt")
            self.generate_text_report(findings, report_file)
                
            print_colored(f"[+] Smart detection found {len(findings)} potential issues. Report saved to {report_file}", Fore.GREEN)
        else:
            print_colored("[*] No anomalies detected.", Fore.YELLOW)
            
        return findings
    
    def generate_text_report(self, findings, report_file):
        """Generate a human-readable text report of findings"""
        report_lines = ["=== SMART ANOMALY DETECTION REPORT ===\n\n"]
        
        for i, finding in enumerate(findings, 1):
            report_lines.append(f"Finding #{i}:")
            report_lines.append(f"Original URL: {finding['original_url']}")
            report_lines.append(f"Mutated URL: {finding['mutated_url']}")
            report_lines.append(f"Mutation: {finding['mutation']['strategy']} on parameter '{finding['mutation']['param']}'")
            report_lines.append(f"Response Code: {finding['response_code']}")
            report_lines.append(f"Similarity to baseline: {finding['similarity']:.2f}")
            
            if finding["findings"]:
                report_lines.append("\nDetected issues:")
                for issue in finding["findings"]:
                    report_lines.append(f"  - {issue['type']}: {issue['details']} ({issue['confidence']} confidence)")
                    if "matches" in issue:
                        report_lines.append(f"    Matches: {', '.join(issue['matches'])}")
            
            report_lines.append("\n" + "-" * 50 + "\n")
        
        save_to_file(report_lines, report_file)

def run_smart_detection(endpoints, output_dir):
    """Run smart detection on the provided endpoints"""
    detector = SmartDetector(output_dir)
    return detector.detect_anomalies(endpoints)
