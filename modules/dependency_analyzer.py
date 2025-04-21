
#!/usr/bin/env python3
"""
Third-Party & Dependency Analyzer: Detects outdated/vulnerable JS libs on websites.
"""
import os
import re
import json
import requests
import hashlib
from colorama import Fore
from tqdm import tqdm
from .utils import print_colored, save_to_file
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

class DependencyAnalyzer:
    def __init__(self, endpoints, output_dir):
        self.endpoints = endpoints
        self.output_dir = output_dir
        self.results = {}
        self.vuln_db = self.load_vulnerability_db()
        
        # Create dependency directory
        self.dep_dir = os.path.join(output_dir, "dependencies")
        if not os.path.exists(self.dep_dir):
            os.makedirs(self.dep_dir)
            
        # Common libraries to check
        self.libraries = [
            "jquery", "react", "angular", "vue", "lodash", "bootstrap", 
            "axios", "moment", "d3", "three", "chart.js", "backbone", 
            "ember", "knockout", "prototype", "mootools", "dojo",
            "underscore", "polymer", "handlebars", "mustache", "leaflet",
            "tensorflow", "gsap", "mathjax", "pixi.js", "phaser",
            "fabric.js", "hammer.js", "popper.js", "modernizr", "require.js",
            "socketio", "babylon.js", "highcharts", "crypto-js"
        ]
        
        # Version regex patterns for common libraries
        self.version_patterns = {
            "jquery": [
                r'(?:jQuery|jquery)\s*[v:]\s*([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'jquery[/-]([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'jquery\s+([0-9]+\.[0-9]+(\.[0-9]+)?)'
            ],
            "react": [
                r'(?:React|react)[v:]\s*([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'react[/-]([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'"react":\s*"[~^]?([0-9]+\.[0-9]+(\.[0-9]+)?)"'
            ],
            "angular": [
                r'angular[v:]\s*([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'angular[/-]([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'"angular":\s*"[~^]?([0-9]+\.[0-9]+(\.[0-9]+)?)"'
            ],
            "bootstrap": [
                r'bootstrap[v:]\s*([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'bootstrap[/-]([0-9]+\.[0-9]+(\.[0-9]+)?)',
                r'"bootstrap":\s*"[~^]?([0-9]+\.[0-9]+(\.[0-9]+)?)"'
            ]
        }
        
        # Known vulnerable versions (simplified)
        self.known_vuln_libs = {
            "jquery": {
                "3.4.0": ["CVE-2019-11358", "Prototype pollution"],
                "3.3.0": ["CVE-2019-11358", "Prototype pollution"],
                "<3.5.0": ["XSS vulnerability in jQuery's html() function"],
                "<3.0.0": ["Multiple XSS vulnerabilities"],
                "<2.2.0": ["XSS in .html() and other parsers"]
            },
            "bootstrap": {
                "<4.3.1": ["CVE-2019-8331", "XSS vulnerability in data-template attribute"],
                "<4.1.2": ["CVE-2018-14041", "XSS vulnerability in tooltip"],
                "<3.4.0": ["CVE-2018-14042", "XSS via collapse data-parent attribute"]
            },
            "angular": {
                "<1.6.9": ["CVE-2018-1000006", "XSS via unsanitized values"],
                "<1.6.5": ["CVE-2017-16869", "Cross-site request forgery"]
            },
            "react": {
                "<16.4.2": ["CVE-2018-6341", "XSS vulnerability"],
                "<16.0.1": ["CVE-2018-6340", "XSS vulnerability"]
            },
            "lodash": {
                "<4.17.12": ["CVE-2019-10744", "Prototype pollution"],
                "<4.17.11": ["CVE-2018-16487", "Prototype pollution"]
            }
        }
    
    def load_vulnerability_db(self):
        """
        Load vulnerability database or create a minimal version if not available
        """
        db_path = os.path.join("data", "vuln_db.json")
        
        if os.path.exists(db_path):
            try:
                with open(db_path, 'r') as f:
                    return json.load(f)
            except:
                pass
                
        # Create a simplified DB if can't load the full one
        return {
            "jquery": {
                "vulnerabilities": [
                    {"below": "3.5.0", "cve": "CVE-2020-11022", "severity": "high"},
                    {"below": "3.0.0", "cve": "CVE-2019-11358", "severity": "medium"}
                ]
            },
            "bootstrap": {
                "vulnerabilities": [
                    {"below": "4.3.1", "cve": "CVE-2019-8331", "severity": "medium"},
                    {"below": "3.4.0", "cve": "CVE-2018-14042", "severity": "high"}
                ]
            },
            "angular": {
                "vulnerabilities": [
                    {"below": "1.6.9", "cve": "CVE-2018-1000006", "severity": "high"},
                    {"below": "1.5.0", "cve": "CVE-2015-20018", "severity": "high"}
                ]
            }
        }
    
    def analyze_single_url(self, url):
        """Analyze a single URL for JS dependencies"""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
            }
            resp = requests.get(url, timeout=15, verify=False, headers=headers)
            
            if resp.status_code != 200:
                return []
                
            findings = []
            html_content = resp.text
            
            # Extract all script sources
            script_srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html_content)
            js_urls = []
            
            for src in script_srcs:
                if src.startswith('//'):
                    src = 'https:' + src
                elif src.startswith('/'):
                    parsed_url = urlparse(url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    src = base_url + src
                elif not src.startswith(('http://', 'https://')):
                    parsed_url = urlparse(url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    if url.endswith('/'):
                        src = base_url + src
                    else:
                        src = base_url + '/' + src
                js_urls.append(src)
            
            # Check direct JS libraries in the HTML
            for lib in self.libraries:
                # First check using generic pattern
                generic_pattern = re.compile(r'(%s)[^0-9]*([0-9]+\.[0-9]+(\.[0-9]+)?)' % lib, re.I)
                for match in generic_pattern.findall(html_content):
                    lib_name = match[0].lower()
                    version = match[1]
                    findings.append({
                        "library": lib_name,
                        "version": version,
                        "url": url,
                        "source": "html"
                    })
                
                # Then check using specific patterns if available
                if lib in self.version_patterns:
                    for pattern in self.version_patterns[lib]:
                        specific_pattern = re.compile(pattern, re.I)
                        for match in specific_pattern.findall(html_content):
                            version = match[0] if isinstance(match, tuple) else match
                            findings.append({
                                "library": lib,
                                "version": version,
                                "url": url,
                                "source": "html-specific"
                            })
            
            # Analyze JS sources
            for js_url in js_urls[:5]:  # Limit to first 5 to prevent overloading
                try:
                    js_resp = requests.get(js_url, timeout=10, verify=False, headers=headers)
                    if js_resp.status_code == 200:
                        js_content = js_resp.text
                        
                        # Create hash for caching
                        content_hash = hashlib.md5(js_content.encode()).hexdigest()
                        
                        # Check for library signatures
                        for lib in self.libraries:
                            if lib in js_url.lower():
                                # Direct match in URL
                                version_match = re.search(r'[.-]([0-9]+\.[0-9]+(\.[0-9]+)?)', js_url)
                                if version_match:
                                    version = version_match.group(1)
                                    findings.append({
                                        "library": lib,
                                        "version": version,
                                        "url": js_url,
                                        "source": "js-url"
                                    })
                            
                            # Generic version pattern in JS content
                            generic_pattern = re.compile(r'%s[^0-9]*([0-9]+\.[0-9]+(\.[0-9]+)?)' % lib, re.I)
                            for match in generic_pattern.findall(js_content[:5000]):  # Check first 5000 chars
                                version = match[0] if isinstance(match, tuple) else match
                                findings.append({
                                    "library": lib,
                                    "version": version,
                                    "url": js_url,
                                    "source": "js-content"
                                })
                except:
                    continue
            
            return findings
        except Exception as ex:
            return []
    
    def check_vulnerability(self, library, version):
        """Check if a library version is vulnerable"""
        vulnerabilities = []
        
        if library in self.known_vuln_libs:
            for ver_pattern, vuln_info in self.known_vuln_libs[library].items():
                if ver_pattern.startswith('<'):
                    # Compare version
                    target_ver = ver_pattern[1:]
                    if self.version_lt(version, target_ver):
                        if isinstance(vuln_info, list):
                            for info in vuln_info:
                                cve = info if "CVE-" in info else None
                                desc = info if "CVE-" not in info else None
                                vulnerabilities.append({
                                    "cve": cve,
                                    "description": desc
                                })
                        else:
                            vulnerabilities.append({
                                "description": vuln_info
                            })
                else:
                    # Exact version match
                    if version == ver_pattern:
                        if isinstance(vuln_info, list):
                            for info in vuln_info:
                                cve = info if "CVE-" in info else None
                                desc = info if "CVE-" not in info else None
                                vulnerabilities.append({
                                    "cve": cve,
                                    "description": desc
                                })
                        else:
                            vulnerabilities.append({
                                "description": vuln_info
                            })
        
        # Also check the full vulnerability DB
        if library in self.vuln_db:
            for vuln in self.vuln_db[library].get("vulnerabilities", []):
                if "below" in vuln and self.version_lt(version, vuln["below"]):
                    vulnerabilities.append({
                        "cve": vuln.get("cve"),
                        "severity": vuln.get("severity", "unknown"),
                        "description": vuln.get("description", "Vulnerable version")
                    })
        
        return vulnerabilities
    
    def version_lt(self, v1, v2):
        """Compare versions (less than)"""
        v1_parts = [int(x) for x in v1.split('.')]
        v2_parts = [int(x) for x in v2.split('.')]
        
        # Pad with zeroes if needed
        while len(v1_parts) < len(v2_parts):
            v1_parts.append(0)
        while len(v2_parts) < len(v1_parts):
            v2_parts.append(0)
        
        for i in range(len(v1_parts)):
            if v1_parts[i] < v2_parts[i]:
                return True
            elif v1_parts[i] > v2_parts[i]:
                return False
        
        return False  # Equal versions
    
    def run_analysis(self):
        """Run the dependency analysis on all endpoints"""
        print_colored("[*] Analyzing for outdated/vulnerable JS libraries...", Fore.MAGENTA)
        
        all_findings = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.analyze_single_url, url): url for url in self.endpoints}
            
            for future in tqdm(futures, desc="Analyzing dependencies"):
                url = futures[future]
                try:
                    findings = future.result()
                    if findings:
                        all_findings.extend(findings)
                except Exception as e:
                    print_colored(f"[!] Error analyzing {url}: {str(e)}", Fore.RED)
        
        # De-duplicate findings
        unique_findings = {}
        for finding in all_findings:
            key = f"{finding['library']}|{finding['version']}|{finding['url']}"
            if key not in unique_findings:
                unique_findings[key] = finding
        
        # Check for vulnerabilities
        vuln_findings = []
        for finding in unique_findings.values():
            vulns = self.check_vulnerability(finding['library'], finding['version'])
            if vulns:
                finding['vulnerabilities'] = vulns
                vuln_findings.append(finding)
        
        # Save results
        self.results = list(unique_findings.values())
        
        # Generate text report
        text_report = []
        for finding in self.results:
            lib_info = f"{finding['url']}: {finding['library']} v{finding['version']}"
            if 'vulnerabilities' in finding:
                lib_info += " (VULNERABLE)"
                for vuln in finding['vulnerabilities']:
                    if vuln.get('cve'):
                        lib_info += f"\n  - {vuln.get('cve')}: {vuln.get('description', 'No description')}"
                    else:
                        lib_info += f"\n  - {vuln.get('description', 'Unknown vulnerability')}"
            text_report.append(lib_info)
        
        # Save results
        outF = os.path.join(self.dep_dir, "js_dependencies.txt")
        if text_report:
            save_to_file(text_report, outF)
            print_colored(f"[+] Saved dependency analysis to {outF}", Fore.GREEN)
        else:
            print_colored("[*] No JS dependencies found for version check.", Fore.YELLOW)
        
        # Save JSON report
        json_report = os.path.join(self.dep_dir, "dependencies.json")
        with open(json_report, 'w') as f:
            json.dump({
                "total": len(self.results),
                "vulnerable": len(vuln_findings),
                "findings": self.results
            }, f, indent=2)
        
        # Save vulnerable libs only
        if vuln_findings:
            vuln_report = os.path.join(self.dep_dir, "vulnerable_libs.txt")
            vuln_text = [f"[{finding.get('library')}] v{finding.get('version')} at {finding.get('url')}" for finding in vuln_findings]
            save_to_file(vuln_text, vuln_report)
            print_colored(f"[!] Found {len(vuln_findings)} vulnerable libraries! See {vuln_report}", Fore.RED)
        
        return self.results

def analyze_dependencies(endpoints, output_dir):
    analyzer = DependencyAnalyzer(endpoints, output_dir)
    return analyzer.run_analysis()
