
#!/usr/bin/env python3
"""
Intelligent Risk Scoring & Grouping Module: Analyzes vulnerability findings and calculates risk scores
"""
import os
import re
import json
import hashlib
from colorama import Fore
from .utils import print_colored, save_to_file

class RiskScorer:
    """Class for calculating risk scores and grouping vulnerabilities"""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.risk_dir = os.path.join(output_dir, "risk_analysis")
        
        if not os.path.exists(self.risk_dir):
            os.makedirs(self.risk_dir)
            
        # Risk scoring weights
        self.risk_weights = {
            "vulnerability_type": {
                "sqli": 10,
                "rce": 10,
                "lfi": 9,
                "xxe": 8,
                "ssti": 8,
                "xss": 7,
                "ssrf": 7,
                "open_redirect": 6,
                "idor": 6,
                "csrf": 5,
                "clickjacking": 4,
                "information_disclosure": 3,
                "header_security": 2
            },
            "attack_vector": {
                "network": 2,
                "adjacent_network": 2.5,
                "local": 3,
                "physical": 3.5
            },
            "attack_complexity": {
                "low": 3,
                "high": 1
            },
            "privileges_required": {
                "none": 3,
                "low": 2,
                "high": 1
            },
            "user_interaction": {
                "none": 3,
                "required": 1.5
            },
            "scope": {
                "unchanged": 2,
                "changed": 3
            },
            "confidentiality": {
                "none": 0,
                "low": 2,
                "high": 3
            },
            "integrity": {
                "none": 0,
                "low": 2,
                "high": 3
            },
            "availability": {
                "none": 0,
                "low": 2,
                "high": 3
            }
        }
        
        # Risk level thresholds (based on CVSS)
        self.risk_levels = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 1.0,
            "info": 0.0
        }
    
    def load_vulnerability_data(self):
        """Load vulnerability data from various sources in the output directory"""
        vuln_data = {
            "vulnerabilities": [],
            "security_headers": [],
            "http_findings": [],
            "dependencies": []
        }
        
        # Load vulnerabilities from vulnerability scanner
        vuln_dir = os.path.join(self.output_dir, "vulnerabilities")
        if os.path.exists(vuln_dir):
            for vuln_type in ["sqli", "xss", "rce", "lfi", "csrf", "ssrf", "idor", "xxe", "ssti", "jwt", "broken_auth"]:
                vuln_file = os.path.join(vuln_dir, vuln_type, "vulnerable_urls.txt")
                if os.path.exists(vuln_file):
                    with open(vuln_file, 'r') as f:
                        for line in f:
                            url = line.strip()
                            if url:
                                vuln_data["vulnerabilities"].append({
                                    "type": vuln_type,
                                    "url": url,
                                    "source": "vuln_scanner"
                                })
        
        # Load security header findings
        http_analysis_file = os.path.join(self.output_dir, "endpoints", "analysis", "http_analysis.json")
        if os.path.exists(http_analysis_file):
            try:
                with open(http_analysis_file, 'r') as f:
                    http_data = json.load(f)
                    for finding in http_data:
                        if "security_issues" in finding and finding["security_issues"]:
                            vuln_data["http_findings"].append(finding)
            except:
                pass
        
        # Load dependency vulnerabilities
        dep_json_file = os.path.join(self.output_dir, "dependencies", "dependencies.json")
        if os.path.exists(dep_json_file):
            try:
                with open(dep_json_file, 'r') as f:
                    dep_data = json.load(f)
                    for finding in dep_data.get("findings", []):
                        if "vulnerabilities" in finding:
                            vuln_data["dependencies"].append(finding)
            except:
                pass
        
        # Load payload testing results
        payload_file = os.path.join(self.output_dir, "payloads", "payload_results.json")
        if os.path.exists(payload_file):
            try:
                with open(payload_file, 'r') as f:
                    payload_data = json.load(f)
                    for finding in payload_data.get("findings", []):
                        vuln_data["vulnerabilities"].append({
                            "type": finding.get("type", "unknown"),
                            "url": finding.get("url", ""),
                            "evidence": finding.get("evidence", ""),
                            "risk": finding.get("risk", "Low"),
                            "source": "payload_testing"
                        })
            except:
                pass
        
        return vuln_data
    
    def calculate_base_score(self, vulnerability):
        """Calculate a base risk score for a vulnerability (CVSS-like)"""
        vuln_type = vulnerability.get("type", "other").lower()
        
        # Start with type-based score
        base_score = self.risk_weights["vulnerability_type"].get(vuln_type, 5.0)
        
        # Adjust based on URL sensitivity
        url = vulnerability.get("url", "").lower()
        if any(sensitive in url for sensitive in ["admin", "config", "setup", "install", "dashboard"]):
            base_score += 1.0
        
        # Adjust based on evidence (if available)
        evidence = vulnerability.get("evidence", "").lower()
        if "critical" in evidence:
            base_score += 1.5
        elif "high" in evidence:
            base_score += 1.0
        
        # Adjust if it's from a reliable source
        if vulnerability.get("source") == "vuln_scanner":
            base_score += 0.5
        
        # Cap at 10.0
        return min(10.0, base_score)
    
    def calculate_environmental_score(self, vulnerability, base_score):
        """Adjust score based on environmental factors"""
        # Start with base score
        env_score = base_score
        
        # Adjust based on URL (public vs internal)
        url = vulnerability.get("url", "").lower()
        if any(internal in url for internal in ["internal", "dev", "test", "staging"]):
            env_score -= 1.0  # Less severe if on internal systems
        elif any(public in url for public in ["api", "public", "app"]):
            env_score += 0.5  # More severe if on public API
        
        # Adjust based on potential impact evidence
        evidence = vulnerability.get("evidence", "").lower()
        if any(critical in evidence for critical in ["password", "credential", "token", "key", "admin"]):
            env_score += 1.0  # Critical data access increases severity
        
        # Cap at 10.0
        return min(10.0, max(0.0, env_score))
    
    def determine_risk_level(self, score):
        """Convert numerical score to risk level"""
        if score >= self.risk_levels["critical"]:
            return "critical"
        elif score >= self.risk_levels["high"]:
            return "high"
        elif score >= self.risk_levels["medium"]:
            return "medium"
        elif score >= self.risk_levels["low"]:
            return "low"
        else:
            return "info"
    
    def group_vulnerabilities(self, scored_vulnerabilities):
        """Group vulnerabilities by type, host, and path"""
        grouped = {
            "by_type": {},
            "by_host": {},
            "by_risk": {},
            "by_source": {}
        }
        
        for vuln in scored_vulnerabilities:
            # Group by type
            vuln_type = vuln.get("type", "other")
            if vuln_type not in grouped["by_type"]:
                grouped["by_type"][vuln_type] = []
            grouped["by_type"][vuln_type].append(vuln)
            
            # Group by host
            url = vuln.get("url", "")
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.netloc
                
                if not host:
                    host = "unknown"
            except:
                host = "unknown"
                
            if host not in grouped["by_host"]:
                grouped["by_host"][host] = []
            grouped["by_host"][host].append(vuln)
            
            # Group by risk level
            risk_level = vuln.get("risk_level", "low")
            if risk_level not in grouped["by_risk"]:
                grouped["by_risk"][risk_level] = []
            grouped["by_risk"][risk_level].append(vuln)
            
            # Group by source
            source = vuln.get("source", "unknown")
            if source not in grouped["by_source"]:
                grouped["by_source"][source] = []
            grouped["by_source"][source].append(vuln)
        
        return grouped
    
    def calculate_host_risk_scores(self, grouped_vulnerabilities):
        """Calculate risk scores for each host"""
        host_risk_scores = {}
        
        for host, vulns in grouped_vulnerabilities["by_host"].items():
            # Base risk is the highest individual vulnerability
            base_risk = max(vuln.get("risk_score", 0) for vuln in vulns)
            
            # Adjust based on number and types of vulnerabilities
            num_critical = len([v for v in vulns if v.get("risk_level") == "critical"])
            num_high = len([v for v in vulns if v.get("risk_level") == "high"])
            
            # Increase risk if multiple critical findings
            if num_critical > 1:
                base_risk = min(10.0, base_risk + (num_critical * 0.2))
            
            # Increase risk if many high findings
            if num_high > 2:
                base_risk = min(10.0, base_risk + (num_high * 0.1))
            
            host_risk_scores[host] = {
                "risk_score": base_risk,
                "risk_level": self.determine_risk_level(base_risk),
                "critical_count": num_critical,
                "high_count": num_high,
                "total_vulnerabilities": len(vulns)
            }
        
        return host_risk_scores
    
    def run_risk_analysis(self):
        """Run the complete risk analysis process"""
        print_colored("[*] Running intelligent risk scoring and analysis...", Fore.BLUE)
        
        # Load vulnerability data from various sources
        vuln_data = self.load_vulnerability_data()
        total_findings = len(vuln_data["vulnerabilities"]) + len(vuln_data["http_findings"]) + len(vuln_data["dependencies"])
        
        if total_findings == 0:
            print_colored("[*] No vulnerability findings to analyze.", Fore.YELLOW)
            return None
        
        print_colored(f"[+] Loaded {total_findings} vulnerability findings for analysis.", Fore.GREEN)
        
        # Score each vulnerability
        scored_vulnerabilities = []
        
        # Process main vulnerabilities
        for vuln in vuln_data["vulnerabilities"]:
            base_score = self.calculate_base_score(vuln)
            env_score = self.calculate_environmental_score(vuln, base_score)
            risk_level = self.determine_risk_level(env_score)
            
            scored_vuln = vuln.copy()
            scored_vuln.update({
                "base_score": round(base_score, 1),
                "risk_score": round(env_score, 1),
                "risk_level": risk_level
            })
            scored_vulnerabilities.append(scored_vuln)
        
        # Process HTTP findings (typically security headers)
        for finding in vuln_data["http_findings"]:
            # Create a vulnerability entry for each security issue
            for issue in finding.get("security_issues", []):
                vuln = {
                    "type": "security_header",
                    "url": finding.get("url", ""),
                    "evidence": issue,
                    "source": "http_analysis",
                    "status_code": finding.get("status_code")
                }
                
                # Security headers usually have lower severity
                base_score = 3.0
                if "CORS" in issue:
                    base_score = 5.0  # CORS misconfigurations can be more severe
                elif "Content-Security-Policy" in issue:
                    base_score = 4.0  # Missing CSP can lead to XSS
                
                env_score = self.calculate_environmental_score(vuln, base_score)
                risk_level = self.determine_risk_level(env_score)
                
                vuln.update({
                    "base_score": round(base_score, 1),
                    "risk_score": round(env_score, 1),
                    "risk_level": risk_level
                })
                scored_vulnerabilities.append(vuln)
        
        # Process dependency vulnerabilities
        for dep in vuln_data["dependencies"]:
            for vuln in dep.get("vulnerabilities", []):
                vulnerability = {
                    "type": "outdated_dependency",
                    "url": f"Library: {dep.get('library')} v{dep.get('version')}",
                    "evidence": vuln.get("description", "Vulnerable dependency"),
                    "source": "dependency_analyzer",
                    "cve": vuln.get("cve")
                }
                
                # Base score depends on whether there's a CVE
                base_score = 5.0 if vuln.get("cve") else 3.0
                env_score = base_score  # No environmental adjustment for dependencies
                risk_level = self.determine_risk_level(env_score)
                
                vulnerability.update({
                    "base_score": round(base_score, 1),
                    "risk_score": round(env_score, 1),
                    "risk_level": risk_level
                })
                scored_vulnerabilities.append(vulnerability)
        
        # Group vulnerabilities by different dimensions
        grouped_vulnerabilities = self.group_vulnerabilities(scored_vulnerabilities)
        
        # Calculate host risk scores
        host_risk_scores = self.calculate_host_risk_scores(grouped_vulnerabilities)
        
        # Generate the risk report
        self.generate_risk_report(scored_vulnerabilities, grouped_vulnerabilities, host_risk_scores)
        
        return {
            "vulnerabilities": scored_vulnerabilities,
            "grouped": grouped_vulnerabilities,
            "host_risk_scores": host_risk_scores
        }
    
    def generate_risk_report(self, vulnerabilities, grouped, host_risk_scores):
        """Generate comprehensive risk report files"""
        # Save full JSON data
        json_report = os.path.join(self.risk_dir, "risk_analysis.json")
        with open(json_report, 'w') as f:
            json.dump({
                "total_vulnerabilities": len(vulnerabilities),
                "risk_statistics": {
                    "critical": len(grouped["by_risk"].get("critical", [])),
                    "high": len(grouped["by_risk"].get("high", [])),
                    "medium": len(grouped["by_risk"].get("medium", [])),
                    "low": len(grouped["by_risk"].get("low", [])),
                    "info": len(grouped["by_risk"].get("info", []))
                },
                "vulnerabilities_by_type": {k: len(v) for k, v in grouped["by_type"].items()},
                "host_risk_assessment": host_risk_scores,
                "detailed_vulnerabilities": vulnerabilities
            }, f, indent=2)
        
        # Generate text report
        text_report = os.path.join(self.risk_dir, "risk_report.txt")
        
        with open(text_report, 'w') as f:
            f.write("=== VULNERABILITY RISK ASSESSMENT REPORT ===\n\n")
            
            # Summary statistics
            f.write("SUMMARY STATISTICS\n")
            f.write("------------------\n")
            f.write(f"Total vulnerabilities found: {len(vulnerabilities)}\n")
            f.write("\nBreakdown by risk level:\n")
            for level in ["critical", "high", "medium", "low", "info"]:
                count = len(grouped["by_risk"].get(level, []))
                f.write(f"  - {level.upper()}: {count}\n")
            
            # Host risk assessment
            f.write("\nHOST RISK ASSESSMENT\n")
            f.write("--------------------\n")
            for host, risk in sorted(host_risk_scores.items(), key=lambda x: x[1]['risk_score'], reverse=True):
                f.write(f"Host: {host}\n")
                f.write(f"  Risk Level: {risk['risk_level'].upper()}\n")
                f.write(f"  Risk Score: {risk['risk_score']}\n")
                f.write(f"  Critical Findings: {risk['critical_count']}\n")
                f.write(f"  High Findings: {risk['high_count']}\n")
                f.write(f"  Total Vulnerabilities: {risk['total_vulnerabilities']}\n\n")
            
            # Top critical and high vulnerabilities
            f.write("\nCRITICAL AND HIGH RISK VULNERABILITIES\n")
            f.write("--------------------------------------\n")
            critical_high = []
            if "critical" in grouped["by_risk"]:
                critical_high.extend(grouped["by_risk"]["critical"])
            if "high" in grouped["by_risk"]:
                critical_high.extend(grouped["by_risk"]["high"])
            
            critical_high = sorted(critical_high, key=lambda x: x.get("risk_score", 0), reverse=True)
            
            for vuln in critical_high:
                f.write(f"Type: {vuln.get('type', 'unknown')}\n")
                f.write(f"URL: {vuln.get('url', 'unknown')}\n")
                f.write(f"Risk Level: {vuln.get('risk_level', 'unknown').upper()}\n")
                f.write(f"Risk Score: {vuln.get('risk_score', 0)}\n")
                if "evidence" in vuln:
                    f.write(f"Evidence: {vuln.get('evidence')}\n")
                if "cve" in vuln and vuln["cve"]:
                    f.write(f"CVE: {vuln.get('cve')}\n")
                f.write("\n")
            
            # Vulnerability types summary
            f.write("\nVULNERABILITY TYPES SUMMARY\n")
            f.write("---------------------------\n")
            for vuln_type, vulns in sorted(grouped["by_type"].items(), key=lambda x: len(x[1]), reverse=True):
                f.write(f"{vuln_type}: {len(vulns)}\n")
        
        # Generate CSV report for easy import into spreadsheets
        csv_report = os.path.join(self.risk_dir, "vulnerabilities.csv")
        
        with open(csv_report, 'w') as f:
            f.write("Type,URL,Risk Level,Risk Score,Evidence,Source\n")
            
            for vuln in vulnerabilities:
                # Escape any commas in fields
                vuln_type = vuln.get("type", "unknown").replace(",", ";")
                url = vuln.get("url", "unknown").replace(",", ";")
                risk_level = vuln.get("risk_level", "unknown")
                risk_score = vuln.get("risk_score", 0)
                evidence = vuln.get("evidence", "").replace(",", ";") if "evidence" in vuln else ""
                source = vuln.get("source", "unknown").replace(",", ";")
                
                f.write(f"{vuln_type},{url},{risk_level},{risk_score},{evidence},{source}\n")
        
        print_colored(f"[+] Risk analysis complete. Reports saved to {self.risk_dir}", Fore.GREEN)
        
        # Print summary to console
        print_colored("\nRISK ASSESSMENT SUMMARY:", Fore.CYAN)
        for level in ["critical", "high", "medium", "low", "info"]:
            count = len(grouped["by_risk"].get(level, []))
            if level == "critical":
                color = Fore.RED + Style.BRIGHT
            elif level == "high":
                color = Fore.MAGENTA
            elif level == "medium":
                color = Fore.YELLOW
            elif level == "low":
                color = Fore.CYAN
            else:
                color = Fore.WHITE
            print_colored(f"  - {level.upper()}: {count}", color)
        
        # Print host risk levels
        print_colored("\nHOST RISK LEVELS:", Fore.CYAN)
        for host, risk in sorted(host_risk_scores.items(), key=lambda x: x[1]['risk_score'], reverse=True)[:5]:  # Top 5
            level = risk['risk_level']
            if level == "critical":
                color = Fore.RED + Style.BRIGHT
            elif level == "high":
                color = Fore.MAGENTA
            elif level == "medium":
                color = Fore.YELLOW
            elif level == "low":
                color = Fore.CYAN
            else:
                color = Fore.WHITE
            print_colored(f"  - {host}: {level.upper()} ({risk['risk_score']})", color)

def run_risk_analysis(output_dir):
    """Run risk analysis and generate reports"""
    scorer = RiskScorer(output_dir)
    return scorer.run_risk_analysis()
