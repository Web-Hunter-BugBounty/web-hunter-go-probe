
#!/usr/bin/env python3
"""
Security Headers Analysis module for Web-Hunter
"""

import os
import json
import requests
import concurrent.futures
from colorama import Fore
from .utils import (
    print_colored, STATUS_SYMBOLS, show_progress, save_to_file,
    analyze_csp_headers, analyze_cors_headers
)

# Critical security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "recommendation": "Recommended value: strict-transport-security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "recommendation": "Implement a restrictive CSP that limits sources of executable scripts"
    },
    "X-Frame-Options": {
        "description": "X-Frame-Options",
        "recommendation": "Recommended value: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "description": "X-Content-Type-Options",
        "recommendation": "Recommended value: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "description": "Referrer Policy",
        "recommendation": "Recommended value: Referrer-Policy: no-referrer or strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "description": "Permissions Policy (formerly Feature-Policy)",
        "recommendation": "Implement a restrictive Permissions-Policy to limit features"
    },
    "X-XSS-Protection": {
        "description": "X-XSS-Protection",
        "recommendation": "Recommended value: X-XSS-Protection: 1; mode=block"
    },
    "Access-Control-Allow-Origin": {
        "description": "Access-Control-Allow-Origin (CORS)",
        "recommendation": "Avoid using wildcard (*) with credentials"
    },
    "Access-Control-Allow-Credentials": {
        "description": "Access-Control-Allow-Credentials (CORS)",
        "recommendation": "Be cautious when using with wildcard origins"
    },
    "Cache-Control": {
        "description": "Cache-Control",
        "recommendation": "For sensitive data: Cache-Control: no-store, max-age=0"
    },
    "Clear-Site-Data": {
        "description": "Clear-Site-Data",
        "recommendation": "For logout endpoints: Clear-Site-Data: \"cache\", \"cookies\", \"storage\""
    }
}

def analyze_security_headers(url):
    """Analyze security headers for a given URL"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        
        findings = {
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "missing_headers": [],
            "implemented_headers": [],
            "issues": [],
            "score": 0
        }
        
        # Check for each security header
        max_score = len(SECURITY_HEADERS) * 10
        current_score = 0
        
        for header, info in SECURITY_HEADERS.items():
            if header in response.headers:
                header_value = response.headers[header]
                findings["implemented_headers"].append({
                    "header": header,
                    "value": header_value,
                    "description": info["description"]
                })
                
                # Add points for having the header
                current_score += 5
                
                # Special case analyzes
                if header == "Content-Security-Policy":
                    csp_analysis = analyze_csp_headers(response.headers)
                    if csp_analysis.get("issues", []):
                        for issue in csp_analysis["issues"]:
                            findings["issues"].append({
                                "header": header,
                                "issue": issue,
                                "recommendation": info["recommendation"]
                            })
                    else:
                        # Extra points for good CSP
                        current_score += 5
                
                elif header == "Strict-Transport-Security":
                    if "max-age=31536000" in header_value and "includeSubDomains" in header_value:
                        # Extra points for good HSTS config
                        current_score += 5
                    else:
                        findings["issues"].append({
                            "header": header,
                            "issue": "HSTS header present but not optimally configured",
                            "recommendation": info["recommendation"]
                        })
                
                elif header == "X-Frame-Options":
                    if header_value.upper() in ["DENY", "SAMEORIGIN"]:
                        # Extra points for good X-Frame-Options
                        current_score += 5
                    else:
                        findings["issues"].append({
                            "header": header,
                            "issue": "X-Frame-Options has a weak value",
                            "recommendation": info["recommendation"]
                        })
                
                elif header in ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"]:
                    # CORS analysis is done together for both headers
                    if "Access-Control-Allow-Origin" in response.headers and "Access-Control-Allow-Credentials" in response.headers:
                        cors_analysis = analyze_cors_headers(response.headers)
                        if cors_analysis.get("issues", []):
                            for issue in cors_analysis["issues"]:
                                findings["issues"].append({
                                    "header": "CORS Configuration",
                                    "issue": issue,
                                    "recommendation": "Avoid using wildcard origins with credentials"
                                })
                        else:
                            # Extra points for good CORS config
                            current_score += 5
            
            else:
                findings["missing_headers"].append({
                    "header": header,
                    "description": info["description"],
                    "recommendation": info["recommendation"]
                })
                
                # Especially important headers
                if header in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
                    findings["issues"].append({
                        "header": header,
                        "issue": f"Missing critical security header: {header}",
                        "recommendation": info["recommendation"]
                    })
        
        # Calculate final score (0-100)
        findings["score"] = min(100, int((current_score / max_score) * 100))
        
        # Add an overall rating
        if findings["score"] >= 90:
            findings["rating"] = "Excellent"
        elif findings["score"] >= 70:
            findings["rating"] = "Good"
        elif findings["score"] >= 50:
            findings["rating"] = "Fair"
        elif findings["score"] >= 30:
            findings["rating"] = "Poor"
        else:
            findings["rating"] = "Very Poor"
        
        return findings
    
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "score": 0,
            "rating": "Error",
            "issues": [{
                "header": "Connection Error",
                "issue": f"Could not connect to {url}: {str(e)}",
                "recommendation": "Check if the server is accessible"
            }]
        }

def run_security_headers_analysis(targets, output_dir):
    """Run security headers analysis on a list of targets"""
    print_colored(f"[{STATUS_SYMBOLS['info']}] Starting security headers analysis on {len(targets)} targets", Fore.CYAN)
    
    # Create headers directory
    headers_dir = os.path.join(output_dir, "security_headers")
    if not os.path.exists(headers_dir):
        os.makedirs(headers_dir)
    
    # Function to normalize URLs
    def normalize_url(url):
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url
    
    # Normalize target URLs
    normalized_targets = [normalize_url(target) for target in targets]
    
    # Progress bar
    progress = show_progress(len(normalized_targets), "Security headers analysis")
    
    all_results = []
    
    def analyze_target(target):
        result = analyze_security_headers(target)
        progress.update(1)
        return result
    
    # Run analysis in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(analyze_target, normalized_targets))
    
    progress.close()
    all_results.extend(results)
    
    # Generate report files
    
    # 1. Full JSON report
    json_report = os.path.join(headers_dir, "security_headers_full.json")
    with open(json_report, 'w') as f:
        json.dump(all_results, f, indent=4)
    
    # 2. Text summary report
    text_report = os.path.join(headers_dir, "security_headers_summary.txt")
    with open(text_report, 'w') as f:
        f.write("SECURITY HEADERS ANALYSIS SUMMARY\n")
        f.write("=================================\n\n")
        
        # Overall stats
        total_targets = len(all_results)
        error_count = sum(1 for r in all_results if r.get("rating") == "Error")
        successful_scans = total_targets - error_count
        
        avg_score = 0
        if successful_scans > 0:
            avg_score = sum(r.get("score", 0) for r in all_results) / successful_scans
        
        f.write(f"Total targets scanned: {total_targets}\n")
        f.write(f"Successful scans: {successful_scans}\n")
        f.write(f"Errors: {error_count}\n")
        f.write(f"Average security score: {avg_score:.1f}/100\n\n")
        
        # Most common issues
        all_issues = []
        for result in all_results:
            for issue in result.get("issues", []):
                all_issues.append((issue.get("header", "Unknown"), issue.get("issue", "Unknown issue")))
        
        issue_count = {}
        for header, issue in all_issues:
            key = f"{header}: {issue}"
            if key not in issue_count:
                issue_count[key] = 0
            issue_count[key] += 1
        
        f.write("MOST COMMON ISSUES:\n")
        for i, (issue, count) in enumerate(sorted(issue_count.items(), key=lambda x: x[1], reverse=True)[:10], 1):
            f.write(f"{i}. {issue} ({count} occurrences)\n")
        
        f.write("\n")
        
        # Per-target summary
        f.write("PER-TARGET SUMMARY:\n")
        for result in sorted(all_results, key=lambda x: x.get("score", 0), reverse=True):
            url = result.get("url", "Unknown")
            score = result.get("score", 0)
            rating = result.get("rating", "Unknown")
            
            f.write(f"\n{url}\n")
            f.write(f"Score: {score}/100 ({rating})\n")
            
            if result.get("issues", []):
                f.write("Issues:\n")
                for issue in result.get("issues", [])[:3]:  # Show top 3 issues
                    f.write(f"- {issue.get('header', '')}: {issue.get('issue', '')}\n")
                
                if len(result.get("issues", [])) > 3:
                    f.write(f"  ... and {len(result.get('issues', [])) - 3} more issues\n")
            else:
                f.write("No issues found.\n")
    
    # 3. CSV report for easy importing
    csv_report = os.path.join(headers_dir, "security_headers_scores.csv")
    with open(csv_report, 'w') as f:
        f.write("URL,Score,Rating,Missing Critical Headers,Issues Count\n")
        for result in all_results:
            url = result.get("url", "Unknown")
            score = result.get("score", 0)
            rating = result.get("rating", "Unknown")
            
            missing_critical = sum(1 for h in result.get("missing_headers", []) 
                                 if h.get("header") in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"])
            
            issues_count = len(result.get("issues", []))
            
            f.write(f"{url},{score},{rating},{missing_critical},{issues_count}\n")
    
    print_colored(f"[{STATUS_SYMBOLS['success']}] Security headers analysis completed", Fore.GREEN)
    print_colored(f"[{STATUS_SYMBOLS['info']}] Results saved to {headers_dir}", Fore.CYAN)
    
    return all_results
