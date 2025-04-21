
#!/usr/bin/env python3
"""
AI-driven bug analysis module for advanced vulnerability detection, PoC suggestion, and payload generation.
Requires: Set an environment variable AI_API_KEY with your OpenAI/Perplexity API key.
"""

import os
import requests
import json
import time
import hashlib
from colorama import Fore
from .utils import print_colored, save_to_file

LLM_API_URL = os.environ.get("AI_API_URL", "https://api.perplexity.ai/chat/completions")
LLM_API_KEY = os.environ.get("AI_API_KEY")
LEARNING_DB_FILE = "learning_db.json"

def query_llm(prompt, model="llama-3.1-sonar-large-128k-online"):
    if not LLM_API_KEY:
        print_colored("[AI] No API key set for the AI module. Set AI_API_KEY environment variable.", Fore.YELLOW)
        return None
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": model,
        "messages": [
            {"role": "system", "content": (
                "You are a web penetration testing AI. For each analyzed endpoint and HTTP response, "
                "detect any vulnerabilities (well-known or novel), provide a detailed proof-of-concept (PoC) exploit step if you can, "
                "suggest payload(s), and rate the likelihood [none/low/medium/high/critical]. Output concisely."
            )},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 800
    }
    try:
        resp = requests.post(LLM_API_URL, json=data, headers=headers)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        else:
            print_colored(f"[AI] LLM query failed: {resp.text}", Fore.RED)
            return None
    except Exception as ex:
        print_colored(f"[AI] Error querying LLM: {ex}", Fore.RED)
        return None

def load_learning_db():
    """Load the learning database or create a new one"""
    if os.path.exists(LEARNING_DB_FILE):
        try:
            with open(LEARNING_DB_FILE, 'r') as f:
                return json.load(f)
        except:
            return {"patterns": {}, "payloads": {}, "techniques": {}}
    return {"patterns": {}, "payloads": {}, "techniques": {}}

def save_learning_db(db):
    """Save the learning database"""
    with open(LEARNING_DB_FILE, 'w') as f:
        json.dump(db, f, indent=2)

def learn_from_result(url, result, success=False):
    """Learn from scan results to improve future scans"""
    db = load_learning_db()
    
    # Generate hash for URL pattern
    url_pattern = url.split('?')[0] if '?' in url else url
    pattern_hash = hashlib.md5(url_pattern.encode()).hexdigest()
    
    # Process successful payloads
    if success and '?' in url:
        params = url.split('?')[1]
        for param in params.split('&'):
            if '=' in param:
                param_name, param_value = param.split('=', 1)
                if param_name not in db["payloads"]:
                    db["payloads"][param_name] = []
                if param_value not in db["payloads"][param_name]:
                    db["payloads"][param_name].append(param_value)
    
    # Update patterns
    if pattern_hash not in db["patterns"]:
        db["patterns"][pattern_hash] = {"url": url_pattern, "success": 0, "failure": 0}
    
    if success:
        db["patterns"][pattern_hash]["success"] += 1
    else:
        db["patterns"][pattern_hash]["failure"] += 1
    
    # Extract techniques if present in result
    if result and isinstance(result, str):
        if "SQLi" in result or "SQL injection" in result:
            if "sqli" not in db["techniques"]:
                db["techniques"]["sqli"] = 0
            db["techniques"]["sqli"] += 1
        if "XSS" in result:
            if "xss" not in db["techniques"]:
                db["techniques"]["xss"] = 0
            db["techniques"]["xss"] += 1
        # Add more technique detection as needed
    
    save_learning_db(db)
    return db

def generate_smart_payloads(url, endpoint_type=None):
    """Generate smart payloads based on learned patterns"""
    db = load_learning_db()
    payloads = []
    
    # Basic payload set
    default_payloads = {
        "sqli": ["' OR 1=1--", "1' OR '1'='1", "1; DROP TABLE users--"],
        "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "rce": ["$(sleep 5)", "; sleep 5;", "|| sleep 5 ||"],
        "lfi": ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"],
    }
    
    # Add default payloads
    if endpoint_type:
        payloads.extend(default_payloads.get(endpoint_type, []))
    else:
        # If no specific type, add some from each category
        for category in default_payloads:
            payloads.extend(default_payloads[category][:1])
    
    # Add learned payloads
    if '?' in url:
        param_name = url.split('?')[1].split('=')[0] if '=' in url.split('?')[1] else None
        if param_name and param_name in db["payloads"]:
            payloads.extend(db["payloads"][param_name])
    
    # Prioritize techniques that have worked before
    if db["techniques"]:
        top_technique = max(db["techniques"].items(), key=lambda x: x[1])[0]
        payloads = default_payloads.get(top_technique, []) + payloads
    
    return list(set(payloads))  # Remove duplicates

def ai_analyze_endpoints(endpoints, output_dir):
    """
    Analyze a list of endpoints using an AI model, suggest vulnerabilities, PoCs, and payloads.
    """
    print_colored("[AI] Running AI bug analysis on endpoints (experimental)...", Fore.MAGENTA)
    out_dir = os.path.join(output_dir, "ai")
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    results = []
    critical_findings = []
    high_findings = []
    
    for idx, ep in enumerate(endpoints):
        print_colored(f"[AI] Analyzing endpoint {idx+1}/{len(endpoints)}: {ep}", Fore.CYAN)
        try:
            # Fetch basic response (use GET; no scanning here, just for context)
            import requests
            resp = requests.get(ep, timeout=8, verify=False, allow_redirects=True)
            prompt = f"URL: {ep}\nResponse code: {resp.status_code}\nHeaders: {dict(resp.headers)}\nSample content: {resp.text[:500]}"
            ai_result = query_llm(prompt)
            if ai_result:
                display = f"URL: {ep}\n{ai_result}"
                
                # Identify risk level
                risk_level = "medium"  # Default
                if "critical" in ai_result.lower():
                    risk_level = "critical"
                    critical_findings.append({"url": ep, "analysis": ai_result})
                elif "high" in ai_result.lower():
                    risk_level = "high"
                    high_findings.append({"url": ep, "analysis": ai_result})
                
                # Use colored output based on risk level
                color = Fore.RED if risk_level == "critical" else (Fore.MAGENTA if risk_level == "high" else Fore.YELLOW)
                print_colored(display, color)
                
                # Learn from this result
                learn_from_result(ep, ai_result, risk_level in ["critical", "high"])
                
                # Add result to output
                results.append(display)
            else:
                results.append(f"URL: {ep}\n[AI] No analysis result.")
        except Exception as ex:
            print_colored(f"[AI] Error analyzing {ep}: {ex}", Fore.YELLOW)
            continue
        # AI rate limit protection
        time.sleep(2)
    
    # Save results
    ai_report = os.path.join(out_dir, "ai_analysis.txt")
    save_to_file(results, ai_report)
    
    # Save critical and high findings separately
    if critical_findings:
        critical_report = os.path.join(out_dir, "critical_findings.json")
        with open(critical_report, 'w') as f:
            json.dump(critical_findings, f, indent=2)
    
    if high_findings:
        high_report = os.path.join(out_dir, "high_findings.json")
        with open(high_report, 'w') as f:
            json.dump(high_findings, f, indent=2)
    
    print_colored(f"[AI] Saved AI analysis results to: {ai_report}", Fore.MAGENTA)
    print_colored(f"[AI] Found {len(critical_findings)} critical and {len(high_findings)} high-risk issues", 
                 Fore.RED if critical_findings else Fore.GREEN)
    
    return results

def generate_exploits(vulnerabilities, output_dir):
    """
    Generate exploit code for identified vulnerabilities
    """
    print_colored("[AI] Generating proof-of-concept exploits...", Fore.MAGENTA)
    exploits_dir = os.path.join(output_dir, "ai", "exploits")
    if not os.path.exists(exploits_dir):
        os.makedirs(exploits_dir)
    
    exploits = []
    for vuln_type, urls in vulnerabilities.items():
        if not urls:
            continue
            
        for url in urls[:5]:  # Limit to first 5 URLs per type
            prompt = f"Generate a working exploit code in Python for the following vulnerability:\nType: {vuln_type}\nURL: {url}\n"
            prompt += "Include only the Python code with proper comments. Use requests library."
            
            exploit_code = query_llm(prompt)
            if exploit_code:
                # Clean up the response to get just the code
                if "```python" in exploit_code:
                    exploit_code = exploit_code.split("```python")[1].split("```")[0].strip()
                elif "```" in exploit_code:
                    exploit_code = exploit_code.split("```")[1].split("```")[0].strip()
                
                # Create a unique filename
                url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
                exploit_file = os.path.join(exploits_dir, f"{vuln_type}_{url_hash}_exploit.py")
                
                # Add shebang and imports if not present
                if not exploit_code.startswith("#!/usr/bin/env python"):
                    exploit_code = f"#!/usr/bin/env python3\n# Exploit for {vuln_type} at {url}\n\n{exploit_code}"
                
                with open(exploit_file, 'w') as f:
                    f.write(exploit_code)
                    os.chmod(exploit_file, 0o755)  # Make executable
                
                exploits.append({"type": vuln_type, "url": url, "file": exploit_file})
                print_colored(f"[AI] Generated exploit for {vuln_type} at {url}", Fore.GREEN)
            
            # Avoid rate limiting
            time.sleep(2)
    
    # Save exploit index
    if exploits:
        index_file = os.path.join(exploits_dir, "exploits_index.json")
        with open(index_file, 'w') as f:
            json.dump(exploits, f, indent=2)
        print_colored(f"[AI] Generated {len(exploits)} exploits in {exploits_dir}", Fore.GREEN)
    else:
        print_colored("[AI] No exploits were generated", Fore.YELLOW)
    
    return exploits
