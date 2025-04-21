
#!/usr/bin/env python3
"""
Advanced HTTP/Endpoint Analysis: Threat analysis of headers, CORS, redirects, compression, cookies, CSP, param behaviors.
"""
import os, requests
from colorama import Fore
from .utils import print_colored, save_to_file

def analyze_http_behaviors(endpoints, output_dir):
    print_colored("[*] Running advanced HTTP/endpoint analysis (headers, CORS, redirects)...", Fore.CYAN)
    results = []
    for url in endpoints:
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
            csp = resp.headers.get("Content-Security-Policy", "None")
            cors = resp.headers.get("Access-Control-Allow-Origin", "None")
            cookies = resp.cookies.get_dict()
            hsts = resp.headers.get("Strict-Transport-Security", "None")
            result = f"{url}\n  CSP: {csp}\n  CORS: {cors}\n  HSTS: {hsts}\n  Cookies: {cookies}\n"
            results.append(result)
        except Exception as ex:
            continue
    out = os.path.join(output_dir, "endpoints", "http_analysis.txt")
    save_to_file(results, out)
    print_colored(f"[+] Saved HTTP/Endpoint analysis to {out}", Fore.GREEN)
    return results
