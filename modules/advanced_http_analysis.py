
#!/usr/bin/env python3
"""
Advanced HTTP/Endpoint Analysis: Fast, threaded threat analysis of headers, CORS, redirects, compression, cookies, CSP, param behaviors.
"""
import os, requests
from colorama import Fore
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import print_colored, save_to_file

def _process_url(url, exclude_domains):
    try:
        for ex in exclude_domains:
            if ex in url:
                return None  # Skip out-of-scope domains/URLs
        resp = requests.get(url, timeout=10, allow_redirects=True)
        csp = resp.headers.get("Content-Security-Policy", "None")
        cors = resp.headers.get("Access-Control-Allow-Origin", "None")
        cookies = resp.cookies.get_dict()
        hsts = resp.headers.get("Strict-Transport-Security", "None")
        return f"{url}\n  CSP: {csp}\n  CORS: {cors}\n  HSTS: {hsts}\n  Cookies: {cookies}\n"
    except Exception:
        return None

def analyze_http_behaviors(endpoints, output_dir, exclude_domains=None, max_workers=20):
    """
    endpoints: List of URLs,
    output_dir: Where to save the report
    exclude_domains: List of substrings (domains or full URLs) to skip (default [])
    max_workers: Number of threads for fast crawling
    """
    print_colored("[*] Running advanced HTTP/endpoint analysis (headers, CORS, redirects)...", Fore.CYAN)

    if exclude_domains is None:
        exclude_domains = []
    results = []

    # Display excluded out-of-scope domains
    if exclude_domains:
        print_colored(f"[*] Excluding out-of-scope domains/URLs: {exclude_domains}", Fore.YELLOW)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(_process_url, url, exclude_domains): url for url in endpoints}
        for future in as_completed(future_to_url):
            res = future.result()
            if res:
                results.append(res)

    out = os.path.join(output_dir, "endpoints", "http_analysis.txt")
    save_to_file(results, out)
    print_colored(f"[+] Saved HTTP/Endpoint analysis to {out}", Fore.GREEN)
    return results
