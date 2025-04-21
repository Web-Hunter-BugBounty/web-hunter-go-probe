
#!/usr/bin/env python3
"""
Enhanced endpoint discovery module for Web-Hunter
Supports extracting endpoints from various sources and analyzing them
"""

import os
import sys
import re
import time
import concurrent.futures
import json
import requests
import urllib3
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style
from tqdm import tqdm
from .utils import print_colored, save_to_file, get_command_output, check_command

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_endpoints_from_wayback(domain, output_dir):
    """Extract endpoints from Wayback Machine"""
    try:
        wayback_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey"
        response = requests.get(wayback_url, timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                if len(data) > 0:
                    # Remove header row
                    data = data[1:]
                    endpoints = [item[2] for item in data]
                    return endpoints
                return []
            except:
                return []
        else:
            return []
    except Exception:
        # Silently fail without printing detailed connection errors
        return []

def extract_endpoints_from_alienvault(domain, output_dir):
    """Extract endpoints from AlienVault OTX"""
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        response = requests.get(otx_url, timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                if 'url_list' in data:
                    endpoints = [item['url'] for item in data['url_list']]
                    return endpoints
                return []
            except:
                return []
        else:
            return []
    except Exception:
        # Silently fail without printing detailed connection errors
        return []

def extract_endpoints_from_commoncrawl(domain, output_dir):
    """Extract endpoints from CommonCrawl"""
    try:
        cc_url = f"https://index.commoncrawl.org/CC-MAIN-2021-43-index?url={domain}/*&output=json"
        response = requests.get(cc_url, timeout=15)
        
        if response.status_code == 200:
            endpoints = []
            for line in response.text.split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        endpoints.append(data.get('url', ''))
                    except:
                        continue
            return endpoints
        else:
            return []
    except Exception:
        # Silently fail without printing detailed connection errors
        return []

def extract_endpoints_from_github(domain, output_dir):
    """Extract endpoints from GitHub code search"""
    try:
        github_url = f"https://api.github.com/search/code?q={domain}&per_page=100"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(github_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                endpoints = []
                
                for item in data.get('items', []):
                    if 'html_url' in item:
                        endpoints.append(item['html_url'])
                
                return endpoints
            except:
                return []
        else:
            return []
    except Exception:
        # Silently fail without printing detailed connection errors
        return []

def crawl_website(url, depth=1, max_urls=100, visited=None):
    """Crawl a website to extract endpoints"""
    if visited is None:
        visited = set()
    
    if len(visited) >= max_urls or depth <= 0 or url in visited:
        return []
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        if response.status_code != 200:
            return []
        
        visited.add(url)
        new_endpoints = [url]
        
        soup = BeautifulSoup(response.text, 'html.parser')
        base_url = urlparse(url).scheme + '://' + urlparse(url).netloc
        domain = urlparse(url).netloc
        
        # Extract URLs from anchor tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            
            # Handle relative URLs
            if href.startswith('/'):
                full_url = urljoin(base_url, href)
            elif href.startswith('http'):
                full_url = href
            else:
                full_url = urljoin(url, href)
            
            # Only follow links to the same domain
            if urlparse(full_url).netloc == domain and full_url not in visited:
                new_endpoints.extend(crawl_website(full_url, depth-1, max_urls, visited))
                
                if len(new_endpoints) >= max_urls:
                    break
        
        return new_endpoints
    except Exception:
        # Silently fail without printing detailed connection errors
        return []

def extract_endpoints(targets, output_dir):
    """Extract endpoints from various sources"""
    print_colored("[*] Starting endpoint discovery...", Fore.BLUE)
    
    endpoints_dir = os.path.join(output_dir, "endpoints")
    
    # Create directory if it doesn't exist
    if not os.path.exists(endpoints_dir):
        os.makedirs(endpoints_dir)
    
    all_endpoints = []
    
    # Process each target
    with tqdm(total=len(targets), desc="Discovering endpoints", bar_format="{desc}: {percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as progress_bar:
        for i, target in enumerate(targets):
            try:
                # Use various sources to extract endpoints
                wayback_endpoints = extract_endpoints_from_wayback(target, output_dir)
                # Complete a single line from 0% to 20%
                progress_bar.update(0.2)
                
                alienvault_endpoints = extract_endpoints_from_alienvault(target, output_dir)
                # Update from 20% to 40%
                progress_bar.update(0.2)
                
                commoncrawl_endpoints = extract_endpoints_from_commoncrawl(target, output_dir)
                # Update from 40% to 60%
                progress_bar.update(0.2)
                
                github_endpoints = extract_endpoints_from_github(target, output_dir)
                # Update from 60% to 80%
                progress_bar.update(0.2)
                
                # Crawl the website directly
                crawled_endpoints = crawl_website(f"https://{target}" if not target.startswith('http') else target)
                # Update from 80% to 100%
                progress_bar.update(0.2)
                
                # Collect all endpoints
                target_endpoints = wayback_endpoints + alienvault_endpoints + commoncrawl_endpoints + github_endpoints + crawled_endpoints
                
                # Save target-specific endpoints
                target_endpoints_file = os.path.join(endpoints_dir, f"{target.replace('/', '_').replace(':', '_')}_endpoints.txt")
                save_to_file(target_endpoints, target_endpoints_file)
                
                all_endpoints.extend(target_endpoints)
                
            except Exception:
                # Silently continue without showing detailed errors
                pass
    
    # Remove duplicates
    all_endpoints = list(set(all_endpoints))
    
    # Save all endpoints
    all_endpoints_file = os.path.join(endpoints_dir, "all_endpoints.txt")
    save_to_file(all_endpoints, all_endpoints_file)
    
    print_colored(f"[+] Found {len(all_endpoints)} unique endpoints", Fore.GREEN)
    
    return all_endpoints

def filter_endpoints(endpoints, output_dir):
    """Filter endpoints for potentially critical ones"""
    print_colored("[*] Filtering endpoints for critical patterns...", Fore.BLUE)
    
    endpoints_dir = os.path.join(output_dir, "endpoints")
    
    # Create directory if it doesn't exist
    if not os.path.exists(endpoints_dir):
        os.makedirs(endpoints_dir)
    
    # Non-critical file extensions to exclude
    excluded_extensions = {
        '.jpeg', '.jpg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', 
        '.ttf', '.eot', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.css', 
        '.map', '.swf', '.mp4', '.webm', '.mp3', '.wav', '.ogg', '.webp',
        '.bmp', '.tiff', '.zip', '.tar', '.gz', '.rar', '.json', '.xml',
        '.txt', '.md', '.html', '.htm', '.php', '.asp', '.aspx', '.js',
        '.jsx', '.ts', '.tsx', '.vue', '.rb', '.py', '.java', '.cs',
        '.cpp', '.h', '.c', '.go', '.rs', '.swift', '.kotlin', '.dart'
    }
    
    # Enhanced critical patterns for better detection
    critical_patterns = [
        # API and Authentication
        r'/api[_/]?v?\d*', r'/graphql', r'/graphiql', r'/swagger', r'/auth',
        r'/oauth', r'/login', r'/logout', r'/signin', r'/signup', r'/register',
        r'/session', r'/token', r'/jwt', r'/access', r'/refresh',
        
        # Sensitive Operations
        r'/admin', r'/administrator', r'/backend', r'/manage', r'/console',
        r'/dashboard', r'/control', r'/panel', r'/cp', r'/master',
        
        # Security Related
        r'/security', r'/password', r'/reset', r'/forgot', r'/recover',
        r'/api[_-]?key', r'/secret', r'/credential', r'/private',
        
        # Configuration and System
        r'/config', r'/setting', r'/env', r'/environment', r'/setup',
        r'/install', r'/update', r'/upgrade', r'/maintenance',
        
        # Database and Storage
        r'/db', r'/database', r'/sql', r'/mysql', r'/postgres', r'/oracle',
        r'/backup', r'/dump', r'/export', r'/import', r'/sync',
        
        # Server Operations
        r'/shell', r'/cmd', r'/command', r'/exec', r'/execute', r'/run',
        r'/system', r'/ping', r'/trace', r'/test', r'/debug',
        
        # File Operations
        r'/upload', r'/download', r'/file', r'/document', r'/read',
        r'/write', r'/delete', r'/remove', r'/edit', r'/view',
        
        # Critical Functions
        r'/account', r'/user', r'/admin', r'/group', r'/role', r'/permission',
        r'/sudo', r'/root', r'/administrator', r'/superuser',
        
        # Development and Testing
        r'/dev', r'/development', r'/staging', r'/test', r'/beta',
        r'/internal', r'/local', r'/preview', r'/uat',
        
        # Common Vulnerabilities
        r'/phpinfo', r'/php-info', r'/info\.php', r'/.htaccess', 
        r'/server-status', r'/crossdomain.xml', r'/trace.axd',
        
        # Cloud and Infrastructure
        r'/aws', r'/azure', r'/gcp', r'/s3', r'/bucket', r'/storage',
        r'/cdn', r'/cloud', r'/instance', r'/function'
    ]
    
    # Compile regex patterns for efficiency
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in critical_patterns]
    
    critical_endpoints = []
    filtered_endpoints = []
    
    # Process each endpoint
    with tqdm(total=len(endpoints), desc="Filtering critical endpoints", bar_format="{desc}: {percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as progress_bar:
        for endpoint in endpoints:
            try:
                # Skip endpoints with excluded extensions
                parsed_url = urlparse(endpoint)
                path = parsed_url.path.lower()
                
                # Skip if the URL ends with an excluded extension
                if any(path.endswith(ext) for ext in excluded_extensions):
                    filtered_endpoints.append(endpoint)
                    progress_bar.update(1)
                    continue
                
                # Check if the endpoint contains any critical pattern
                is_critical = False
                for pattern in compiled_patterns:
                    if pattern.search(endpoint):
                        critical_endpoints.append(endpoint)
                        is_critical = True
                        break
                        
                if not is_critical:
                    filtered_endpoints.append(endpoint)
                
            except:
                # Silently continue on error
                filtered_endpoints.append(endpoint)
            
            progress_bar.update(1)
    
    # Save critical endpoints
    critical_endpoints_file = os.path.join(endpoints_dir, "critical_endpoints.txt")
    save_to_file(critical_endpoints, critical_endpoints_file)
    
    # Save filtered (non-critical) endpoints
    filtered_endpoints_file = os.path.join(endpoints_dir, "filtered_endpoints.txt")
    save_to_file(filtered_endpoints, filtered_endpoints_file)
    
    print_colored(f"[+] Found {len(critical_endpoints)} critical endpoints", Fore.GREEN)
    print_colored(f"[+] Removed {len(filtered_endpoints)} non-critical endpoints", Fore.YELLOW)
    
    return critical_endpoints

def filter_js_files(endpoints, output_dir):
    """Filter JavaScript files from endpoints"""
    print_colored("[*] Filtering JavaScript files...", Fore.BLUE)
    
    endpoints_dir = os.path.join(output_dir, "endpoints")
    
    # Create directory if it doesn't exist
    if not os.path.exists(endpoints_dir):
        os.makedirs(endpoints_dir)
    
    js_files = []
    
    # Process each endpoint
    with tqdm(total=len(endpoints), desc="Filtering JS files", bar_format="{desc}: {percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as progress_bar:
        for endpoint in endpoints:
            # Check if the endpoint is a JavaScript file
            if endpoint.endswith('.js'):
                js_files.append(endpoint)
            
            progress_bar.update(1)
    
    # Save JavaScript files
    js_files_file = os.path.join(endpoints_dir, "js_files.txt")
    save_to_file(js_files, js_files_file)
    
    print_colored(f"[+] Found {len(js_files)} JavaScript files", Fore.GREEN)
    
    return js_files

def extract_sensitive_info(endpoints, output_dir):
    """Extract sensitive information from endpoints"""
    print_colored("[*] Extracting sensitive information from endpoints...", Fore.BLUE)
    
    endpoints_dir = os.path.join(output_dir, "endpoints")
    sensitive_dir = os.path.join(endpoints_dir, "sensitive_info")
    
    # Create directory if it doesn't exist
    if not os.path.exists(sensitive_dir):
        os.makedirs(sensitive_dir)
    
    # Define patterns for sensitive information
    sensitive_patterns = {
        'api_key': [
            r'([a-zA-Z0-9_-]+(?:key|token|secret|password|credential|auth|access|id)["\']?\s*[=:]\s*["\']?[a-zA-Z0-9_\-\.]{16,64}["\']?)',
            r'(api[_\-]?key|api[_\-]?token|app[_\-]?key|app[_\-]?token|api_?id|client[_\-]?key|client[_\-]?token|client[_\-]?secret|customer[_\-]?key|token|secret)["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{16,64})["\']?',
            r'(ACCESS|SECRET|ACCOUNT|API)[_\-]?KEY["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{16,64})["\']?'
        ],
        'aws': [
            r'AKIA[0-9A-Z]{16}',
            r'aws[_\-]?access[_\-]?key[_\-]?id["\']?\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?',
            r'aws[_\-]?secret[_\-]?access[_\-]?key["\']?\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
        ],
        'azure': [
            r'[a-z0-9]{32}-[a-z0-9]{16}-[a-z0-9]{64}',  # Azure Storage Account key
            r'https?://[a-z0-9]+\.blob\.core\.windows\.net/[a-z0-9]+'  # Azure Blob Storage URL
        ],
        'google': [
            r'AIza[0-9A-Za-z_-]{35}',  # Google API Key
            r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'  # Google OAuth Client ID
        ],
        'github': [
            r'gh[pousr]_[A-Za-z0-9_]{36,255}',  # GitHub Personal Access Token
            r'github[_\-]?token["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_]{35,255})["\']?'
        ],
        'ssh_key': [
            r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            r'ssh-rsa [A-Za-z0-9+/=]+ [A-Za-z0-9_.-]+(@[A-Za-z0-9_.-]+)?'
        ],
        'jwt': [
            r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'  # JWT
        ],
        'ipv4': [
            r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ],
        'email': [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ],
        'firebase': [
            r'https?://[a-z0-9-]+\.firebaseio\.com'
        ],
        's3_bucket': [
            r'https?://[a-z0-9.-]+\.s3\.amazonaws\.com',
            r'https?://s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+'
        ]
    }
    
    # Compile regex patterns for efficiency
    compiled_patterns = {}
    for category, patterns in sensitive_patterns.items():
        compiled_patterns[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    
    # Store findings
    findings = {}
    
    # Process each endpoint
    with tqdm(total=len(endpoints), desc="Extracting sensitive info", bar_format="{desc}: {percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as progress_bar:
        for endpoint in endpoints:
            try:
                # Check if JS file or API endpoint
                if endpoint.endswith('.js') or 'api' in endpoint:
                    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36'}
                    response = requests.get(endpoint, headers=headers, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        # Search for sensitive information
                        for category, patterns in compiled_patterns.items():
                            for pattern in patterns:
                                matches = pattern.findall(content)
                                if matches:
                                    if category not in findings:
                                        findings[category] = []
                                    
                                    for match in matches:
                                        finding = {
                                            'endpoint': endpoint,
                                            'match': match if isinstance(match, str) else ''.join(match)
                                        }
                                        findings[category].append(finding)
            except Exception:
                # Silently continue on error
                pass
            
            progress_bar.update(1)
    
    # Save findings
    for category, category_findings in findings.items():
        category_file = os.path.join(sensitive_dir, f"{category}_findings.json")
        with open(category_file, 'w') as f:
            json.dump(category_findings, f, indent=2)
    
    # Create a summary
    summary_file = os.path.join(sensitive_dir, "sensitive_info_summary.txt")
    
    with open(summary_file, 'w') as f:
        f.write("Sensitive Information Summary\n")
        f.write("=" * 50 + "\n\n")
        
        total_findings = sum(len(category_findings) for category_findings in findings.values())
        f.write(f"Total findings: {total_findings}\n\n")
        
        for category, category_findings in findings.items():
            f.write(f"{category.upper()}: {len(category_findings)}\n")
    
    print_colored(f"[+] Found {sum(len(category_findings) for category_findings in findings.values())} instances of sensitive information", Fore.GREEN)
    print_colored(f"[+] Results saved to {sensitive_dir}", Fore.GREEN)
    
    return findings
