
#!/usr/bin/env python3
"""
Enhanced login/admin/dev panel finder module.
"""
import os
import re
import json
import hashlib
import requests
import concurrent.futures
import urllib3
from urllib.parse import urlparse, urljoin
from colorama import Fore
from tqdm import tqdm
from .utils import print_colored, save_to_file

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Expanded list of common login paths
COMMON_LOGIN_PATHS = [
    # Login panels
    "/login", "/admin/login", "/administrator/login", "/auth/login", "/user/login", 
    "/control/login", "/admincp/login", "/admin_area/login", "/panel-administracion/login",
    "/adminLogin", "/admin_login", "/adminarea/login", "/login.php", "/login.aspx", "/login.html",
    "/login.js", "/login.jsp", "/wp-login.php", "/signin", "/sign-in", "/sign_in", "/account/login",
    
    # Admin panels
    "/admin", "/administrator", "/admin1", "/admin2", "/admin/", "/admin/dashboard", 
    "/admincp", "/admin/cp", "/cp", "/administrator/index", "/administrator/index.php",
    "/admin/controlpanel", "/admin.php", "/admin.html", "/admin/admin", "/admin/admin.php",
    "/admin123", "/admin/index", "/admin/index.php", "/admin_area", "/manager/", "/panel",
    "/panel-administracion", "/instadmin", "/memberadmin", "/administratorlogin", "/adm", "/admin/account.php",
    
    # WordPress specific
    "/wp-admin", "/wp-login", "/wordpress/wp-login.php", "/wp/wp-login.php", 
    
    # Joomla specific
    "/administrator", "/admin", "/joomla/administrator", "/administrator/index.php",
    
    # Drupal specific
    "/user", "/user/login", "/admin", "/admin/user/login",
    
    # Control panels
    "/cpanel", "/phpmyadmin", "/webadmin", "/sysadmin", "/dashboard", "/control", "/portal",
    "/manage", "/management", "/backend", "/customer_login", "/useradmin", "/memberadmin",
    "/admincontrol", "/bb-admin", "/adminpanel", "/user-admin", "/control-panel",
    
    # Development panels
    "/dev", "/dev/index", "/developers", "/development", "/staging", "/test", "/test/login", 
    "/beta", "/beta/login", "/debug", "/debug/default", "/devel", "/phpinfo", "/info.php",
    "/phpinfo.php", "/site.php", "/install", "/conf", "/config", "/settings", "/setting",
    "/configure", "/configuration", "/setup", "/console", "/terminal", "/webshell", "/backdoor",
    
    # Private/restricted areas
    "/private", "/customer", "/customers", "/client", "/clients", "/partner", "/partners",
    "/admin/", "/secret", "/backup", "/backups", "/old", "/db", "/database", "/staff", 
    
    # API endpoints
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/login", "/api/auth", "/api/token",
    "/api/admin", "/api/swagger", "/swagger", "/swagger-ui", "/graphql", "/graphiql"
]

# Authentication form patterns
AUTH_FORM_PATTERNS = [
    # Username/password fields
    r'<input[^>]*name=["\'](?:username|user|login|email|userEmail)["\']',
    r'<input[^>]*name=["\'](?:password|pass|userPassword|passwd)["\']',
    r'<input[^>]*type=["\']password["\']',
    
    # Login/submit buttons
    r'<button[^>]*(?:type=["\']submit["\']|class=["\'](?:login|submit|btn-login|btn-submit)["\'])[^>]*>(?:Login|Anmelden|Sign[ -]?in|Submit|Go|Enter|Entrar|Connexion)',
    r'<input[^>]*type=["\']submit["\'][^>]*value=["\'](?:Login|Anmelden|Sign[ -]?in|Submit|Go|Enter|Entrar|Connexion)["\']',
    
    # Form specific patterns
    r'<form[^>]*(?:id|class|name)=["\'](?:login|signin|auth)["\']',
    r'<form[^>]*action=["\'][^"\']*(?:login|signin|auth|account)[^"\']*["\']',
    
    # Common login form wrappers
    r'<div[^>]*(?:id|class)=["\'](?:login|login-form|login-box|signin|auth)["\']',
    
    # Common authentication labels
    r'<label[^>]*>(?:Username|User|Login|Email|Password|Pass)(?:</label>)?',
    
    # Recovery links
    r'<a[^>]*href=["\'][^"\']*(?:forgot|reset|recover|password|lost)[^"\']*["\']'
]

# Strings that indicate successful login panel detection
LOGIN_INDICATORS = [
    "login", "logged in", "log in", "sign in", "signin", "authentication", "authenticate", "username", 
    "user name", "password", "pass word", "email", "e-mail", "account", "credential", "session",
    "forgot password", "reset password", "recover password", "remember me", "keep me logged in",
    "admin login", "administrator", "dashboard", "control panel", "cpanel", "panel", "backend",
    "authorization", "authorize", "access", "member", "membership", "user login", "user access",
    "login to continue", "please login", "please sign in", "login required", "authentication required"
]

# Success response indicators
SUCCESS_INDICATORS = [
    "welcome", "dashboard", "logged in", "successfully", "authorized", "account", "profile", "logout",
    "sign out", "signout", "my account", "control panel", "admin area", "administration", 
    "preferences", "settings", "configuration", "overview", "summary", "statistics", "analytics"
]

class PanelFinder:
    def __init__(self, domains, output_dir, max_workers=10):
        self.domains = domains
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.results = {
            "admin_panels": [],
            "login_forms": [],
            "api_endpoints": [],
            "dev_panels": []
        }
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "DNT": "1"
        })
        
        # Ensure output directory exists
        self.results_dir = os.path.join(output_dir, "endpoints")
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def fetch_url(self, url, timeout=8):
        """Fetch a URL and return the response if successful"""
        try:
            resp = self.session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            if resp.status_code in [200, 301, 302, 307, 401, 403, 503]:
                return resp
            return None
        except:
            return None
    
    def check_url(self, domain, path):
        """Check if a URL exists and contains login form"""
        for proto in ['https://', 'http://']:
            base_url = proto + domain if not domain.startswith('http') else domain
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            
            resp = self.fetch_url(url)
            if not resp:
                continue
                
            # Create URL ID for tracking
            url_id = hashlib.md5(url.encode()).hexdigest()[:8]
            
            # Check for login indicators in response text
            content_lower = resp.text.lower()
            found_indicators = [i for i in LOGIN_INDICATORS if i.lower() in content_lower]
            
            # Check for authentication form patterns
            has_auth_form = any(re.search(pattern, resp.text, re.I) for pattern in AUTH_FORM_PATTERNS)
            
            # Determine panel type
            panel_type = "unknown"
            if path.startswith(("/admin", "/administrator", "/admincp", "/panel", "/control")):
                panel_type = "admin_panel"
            elif path.startswith(("/login", "/signin", "/user", "/account")):
                panel_type = "login_form"
            elif path.startswith(("/api", "/swagger", "/graphql")):
                panel_type = "api_endpoint"
            elif path.startswith(("/dev", "/staging", "/test", "/beta", "/debug")):
                panel_type = "dev_panel"
            
            # Process results
            if has_auth_form or (found_indicators and len(found_indicators) >= 2):
                result = {
                    "url": url,
                    "status_code": resp.status_code,
                    "indicators": found_indicators,
                    "has_auth_form": has_auth_form,
                    "panel_type": panel_type,
                    "id": url_id
                }
                
                # Extract page title if available
                title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.I | re.S)
                if title_match:
                    result["title"] = title_match.group(1).strip()
                
                return result
        
        return None
    
    def detect_protection(self, url):
        """Detect if the panel is protected by security measures"""
        resp = self.fetch_url(url)
        if not resp:
            return None
            
        protection = []
        headers = resp.headers
        
        # WAF detection
        waf_headers = [
            ("X-Firewall-By", "Any"),
            ("X-CDN", "Any"),
            ("server", "cloudflare"),
            ("cf-ray", "Any"),
            ("X-Sucuri-ID", "Any"),
            ("X-Protected-By", "Any")
        ]
        
        for header, value in waf_headers:
            if header.lower() in headers:
                if value == "Any" or value.lower() in headers[header.lower()].lower():
                    protection.append(f"WAF: {header}={headers[header.lower()]}")
        
        # Authentication detection
        if resp.status_code in [401, 403]:
            protection.append("Authentication required")
            
            if "www-authenticate" in headers:
                protection.append(f"Auth type: {headers['www-authenticate']}")
        
        # Rate limiting
        rate_limit_headers = ["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After", "X-Rate-Limit"]
        for header in rate_limit_headers:
            if header.lower() in headers:
                protection.append(f"Rate limiting: {header}={headers[header.lower()]}")
        
        # CAPTCHA detection
        if "captcha" in resp.text.lower() or "recaptcha" in resp.text.lower():
            protection.append("CAPTCHA protection")
        
        return protection if protection else None
    
    def test_default_creds(self, url):
        """Test for default credentials on found panels"""
        # Default credentials to test
        default_creds = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "12345"},
            {"username": "admin", "password": "admin123"},
            {"username": "administrator", "password": "administrator"},
            {"username": "test", "password": "test"},
            {"username": "user", "password": "user"},
            {"username": "guest", "password": "guest"}
        ]
        
        # Extract form details
        resp = self.fetch_url(url)
        if not resp:
            return None
            
        # Try to find the login form
        form_match = re.search(r'<form[^>]*>(.+?)</form>', resp.text, re.I | re.S)
        if not form_match:
            return None
            
        form_html = form_match.group(0)
        
        # Extract form action
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html)
        action = action_match.group(1) if action_match else ""
        
        # Determine form method
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_html)
        method = method_match.group(1) if method_match else "post"
        
        # Find input fields
        username_field = None
        password_field = None
        
        username_patterns = ["username", "user", "login", "email", "id", "user_login", "admin"]
        password_patterns = ["password", "pass", "psw", "pwd", "passwd", "passcode"]
        
        input_fields = re.findall(r'<input[^>]*>', form_html)
        for field in input_fields:
            name_match = re.search(r'name=["\']([^"\']+)["\']', field)
            if not name_match:
                continue
                
            field_name = name_match.group(1).lower()
            
            if any(pattern in field_name for pattern in username_patterns):
                username_field = name_match.group(1)
            elif any(pattern in field_name for pattern in password_patterns) or ('type="password"' in field or "type='password'" in field):
                password_field = name_match.group(1)
        
        if not username_field or not password_field:
            return None
            
        # Construct form submission URL
        if action:
            if action.startswith(("http://", "https://")):
                form_url = action
            else:
                base_url = "/".join(url.split("/")[:-1]) if "/" in urlparse(url).path else url
                form_url = urljoin(base_url, action)
        else:
            form_url = url
        
        # Test default credentials
        for cred in default_creds[:3]:  # Limit to first 3 to prevent account lockouts
            data = {
                username_field: cred["username"],
                password_field: cred["password"]
            }
            
            try:
                if method.lower() == "get":
                    login_resp = self.session.get(form_url, params=data, timeout=10, verify=False, allow_redirects=True)
                else:
                    login_resp = self.session.post(form_url, data=data, timeout=10, verify=False, allow_redirects=True)
                
                # Check for successful login indicators
                content_lower = login_resp.text.lower()
                if any(indicator in content_lower for indicator in SUCCESS_INDICATORS):
                    return {
                        "username": cred["username"],
                        "password": cred["password"],
                        "success": True
                    }
            except:
                continue
        
        return None
    
    def find_panels(self):
        """Find admin/login/dev panels in the provided domains"""
        print_colored("[*] Fuzzing for admin/login/dev panels...", Fore.YELLOW)
        
        all_urls_to_check = []
        for domain in self.domains:
            for path in COMMON_LOGIN_PATHS:
                all_urls_to_check.append((domain, path))
        
        found_panels = []
        tested_paths = set()
        
        # Use ThreadPoolExecutor for parallel checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(self.check_url, domain, path): (domain, path) 
                for domain, path in all_urls_to_check
            }
            
            with tqdm(total=len(all_urls_to_check), desc="Checking panels", unit="url") as pbar:
                for future in concurrent.futures.as_completed(future_to_url):
                    domain, path = future_to_url[future]
                    tested_paths.add(path)
                    
                    try:
                        result = future.result()
                        if result:
                            found_panels.append(result)
                            panel_type = result["panel_type"]
                            url = result["url"]
                            
                            # Add to appropriate category
                            if panel_type in self.results:
                                self.results[panel_type].append(url)
                            else:
                                self.results["login_forms"].append(url)
                            
                            # Print attractive output for found panels
                            color = Fore.RED if panel_type == "admin_panel" else (Fore.MAGENTA if panel_type == "dev_panel" else Fore.YELLOW)
                            print_colored(f"[+] Found {panel_type}: {url}", color)
                    except Exception as e:
                        pass
                    
                    pbar.update(1)
        
        # Get additional information for found panels
        enhanced_results = []
        for panel in found_panels:
            # Detect protection mechanisms
            protection = self.detect_protection(panel["url"])
            if protection:
                panel["protection"] = protection
            
            # Test for default credentials (only for admin and login panels)
            if panel["panel_type"] in ["admin_panel", "login_form"]:
                creds = self.test_default_creds(panel["url"])
                if creds and creds["success"]:
                    panel["default_creds"] = creds
                    print_colored(f"[!] DEFAULT CREDENTIALS WORK: {panel['url']} - {creds['username']}:{creds['password']}", Fore.RED + Style.BRIGHT)
            
            enhanced_results.append(panel)
        
        # Save results to files
        self.save_results(enhanced_results)
        
        # Return all login URLs
        all_found_urls = []
        for category, urls in self.results.items():
            all_found_urls.extend(urls)
        
        return all_found_urls
    
    def save_results(self, results):
        """Save results to various output files"""
        # Save all URLs to a single file
        all_urls = []
        for category, urls in self.results.items():
            all_urls.extend(urls)
        
        if all_urls:
            out_file = os.path.join(self.results_dir, "login_urls.txt")
            save_to_file(all_urls, out_file)
            print_colored(f"[+] Saved {len(all_urls)} login/admin/dev panel URLs to {out_file}", Fore.GREEN)
        
        # Save detailed results as JSON
        if results:
            json_file = os.path.join(self.results_dir, "panels_detailed.json")
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Save each category separately
            for category, urls in self.results.items():
                if urls:
                    category_file = os.path.join(self.results_dir, f"{category}.txt")
                    save_to_file(urls, category_file)
            
            # Create summary file
            summary_file = os.path.join(self.results_dir, "panels_summary.txt")
            with open(summary_file, 'w') as f:
                f.write("===== ADMIN & LOGIN PANELS SUMMARY =====\n\n")
                total = sum(len(urls) for urls in self.results.values())
                f.write(f"Total panels found: {total}\n\n")
                
                for category, urls in self.results.items():
                    if urls:
                        f.write(f"{category.replace('_', ' ').title()}: {len(urls)}\n")
                
                # List potentially vulnerable panels (those with default credentials)
                vulnerable_panels = [panel for panel in results if panel.get("default_creds")]
                if vulnerable_panels:
                    f.write("\n===== VULNERABLE PANELS (DEFAULT CREDENTIALS) =====\n\n")
                    for panel in vulnerable_panels:
                        creds = panel["default_creds"]
                        f.write(f"{panel['url']} - {creds['username']}:{creds['password']}\n")
                
                # List protected panels
                protected_panels = [panel for panel in results if panel.get("protection")]
                if protected_panels:
                    f.write("\n===== PROTECTED PANELS =====\n\n")
                    for panel in protected_panels:
                        protection = ", ".join(panel["protection"])
                        f.write(f"{panel['url']} - {protection}\n")
            
            print_colored(f"[+] Saved detailed panel information to {json_file}", Fore.GREEN)
            print_colored(f"[+] Created summary at {summary_file}", Fore.GREEN)

def fuzz_login_panels(domains, output_dir):
    finder = PanelFinder(domains, output_dir)
    return finder.find_panels()
