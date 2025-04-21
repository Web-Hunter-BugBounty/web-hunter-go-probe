
#!/usr/bin/env python3
"""
OSINT module for ReconArsenal
"""

import os
import re
import json
import concurrent.futures
from colorama import Fore
from .utils import print_colored, show_progress, save_to_file, check_command, get_command_output

def whois_lookup(domain, output_dir):
    """Perform WHOIS lookup on domain"""
    print_colored("[*] Performing WHOIS lookup...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    
    # Create directory if it doesn't exist
    if not os.path.exists(osint_dir):
        os.makedirs(osint_dir)
    
    whois_output = os.path.join(osint_dir, "whois.txt")
    
    # Check if whois command is available
    if check_command("whois"):
        whois_cmd = f"whois {domain} > {whois_output}"
        
        try:
            os.system(whois_cmd)
            print_colored(f"[+] WHOIS information saved to {whois_output}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running WHOIS lookup: {str(e)}", Fore.RED)
    
    else:
        print_colored("[!] WHOIS command not found. Using online service...", Fore.YELLOW)
        
        import requests
        
        try:
            response = requests.get(f"https://api.whoisfreaks.com/v1.0/whois?apiKey=demo&whois=live&domainName={domain}")
            
            if response.status_code == 200:
                with open(whois_output, 'w') as f:
                    f.write(json.dumps(response.json(), indent=2))
                
                print_colored(f"[+] WHOIS information saved to {whois_output}", Fore.GREEN)
            
            else:
                print_colored(f"[!] Error getting WHOIS information: {response.status_code}", Fore.RED)
        
        except Exception as e:
            print_colored(f"[!] Error getting WHOIS information: {str(e)}", Fore.RED)

def email_finder(domain, output_dir):
    """Find email addresses related to the domain"""
    print_colored("[*] Searching for email addresses...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    email_dir = os.path.join(osint_dir, "emails")
    
    # Create directory if it doesn't exist
    if not os.path.exists(email_dir):
        os.makedirs(email_dir)
    
    # Check for tools
    tools = {
        "emailfinder": check_command("emailfinder"),
        "theHarvester": check_command("theHarvester")
    }
    
    if not any(tools.values()):
        print_colored("[!] Email discovery tools not found. Using basic discovery...", Fore.YELLOW)
    
    emails = []
    
    # Use emailfinder if available
    if tools.get("emailfinder"):
        print_colored("[*] Using emailfinder...", Fore.BLUE)
        
        emailfinder_output = os.path.join(email_dir, "emailfinder.txt")
        emailfinder_cmd = f"emailfinder -d {domain} > {emailfinder_output}"
        
        try:
            os.system(emailfinder_cmd)
            
            # Read output
            with open(emailfinder_output, 'r') as f:
                for line in f:
                    if '@' in line:
                        email = line.strip()
                        emails.append(email)
            
            print_colored(f"[+] Found {len(emails)} email addresses using emailfinder", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running emailfinder: {str(e)}", Fore.RED)
    
    # Use theHarvester if available
    if tools.get("theHarvester"):
        print_colored("[*] Using theHarvester...", Fore.BLUE)
        
        harvester_output = os.path.join(email_dir, "theharvester.xml")
        harvester_cmd = f"theHarvester -d {domain} -b all -f {harvester_output}"
        
        try:
            os.system(harvester_cmd)
            
            # Parse XML output
            import xml.etree.ElementTree as ET
            
            if os.path.exists(harvester_output):
                tree = ET.parse(harvester_output)
                root = tree.getroot()
                
                for email in root.findall('.//email'):
                    emails.append(email.text.strip())
            
            print_colored(f"[+] Found {len(emails)} email addresses using theHarvester", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running theHarvester: {str(e)}", Fore.RED)
    
    # Use basic discovery if no tools are available
    if not tools.get("emailfinder") and not tools.get("theHarvester"):
        print_colored("[*] Using basic email discovery...", Fore.BLUE)
        
        import requests
        from bs4 import BeautifulSoup
        
        try:
            # Search Google for email patterns
            search_url = f"https://www.google.com/search?q=%22@{domain}%22"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(search_url, headers=headers)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                text = soup.get_text()
                
                # Find email patterns
                email_pattern = r'\b[A-Za-z0-9._%+-]+@' + re.escape(domain) + r'\b'
                found_emails = re.findall(email_pattern, text)
                
                emails.extend(found_emails)
            
            # Also check the website itself
            website_url = f"https://{domain}"
            
            response = requests.get(website_url, headers=headers)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                text = soup.get_text()
                
                # Find email patterns
                email_pattern = r'\b[A-Za-z0-9._%+-]+@' + re.escape(domain) + r'\b'
                found_emails = re.findall(email_pattern, text)
                
                emails.extend(found_emails)
            
            # Look in "Contact Us" page
            contact_url = f"https://{domain}/contact"
            
            response = requests.get(contact_url, headers=headers)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                text = soup.get_text()
                
                # Find email patterns
                email_pattern = r'\b[A-Za-z0-9._%+-]+@' + re.escape(domain) + r'\b'
                found_emails = re.findall(email_pattern, text)
                
                emails.extend(found_emails)
            
            print_colored(f"[+] Found {len(emails)} email addresses using basic discovery", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error during basic email discovery: {str(e)}", Fore.RED)
    
    # Remove duplicates
    emails = list(set(emails))
    
    # Save emails
    if emails:
        emails_file = os.path.join(email_dir, "emails.txt")
        save_to_file(emails, emails_file)
    
    return emails

def check_leaks(domain, output_dir):
    """Check for leaked credentials and data breaches"""
    print_colored("[*] Checking for leaked credentials and data breaches...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    leaks_dir = os.path.join(osint_dir, "leaks")
    
    # Create directory if it doesn't exist
    if not os.path.exists(leaks_dir):
        os.makedirs(leaks_dir)
    
    # Check for tools
    tools = {
        "h8mail": check_command("h8mail"),
        "pwnedOrNot": check_command("pwnedOrNot"),
        "LeakSearch": check_command("LeakSearch")
    }
    
    if not any(tools.values()):
        print_colored("[!] Leak checking tools not found. Using online services...", Fore.YELLOW)
    
    # Get email addresses
    emails_file = os.path.join(osint_dir, "emails", "emails.txt")
    
    if os.path.exists(emails_file):
        with open(emails_file, 'r') as f:
            emails = [line.strip() for line in f if line.strip()]
    else:
        # Try to find emails
        emails = email_finder(domain, output_dir)
    
    if not emails:
        print_colored("[-] No email addresses found to check for leaks", Fore.YELLOW)
        return []
    
    leaks = []
    
    # Save emails to file for tools
    emails_for_tools = os.path.join(leaks_dir, "emails_to_check.txt")
    save_to_file(emails, emails_for_tools)
    
    # Use h8mail if available
    if tools.get("h8mail"):
        print_colored("[*] Using h8mail to check for leaks...", Fore.BLUE)
        
        h8mail_output = os.path.join(leaks_dir, "h8mail_results.csv")
        h8mail_cmd = f"h8mail -t {emails_for_tools} -o {h8mail_output} -c h8mail_config.ini"
        
        try:
            os.system(h8mail_cmd)
            
            # Parse results
            if os.path.exists(h8mail_output):
                import csv
                
                with open(h8mail_output, 'r') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) > 1 and "BREACH FOUND" in ' '.join(row):
                            leaks.append(' '.join(row))
            
            print_colored(f"[+] h8mail found {len(leaks)} potential leaks", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running h8mail: {str(e)}", Fore.RED)
    
    # Use HaveIBeenPwned API
    else:
        print_colored("[*] Checking HaveIBeenPwned API...", Fore.BLUE)
        
        import time
        import requests
        
        hibp_leaks = []
        
        # HaveIBeenPwned API requires delays between requests
        for email in emails:
            try:
                # Note: HaveIBeenPwned API requires an API key now, this is just for demonstration
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                
                headers = {
                    'User-Agent': 'ReconArsenal',
                    'hibp-api-key': 'demo-key'  # Replace with actual API key in real usage
                }
                
                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    breaches = response.json()
                    
                    for breach in breaches:
                        leak = f"{email} found in breach: {breach['Name']} ({breach['BreachDate']})"
                        hibp_leaks.append(leak)
                
                # Wait to avoid rate limiting
                time.sleep(1.5)
            
            except Exception as e:
                pass
        
        if hibp_leaks:
            leaks.extend(hibp_leaks)
            print_colored(f"[+] HaveIBeenPwned API found {len(hibp_leaks)} potential leaks", Fore.GREEN)
    
    # Save leaks
    if leaks:
        leaks_file = os.path.join(leaks_dir, "found_leaks.txt")
        save_to_file(leaks, leaks_file)
    
    return leaks

def azure_tenant_mapper(domain, output_dir):
    """Map Microsoft 365 and Azure tenants"""
    print_colored("[*] Mapping Microsoft 365 and Azure tenants...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    azure_dir = os.path.join(osint_dir, "azure")
    
    # Create directory if it doesn't exist
    if not os.path.exists(azure_dir):
        os.makedirs(azure_dir)
    
    # Check for tools
    tools = {
        "msftrecon": check_command("msftrecon"),
        "o365creeper": check_command("o365creeper")
    }
    
    if not any(tools.values()):
        print_colored("[!] Azure/O365 reconnaissance tools not found. Using basic checks...", Fore.YELLOW)
    
    azure_results = []
    
    # Use msftrecon if available
    if tools.get("msftrecon"):
        print_colored("[*] Using msftrecon...", Fore.BLUE)
        
        msftrecon_output = os.path.join(azure_dir, "msftrecon_results.txt")
        msftrecon_cmd = f"msftrecon -d {domain} -o {msftrecon_output}"
        
        try:
            os.system(msftrecon_cmd)
            
            # Check if results file exists
            if os.path.exists(msftrecon_output):
                with open(msftrecon_output, 'r') as f:
                    for line in f:
                        azure_results.append(line.strip())
            
            print_colored(f"[+] msftrecon completed for {domain}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running msftrecon: {str(e)}", Fore.RED)
    
    # Use basic checks if no tools are available
    if not tools.get("msftrecon") and not tools.get("o365creeper"):
        print_colored("[*] Using basic Azure/O365 checks...", Fore.BLUE)
        
        import requests
        
        # Common Office 365 endpoints to check
        o365_endpoints = [
            f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration",
            f"https://login.microsoftonline.com/{domain}",
            f"https://{domain}.sharepoint.com",
            f"https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{domain}",
            f"https://outlook.office.com/autodiscover/autodiscover.svc",
            f"https://{domain.split('.')[0]}.onmicrosoft.com"
        ]
        
        for endpoint in o365_endpoints:
            try:
                response = requests.get(endpoint, timeout=10)
                
                if response.status_code != 404:
                    azure_results.append(f"Potential O365/Azure endpoint: {endpoint} (Status: {response.status_code})")
            
            except Exception as e:
                pass
        
        print_colored(f"[+] Basic Azure/O365 checks completed for {domain}", Fore.GREEN)
    
    # Save results
    if azure_results:
        azure_file = os.path.join(azure_dir, "azure_tenant_results.txt")
        save_to_file(azure_results, azure_file)
    
    return azure_results

def find_metadata(domain, output_dir):
    """Extract metadata from documents and files"""
    print_colored("[*] Searching for metadata in documents...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    metadata_dir = os.path.join(osint_dir, "metadata")
    
    # Create directory if it doesn't exist
    if not os.path.exists(metadata_dir):
        os.makedirs(metadata_dir)
    
    # Check for tools
    tools = {
        "MetaFinder": check_command("MetaFinder"),
        "metagoofil": check_command("metagoofil"),
        "exiftool": check_command("exiftool")
    }
    
    if not any(tools.values()):
        print_colored("[!] Metadata extraction tools not found. Using basic search...", Fore.YELLOW)
    
    metadata_results = []
    
    # Use MetaFinder if available
    if tools.get("MetaFinder"):
        print_colored("[*] Using MetaFinder...", Fore.BLUE)
        
        metafinder_output = os.path.join(metadata_dir, "metafinder_results.txt")
        metafinder_cmd = f"MetaFinder -d {domain} -o {metafinder_output}"
        
        try:
            os.system(metafinder_cmd)
            
            # Check if results file exists
            if os.path.exists(metafinder_output):
                with open(metafinder_output, 'r') as f:
                    for line in f:
                        metadata_results.append(line.strip())
            
            print_colored(f"[+] MetaFinder completed for {domain}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running MetaFinder: {str(e)}", Fore.RED)
    
    # Use metagoofil if available
    elif tools.get("metagoofil"):
        print_colored("[*] Using metagoofil...", Fore.BLUE)
        
        downloads_dir = os.path.join(metadata_dir, "downloads")
        
        if not os.path.exists(downloads_dir):
            os.makedirs(downloads_dir)
        
        metagoofil_output = os.path.join(metadata_dir, "metagoofil_results.html")
        metagoofil_cmd = f"metagoofil -d {domain} -t pdf,doc,docx,pptx,xlsx -o {downloads_dir} -f {metagoofil_output}"
        
        try:
            os.system(metagoofil_cmd)
            
            # Check if results file exists
            if os.path.exists(metagoofil_output):
                from bs4 import BeautifulSoup
                
                with open(metagoofil_output, 'r', encoding='utf-8', errors='ignore') as f:
                    soup = BeautifulSoup(f.read(), 'html.parser')
                    
                    # Extract metadata from HTML
                    for table in soup.find_all('table'):
                        for row in table.find_all('tr'):
                            metadata_results.append(' '.join([td.text for td in row.find_all('td')]))
            
            # Use exiftool on downloaded files if available
            if tools.get("exiftool") and os.path.exists(downloads_dir):
                for root, _, files in os.walk(downloads_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        exiftool_output = os.path.join(metadata_dir, f"{file}_metadata.txt")
                        exiftool_cmd = f"exiftool {file_path} > {exiftool_output}"
                        
                        try:
                            os.system(exiftool_cmd)
                            
                            # Check if results file exists
                            if os.path.exists(exiftool_output):
                                with open(exiftool_output, 'r') as f:
                                    for line in f:
                                        if "Author" in line or "Creator" in line or "Producer" in line or "Company" in line:
                                            metadata_results.append(f"{file}: {line.strip()}")
                        
                        except Exception as e:
                            pass
            
            print_colored(f"[+] metagoofil completed for {domain}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running metagoofil: {str(e)}", Fore.RED)
    
    # Use basic search if no tools are available
    else:
        print_colored("[*] Using basic metadata search...", Fore.BLUE)
        
        import requests
        from bs4 import BeautifulSoup
        
        # Search for document extensions
        extensions = ["pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx"]
        
        for ext in extensions:
            try:
                # Construct Google search URL (this is just for demonstration)
                search_url = f"https://www.google.com/search?q=site:{domain}+filetype:{ext}"
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                response = requests.get(search_url, headers=headers)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract search results
                    for result in soup.select('.r a'):
                        href = result.get('href')
                        
                        if href.startswith('/url?') and f".{ext}" in href:
                            metadata_results.append(f"Found document: {href}")
            
            except Exception as e:
                pass
        
        print_colored(f"[+] Basic metadata search completed for {domain}", Fore.GREEN)
    
    # Save results
    if metadata_results:
        metadata_file = os.path.join(metadata_dir, "metadata_results.txt")
        save_to_file(metadata_results, metadata_file)
    
    return metadata_results

def search_api_leaks(domain, output_dir):
    """Search for leaked API keys and credentials"""
    print_colored("[*] Searching for leaked API keys...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    api_dir = os.path.join(osint_dir, "api_leaks")
    
    # Create directory if it doesn't exist
    if not os.path.exists(api_dir):
        os.makedirs(api_dir)
    
    # Check for tools
    tools = {
        "porch-pirate": check_command("porch-pirate"),
        "SwaggerSpy": check_command("SwaggerSpy"),
        "keyhacks": check_command("keyhacks")
    }
    
    if not any(tools.values()):
        print_colored("[!] API leak scanning tools not found. Using basic search...", Fore.YELLOW)
    
    api_leaks = []
    
    # Use porch-pirate if available
    if tools.get("porch-pirate"):
        print_colored("[*] Using porch-pirate...", Fore.BLUE)
        
        pirate_output = os.path.join(api_dir, "porch_pirate_results.txt")
        pirate_cmd = f"porch-pirate -d {domain} -o {pirate_output}"
        
        try:
            os.system(pirate_cmd)
            
            # Check if results file exists
            if os.path.exists(pirate_output):
                with open(pirate_output, 'r') as f:
                    for line in f:
                        api_leaks.append(line.strip())
            
            print_colored(f"[+] porch-pirate completed for {domain}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running porch-pirate: {str(e)}", Fore.RED)
    
    # Use SwaggerSpy if available
    if tools.get("SwaggerSpy"):
        print_colored("[*] Using SwaggerSpy...", Fore.BLUE)
        
        swagger_output = os.path.join(api_dir, "swagger_spy_results.txt")
        swagger_cmd = f"SwaggerSpy -d {domain} -o {swagger_output}"
        
        try:
            os.system(swagger_cmd)
            
            # Check if results file exists
            if os.path.exists(swagger_output):
                with open(swagger_output, 'r') as f:
                    for line in f:
                        api_leaks.append(line.strip())
            
            print_colored(f"[+] SwaggerSpy completed for {domain}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running SwaggerSpy: {str(e)}", Fore.RED)
    
    # Use basic search if no tools are available
    if not tools.get("porch-pirate") and not tools.get("SwaggerSpy"):
        print_colored("[*] Using basic API leak search...", Fore.BLUE)
        
        import requests
        
        # Common API endpoints to check
        api_endpoints = [
            f"https://{domain}/api",
            f"https://{domain}/swagger",
            f"https://{domain}/swagger.json",
            f"https://{domain}/swagger-ui.html",
            f"https://{domain}/api-docs",
            f"https://{domain}/v1",
            f"https://{domain}/v2",
            f"https://{domain}/graphql"
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        for endpoint in api_endpoints:
            try:
                response = requests.get(endpoint, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    # Check for API keys in response
                    api_key_patterns = [
                        r'api[_-]key["\s\':]+([\w\d]+)',
                        r'apikey["\s\':]+([\w\d]+)',
                        r'authorization["\s\':]+([\w\d]+)',
                        r'access[_-]token["\s\':]+([\w\d]+)',
                        r'secret[_-]key["\s\':]+([\w\d]+)',
                        r'client[_-]secret["\s\':]+([\w\d]+)',
                        r'api[_-]secret["\s\':]+([\w\d]+)'
                    ]
                    
                    for pattern in api_key_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        
                        for match in matches:
                            leak = f"Potential API key found at {endpoint}: {match}"
                            api_leaks.append(leak)
            
            except Exception as e:
                pass
        
        print_colored(f"[+] Basic API leak search completed for {domain}", Fore.GREEN)
    
    # Save results
    if api_leaks:
        leaks_file = os.path.join(api_dir, "api_leaks.txt")
        save_to_file(api_leaks, leaks_file)
    
    return api_leaks

def run_google_dorks(domain, output_dir):
    """Run Google Dorks to find sensitive information"""
    print_colored("[*] Running Google Dorks...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    dorks_dir = os.path.join(osint_dir, "google_dorks")
    
    # Create directory if it doesn't exist
    if not os.path.exists(dorks_dir):
        os.makedirs(dorks_dir)
    
    # Check for tools
    tools = {
        "dorks_hunter": check_command("dorks_hunter"),
        "pagodo": check_command("pagodo"),
        "gdorklinks": check_command("gdorklinks")
    }
    
    if not any(tools.values()):
        print_colored("[!] Google Dorks tools not found. Using predefined dorks...", Fore.YELLOW)
    
    dorks_results = []
    
    # Use dorks_hunter if available
    if tools.get("dorks_hunter"):
        print_colored("[*] Using dorks_hunter...", Fore.BLUE)
        
        dorks_output = os.path.join(dorks_dir, "dorks_hunter_results.txt")
        dorks_cmd = f"dorks_hunter -d {domain} -o {dorks_output} -l 100"
        
        try:
            os.system(dorks_cmd)
            
            # Check if results file exists
            if os.path.exists(dorks_output):
                with open(dorks_output, 'r') as f:
                    for line in f:
                        dorks_results.append(line.strip())
            
            print_colored(f"[+] dorks_hunter completed for {domain}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running dorks_hunter: {str(e)}", Fore.RED)
    
    # Use predefined dorks if no tools are available
    else:
        print_colored("[*] Using predefined Google Dorks...", Fore.BLUE)
        
        # Predefined Google Dorks
        google_dorks = [
            f"site:{domain} intext:password",
            f"site:{domain} intext:'password' filetype:txt",
            f"site:{domain} intext:'username password' filetype:log",
            f"site:{domain} ext:sql intext:password",
            f"site:{domain} ext:php intitle:phpinfo 'published by the PHP Group'",
            f"site:{domain} inurl:config",
            f"site:{domain} intitle:index.of",
            f"site:{domain} inurl:wp-content",
            f"site:{domain} inurl:wp-config.php",
            f"site:{domain} ext:log",
            f"site:{domain} intext:apikey",
            f"site:{domain} inurl:admin",
            f"site:{domain} filetype:env",
            f"site:{domain} intext:jdbc:mysql",
            f"site:{domain} intext:JDBC",
            f"site:{domain} intext:sql",
            f"site:{domain} intext:SELECT FROM",
            f"site:{domain} ext:yml password",
            f"site:{domain} ext:xml password",
            f"site:{domain} ext:conf password",
            f"site:{domain} ext:cnf password",
            f"site:{domain} ext:bak",
            f"site:{domain} ext:old",
            f"site:{domain} inurl:login",
            f"site:{domain} inurl:signup",
            f"site:{domain} inurl:dev",
            f"site:{domain} inurl:staging",
            f"site:{domain} inurl:test",
            f"site:{domain} inurl:backup",
            f"site:{domain} filetype:sql",
            f"site:{domain} filetype:php"
        ]
        
        dorks_urls_file = os.path.join(dorks_dir, "google_dorks.txt")
        save_to_file(google_dorks, dorks_urls_file)
        
        dorks_results = [f"Generated Google Dork: {dork}" for dork in google_dorks]
        
        print_colored(f"[+] Generated {len(google_dorks)} Google Dorks for {domain}", Fore.GREEN)
    
    # Save results
    if dorks_results:
        results_file = os.path.join(dorks_dir, "google_dorks_results.txt")
        save_to_file(dorks_results, results_file)
    
    return dorks_results

def run_github_dorks(domain, output_dir):
    """Run GitHub Dorks to find sensitive information"""
    print_colored("[*] Running GitHub Dorks...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    github_dir = os.path.join(osint_dir, "github_dorks")
    
    # Create directory if it doesn't exist
    if not os.path.exists(github_dir):
        os.makedirs(github_dir)
    
    # Check for tools
    tools = {
        "gitdorks_go": check_command("gitdorks_go"),
        "gitrob": check_command("gitrob"),
        "trufflehog": check_command("trufflehog")
    }
    
    if not any(tools.values()):
        print_colored("[!] GitHub Dorks tools not found. Using predefined dorks...", Fore.YELLOW)
    
    github_results = []
    
    # Use gitdorks_go if available
    if tools.get("gitdorks_go"):
        print_colored("[*] Using gitdorks_go...", Fore.BLUE)
        
        # Expected format: organization name, not domain
        organization = domain.split('.')[0]
        
        gitdorks_output = os.path.join(github_dir, "gitdorks_results.txt")
        gitdorks_cmd = f"gitdorks_go -org {organization} -o {gitdorks_output}"
        
        try:
            os.system(gitdorks_cmd)
            
            # Check if results file exists
            if os.path.exists(gitdorks_output):
                with open(gitdorks_output, 'r') as f:
                    for line in f:
                        github_results.append(line.strip())
            
            print_colored(f"[+] gitdorks_go completed for {organization}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running gitdorks_go: {str(e)}", Fore.RED)
    
    # Use trufflehog if available
    elif tools.get("trufflehog"):
        print_colored("[*] Using trufflehog...", Fore.BLUE)
        
        # Expected format: organization name, not domain
        organization = domain.split('.')[0]
        
        trufflehog_output = os.path.join(github_dir, "trufflehog_results.txt")
        trufflehog_cmd = f"trufflehog github --org={organization} > {trufflehog_output}"
        
        try:
            os.system(trufflehog_cmd)
            
            # Check if results file exists
            if os.path.exists(trufflehog_output):
                with open(trufflehog_output, 'r') as f:
                    for line in f:
                        github_results.append(line.strip())
            
            print_colored(f"[+] trufflehog completed for {organization}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running trufflehog: {str(e)}", Fore.RED)
    
    # Use predefined dorks if no tools are available
    else:
        print_colored("[*] Using predefined GitHub Dorks...", Fore.BLUE)
        
        # Extract organization/company name from domain
        organization = domain.split('.')[0]
        
        # Predefined GitHub Dorks
        github_dorks = [
            f"org:{organization} password",
            f"org:{organization} api_key",
            f"org:{organization} apikey",
            f"org:{organization} api_secret",
            f"org:{organization} secret",
            f"org:{organization} token",
            f"org:{organization} aws_access_key",
            f"org:{organization} aws_secret",
            f"org:{organization} aws_key",
            f"org:{organization} secret_key",
            f"org:{organization} client_secret",
            f"org:{organization} client_id",
            f"org:{organization} ssh_key",
            f"org:{organization} private_key",
            f"org:{organization} private -language:java",
            f"org:{organization} key -language:java",
            f"org:{organization} token -language:java",
            f"org:{organization} login",
            f"org:{organization} password",
            f"org:{organization} dbpassword",
            f"org:{organization} ftp",
            f"org:{organization} jdbc",
            f"org:{organization} dotenv",
            f"org:{organization} db_password",
            f"org:{organization} db_username",
            f"org:{organization} DATABASE_URL",
            f"org:{organization} .env",
            f"org:{organization} .aws/credentials",
            f"org:{organization} .s3cfg",
            f"org:{organization} wp-config.php",
            f"org:{organization} /config/",
            f"org:{organization} node_modules",
            f"org:{organization} config",
            f"org:{organization} credentials",
            f"{domain} password",
            f"{domain} api_key",
            f"{domain} apikey",
            f"{domain} api_secret",
            f"{domain} secret",
            f"{domain} token",
            f"{domain} aws_access_key",
            f"{domain} aws_secret",
            f"{domain} aws_key",
            f"{domain} secret_key",
            f"{domain} client_secret",
            f"{domain} client_id",
            f"{domain} ssh_key",
            f"{domain} private_key"
        ]
        
        github_urls_file = os.path.join(github_dir, "github_dorks.txt")
        save_to_file(github_dorks, github_urls_file)
        
        github_results = [f"Generated GitHub Dork: {dork}" for dork in github_dorks]
        
        print_colored(f"[+] Generated {len(github_dorks)} GitHub Dorks for {domain}", Fore.GREEN)
    
    # Save results
    if github_results:
        results_file = os.path.join(github_dir, "github_dorks_results.txt")
        save_to_file(github_results, results_file)
    
    return github_results

def analyze_github_repos(domain, output_dir):
    """Analyze GitHub repositories for sensitive information"""
    print_colored("[*] Analyzing GitHub repositories...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    github_dir = os.path.join(osint_dir, "github_repos")
    
    # Create directory if it doesn't exist
    if not os.path.exists(github_dir):
        os.makedirs(github_dir)
    
    # Check for tools
    tools = {
        "enumerepo": check_command("enumerepo"),
        "trufflehog": check_command("trufflehog"),
        "gitleaks": check_command("gitleaks")
    }
    
    if not any(tools.values()):
        print_colored("[!] GitHub repository analysis tools not found. Using basic analysis...", Fore.YELLOW)
    
    # Extract organization/company name from domain
    organization = domain.split('.')[0]
    
    github_results = []
    
    # Use enumerepo if available
    if tools.get("enumerepo"):
        print_colored("[*] Using enumerepo...", Fore.BLUE)
        
        enumerepo_output = os.path.join(github_dir, "enumerepo_results.txt")
        enumerepo_cmd = f"enumerepo -o {organization} > {enumerepo_output}"
        
        try:
            os.system(enumerepo_cmd)
            
            # Check if results file exists
            if os.path.exists(enumerepo_output):
                with open(enumerepo_output, 'r') as f:
                    for line in f:
                        github_results.append(line.strip())
            
            print_colored(f"[+] enumerepo completed for {organization}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running enumerepo: {str(e)}", Fore.RED)
    
    # Use gitleaks if available
    if tools.get("gitleaks"):
        print_colored("[*] Using gitleaks...", Fore.BLUE)
        
        # If enumerepo found repositories, analyze them with gitleaks
        repos = []
        
        # Parse enumerepo results to get repository URLs
        if os.path.exists(enumerepo_output):
            with open(enumerepo_output, 'r') as f:
                for line in f:
                    if line.startswith("https://github.com/"):
                        repos.append(line.strip())
        
        # If no repositories found from enumerepo, use basic search
        if not repos:
            import requests
            
            try:
                # Search GitHub API for organization repositories
                url = f"https://api.github.com/orgs/{organization}/repos"
                
                response = requests.get(url)
                
                if response.status_code == 200:
                    for repo in response.json():
                        repos.append(repo["html_url"])
            
            except Exception as e:
                pass
        
        # Analyze each repository with gitleaks
        for repo in repos:
            repo_name = repo.split("/")[-1]
            gitleaks_output = os.path.join(github_dir, f"gitleaks_{repo_name}.json")
            gitleaks_cmd = f"gitleaks detect -r {repo} -o {gitleaks_output} -f json"
            
            try:
                os.system(gitleaks_cmd)
                
                # Check if results file exists and has content
                if os.path.exists(gitleaks_output) and os.path.getsize(gitleaks_output) > 0:
                    with open(gitleaks_output, 'r') as f:
                        try:
                            import json
                            leaks = json.load(f)
                            
                            for leak in leaks:
                                github_results.append(f"Leak found in {repo_name}: {leak.get('Description', 'Unknown leak')} - {leak.get('File', 'Unknown file')}")
                        
                        except json.JSONDecodeError:
                            pass
            
            except Exception as e:
                pass
        
        print_colored(f"[+] gitleaks completed for {len(repos)} repositories", Fore.GREEN)
    
    # If no tools are available, use basic GitHub search
    if not tools.get("enumerepo") and not tools.get("gitleaks") and not tools.get("trufflehog"):
        print_colored("[*] Using basic GitHub search...", Fore.BLUE)
        
        import requests
        
        try:
            # Search GitHub API for organization repositories
            url = f"https://api.github.com/orgs/{organization}/repos"
            
            response = requests.get(url)
            
            if response.status_code == 200:
                github_results.append(f"Found {len(response.json())} repositories for {organization}:")
                
                for repo in response.json():
                    github_results.append(f"- {repo['html_url']} ({repo['description']})")
            
            else:
                # Search GitHub API for repositories mentioning the domain
                url = f"https://api.github.com/search/repositories?q={domain}"
                
                response = requests.get(url)
                
                if response.status_code == 200:
                    github_results.append(f"Found {len(response.json().get('items', []))} repositories mentioning {domain}:")
                    
                    for repo in response.json().get('items', []):
                        github_results.append(f"- {repo['html_url']} ({repo['description']})")
        
        except Exception as e:
            pass
        
        print_colored(f"[+] Basic GitHub search completed for {organization}", Fore.GREEN)
    
    # Save results
    if github_results:
        results_file = os.path.join(github_dir, "github_repos_analysis.txt")
        save_to_file(github_results, results_file)
    
    return github_results

def check_misconfigurations(domain, output_dir):
    """Check for 3rd party misconfigurations"""
    print_colored("[*] Checking for 3rd party misconfigurations...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    misconfig_dir = os.path.join(osint_dir, "misconfigurations")
    
    # Create directory if it doesn't exist
    if not os.path.exists(misconfig_dir):
        os.makedirs(misconfig_dir)
    
    # Check for tools
    tools = {
        "misconfig-mapper": check_command("misconfig-mapper"),
        "nuclei": check_command("nuclei")
    }
    
    if not any(tools.values()):
        print_colored("[!] Misconfiguration checking tools not found. Using basic checks...", Fore.YELLOW)
    
    misconfig_results = []
    
    # Use misconfig-mapper if available
    if tools.get("misconfig-mapper"):
        print_colored("[*] Using misconfig-mapper...", Fore.BLUE)
        
        misconfig_output = os.path.join(misconfig_dir, "misconfig_mapper_results.txt")
        misconfig_cmd = f"misconfig-mapper -d {domain} -o {misconfig_output}"
        
        try:
            os.system(misconfig_cmd)
            
            # Check if results file exists
            if os.path.exists(misconfig_output):
                with open(misconfig_output, 'r') as f:
                    for line in f:
                        misconfig_results.append(line.strip())
            
            print_colored(f"[+] misconfig-mapper completed for {domain}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running misconfig-mapper: {str(e)}", Fore.RED)
    
    # Use nuclei for misconfiguration templates if available
    elif tools.get("nuclei"):
        print_colored("[*] Using nuclei for misconfiguration checks...", Fore.BLUE)
        
        nuclei_output = os.path.join(misconfig_dir, "nuclei_misconfig_results.txt")
        nuclei_cmd = f"nuclei -u https://{domain} -t misconfigurations/ -o {nuclei_output}"
        
        try:
            os.system(nuclei_cmd)
            
            # Check if results file exists
            if os.path.exists(nuclei_output):
                with open(nuclei_output, 'r') as f:
                    for line in f:
                        misconfig_results.append(line.strip())
            
            print_colored(f"[+] nuclei misconfiguration check completed for {domain}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running nuclei: {str(e)}", Fore.RED)
    
    # Use basic checks if no tools are available
    else:
        print_colored("[*] Using basic misconfiguration checks...", Fore.BLUE)
        
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        
        # Suppress SSL warnings
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        
        # Common misconfiguration checks
        checks = [
            # CORS misconfiguration
            {
                "name": "CORS Misconfiguration",
                "url": f"https://{domain}",
                "headers": {"Origin": "https://evil.com"},
                "check": lambda r: "Access-Control-Allow-Origin: https://evil.com" in str(r.headers) or "Access-Control-Allow-Origin: *" in str(r.headers)
            },
            # Missing security headers
            {
                "name": "Missing Security Headers",
                "url": f"https://{domain}",
                "headers": {},
                "check": lambda r: "X-XSS-Protection" not in str(r.headers) or "X-Frame-Options" not in str(r.headers) or "Content-Security-Policy" not in str(r.headers)
            },
            # Directory listing
            {
                "name": "Directory Listing",
                "url": f"https://{domain}/images/",
                "headers": {},
                "check": lambda r: "Index of /images" in r.text or "Directory Listing" in r.text
            },
            # PHP info exposure
            {
                "name": "PHP Info Exposure",
                "url": f"https://{domain}/phpinfo.php",
                "headers": {},
                "check": lambda r: "PHP Version" in r.text and "phpinfo()" in r.text
            },
            # .git exposure
            {
                "name": ".git Directory Exposure",
                "url": f"https://{domain}/.git/HEAD",
                "headers": {},
                "check": lambda r: "ref: refs/heads/" in r.text
            },
            # .env exposure
            {
                "name": ".env File Exposure",
                "url": f"https://{domain}/.env",
                "headers": {},
                "check": lambda r: "DB_PASSWORD" in r.text or "API_KEY" in r.text
            },
            # robots.txt sensitive entries
            {
                "name": "Sensitive robots.txt",
                "url": f"https://{domain}/robots.txt",
                "headers": {},
                "check": lambda r: "Disallow: /admin" in r.text or "Disallow: /user" in r.text or "Disallow: /private" in r.text
            },
            # Backup files
            {
                "name": "Backup File Exposure",
                "url": f"https://{domain}/backup.zip",
                "headers": {},
                "check": lambda r: r.status_code == 200 and "application/zip" in r.headers.get("Content-Type", "")
            }
        ]
        
        for check in checks:
            try:
                response = requests.get(check["url"], headers=check["headers"], timeout=10, verify=False)
                
                if check["check"](response):
                    result = f"Potential {check['name']} at {check['url']}"
                    misconfig_results.append(result)
            
            except Exception as e:
                pass
        
        print_colored(f"[+] Basic misconfiguration checks completed for {domain}", Fore.GREEN)
    
    # Save results
    if misconfig_results:
        results_file = os.path.join(misconfig_dir, "misconfiguration_results.txt")
        save_to_file(misconfig_results, results_file)
    
    return misconfig_results

def check_spoofable_domains(domain, output_dir):
    """Check for spoofable domains"""
    print_colored("[*] Checking for spoofable domains...", Fore.BLUE)
    
    osint_dir = os.path.join(output_dir, "osint")
    spoofable_dir = os.path.join(osint_dir, "spoofable")
    
    # Create directory if it doesn't exist
    if not os.path.exists(spoofable_dir):
        os.makedirs(spoofable_dir)
    
    # Check for tools
    tools = {
        "spoofcheck": check_command("spoofcheck"),
        "mailspoof": check_command("mailspoof")
    }
    
    if not any(tools.values()):
        print_colored("[!] Email spoofing check tools not found. Using basic checks...", Fore.YELLOW)
    
    spoofable_results = []
    
    # Use spoofcheck if available
    if tools.get("spoofcheck"):
        print_colored("[*] Using spoofcheck...", Fore.BLUE)
        
        spoofcheck_output = os.path.join(spoofable_dir, "spoofcheck_results.txt")
        spoofcheck_cmd = f"spoofcheck {domain} > {spoofcheck_output}"
        
        try:
            os.system(spoofcheck_cmd)
            
            # Check if results file exists
            if os.path.exists(spoofcheck_output):
                with open(spoofcheck_output, 'r') as f:
                    for line in f:
                        spoofable_results.append(line.strip())
            
            print_colored(f"[+] spoofcheck completed for {domain}", Fore.GREEN)
        
        except Exception as e:
            print_colored(f"[!] Error running spoofcheck: {str(e)}", Fore.RED)
    
    # Use basic DNS checks if no tools are available
    else:
        print_colored("[*] Using basic DNS checks for email spoofing protection...", Fore.BLUE)
        
        import dns.resolver
        
        spf_found = False
        dmarc_found = False
        
        # Check SPF record
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_string = txt_string.decode('utf-8')
                    
                    if txt_string.startswith('v=spf1'):
                        spf_found = True
                        spoofable_results.append(f"SPF Record found: {txt_string}")
        
        except Exception as e:
            spoofable_results.append("No SPF record found. Domain may be spoofable.")
        
        # Check DMARC record
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_string = txt_string.decode('utf-8')
                    
                    if txt_string.startswith('v=DMARC1'):
                        dmarc_found = True
                        spoofable_results.append(f"DMARC Record found: {txt_string}")
        
        except Exception as e:
            spoofable_results.append("No DMARC record found. Domain may be spoofable.")
        
        # Summary
        if not spf_found and not dmarc_found:
            spoofable_results.append("VULNERABLE: No SPF or DMARC records found. Domain is likely spoofable.")
        elif not spf_found:
            spoofable_results.append("POTENTIALLY VULNERABLE: No SPF record found.")
        elif not dmarc_found:
            spoofable_results.append("POTENTIALLY VULNERABLE: No DMARC record found.")
        else:
            policy_strength = "Unknown"
            
            for result in spoofable_results:
                if "p=none" in result:
                    policy_strength = "Weak"
                elif "p=quarantine" in result:
                    policy_strength = "Medium"
                elif "p=reject" in result:
                    policy_strength = "Strong"
            
            if policy_strength == "Weak":
                spoofable_results.append("PARTIALLY PROTECTED: SPF and DMARC found, but policy is set to 'none'.")
            elif policy_strength == "Medium":
                spoofable_results.append("MODERATELY PROTECTED: SPF and DMARC found with 'quarantine' policy.")
            elif policy_strength == "Strong":
                spoofable_results.append("WELL PROTECTED: SPF and DMARC found with 'reject' policy.")
            else:
                spoofable_results.append("PROTECTED: SPF and DMARC records found.")
        
        print_colored(f"[+] Basic spoofing protection checks completed for {domain}", Fore.GREEN)
    
    # Save results
    if spoofable_results:
        results_file = os.path.join(spoofable_dir, "spoofable_results.txt")
        save_to_file(spoofable_results, results_file)
    
    return spoofable_results
