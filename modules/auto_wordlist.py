
#!/usr/bin/env python3
"""
Source-based Payload/Wordlist Builder: Collects input names, likely parameters, and words from JS/HTML for future fuzzing, auto-learning.
"""
import os
import re
import json
import hashlib
import requests
from urllib.parse import urlparse, parse_qs
from colorama import Fore
from tqdm import tqdm
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from .utils import print_colored, save_to_file

class WordlistBuilder:
    def __init__(self, endpoints, output_dir, max_workers=5):
        self.endpoints = endpoints
        self.output_dir = output_dir
        self.max_workers = max_workers
        
        # Various word categories
        self.input_names = set()
        self.param_names = set()
        self.form_fields = set()
        self.js_variables = set()
        self.api_paths = set()
        self.common_terms = set()
        self.custom_words = set()
        
        # Results by source type
        self.results_by_source = {
            "html_forms": [],
            "javascript": [],
            "parameters": [],
            "api_patterns": []
        }
        
        # Configure custom headers for requests
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        }
        
        # Create output directory
        self.wordlist_dir = os.path.join(output_dir, "fuzzing")
        if not os.path.exists(self.wordlist_dir):
            os.makedirs(self.wordlist_dir)
    
    def extract_from_html(self, url):
        """Extract input names, form fields, and other interesting elements from HTML"""
        try:
            response = requests.get(url, headers=self.headers, timeout=10, verify=False)
            if response.status_code != 200:
                return None
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extract from input fields
            form_fields = set()
            for input_tag in soup.find_all("input"):
                if input_tag.get("name"):
                    field_name = input_tag.get("name")
                    form_fields.add(field_name)
                    
                    # Special fields that might be reused elsewhere
                    if input_tag.get("type") in ["hidden", "text", "password", "email"]:
                        if field_name not in ["submit", "button", "cancel"]:
                            self.form_fields.add(field_name)
            
            # Extract from select fields
            for select_tag in soup.find_all("select"):
                if select_tag.get("name"):
                    form_fields.add(select_tag.get("name"))
                    self.form_fields.add(select_tag.get("name"))
            
            # Extract from textareas
            for textarea in soup.find_all("textarea"):
                if textarea.get("name"):
                    form_fields.add(textarea.get("name"))
                    self.form_fields.add(textarea.get("name"))
            
            # Extract from buttons
            for button in soup.find_all("button"):
                if button.get("name"):
                    form_fields.add(button.get("name"))
            
            # Extract from forms
            for form in soup.find_all("form"):
                if form.get("action"):
                    action = form.get("action")
                    if action.startswith("/"):
                        action_parts = action.split("/")
                        for part in action_parts:
                            if part and len(part) > 2:
                                self.api_paths.add(part)
            
            # Extract classes and IDs that might be important
            for tag in soup.find_all(class_=True):
                for class_name in tag["class"]:
                    if len(class_name) > 3 and not class_name.startswith(("fa-", "icon-", "ui-")):
                        self.common_terms.add(class_name)
            
            for tag in soup.find_all(id=True):
                if len(tag["id"]) > 3 and not tag["id"].startswith(("fa-", "icon-", "ui-")):
                    self.common_terms.add(tag["id"])
            
            # Extract meta tags
            for meta in soup.find_all("meta"):
                if meta.get("name") and len(meta.get("name")) > 2:
                    self.common_terms.add(meta.get("name"))
            
            return form_fields
        except:
            return None
    
    def extract_from_javascript(self, url):
        """Extract variable names, functions, and patterns from JavaScript files"""
        try:
            # Only process .js files
            if not url.endswith(".js"):
                return None
                
            response = requests.get(url, headers=self.headers, timeout=10, verify=False)
            if response.status_code != 200:
                return None
            
            js_content = response.text
            js_variables = set()
            
            # Extract variable declarations
            var_patterns = [
                r'var\s+([a-zA-Z0-9_$]+)\s*=',
                r'let\s+([a-zA-Z0-9_$]+)\s*=',
                r'const\s+([a-zA-Z0-9_$]+)\s*=',
                r'function\s+([a-zA-Z0-9_$]+)\s*\(',
                r'\.([a-zA-Z0-9_$]+)\s*=\s*function',
                r'([a-zA-Z0-9_$]+):\s*function',
                r'class\s+([a-zA-Z0-9_$]+)'
            ]
            
            for pattern in var_patterns:
                for match in re.findall(pattern, js_content):
                    if match and len(match) > 2 and not match.startswith(("_", "$")):
                        js_variables.add(match)
            
            # Extract from object properties
            prop_pattern = r'[\'"]([a-zA-Z0-9_$]+)[\'"]:\s*[\'"`].+[\'"`]'
            for match in re.findall(prop_pattern, js_content):
                if match and len(match) > 2:
                    js_variables.add(match)
            
            # Extract API-related patterns
            api_patterns = [
                r'url:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'path:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'endpoint:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'api:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'route:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.get\([\'"`]([^\'"`]+)[\'"`]',
                r'\.post\([\'"`]([^\'"`]+)[\'"`]',
                r'\.put\([\'"`]([^\'"`]+)[\'"`]',
                r'\.delete\([\'"`]([^\'"`]+)[\'"`]'
            ]
            
            api_paths = set()
            for pattern in api_patterns:
                for match in re.findall(pattern, js_content):
                    if match and match.startswith("/"):
                        path_parts = match.split("/")
                        for part in path_parts:
                            if part and len(part) > 2:
                                api_paths.add(part)
            
            # Extract parameter names from URL patterns
            param_pattern = r'/:[a-zA-Z0-9_]+|{([a-zA-Z0-9_]+)}'
            for match in re.findall(param_pattern, js_content):
                if match and len(match) > 2:
                    self.param_names.add(match)
            
            return {
                "variables": js_variables,
                "api_paths": api_paths
            }
        except:
            return None
    
    def extract_from_url_parameters(self, url):
        """Extract parameter names from URL query strings"""
        try:
            parsed = urlparse(url)
            if not parsed.query:
                return None
                
            params = parse_qs(parsed.query)
            return set(params.keys())
        except:
            return None
    
    def generate_combined_wordlist(self):
        """Generate a combined wordlist from all collected sources"""
        all_words = set()
        
        # Add words from all sources
        all_words.update(self.input_names)
        all_words.update(self.param_names)
        all_words.update(self.form_fields)
        all_words.update(self.js_variables)
        all_words.update(self.api_paths)
        all_words.update(self.common_terms)
        all_words.update(self.custom_words)
        
        # Filter out very short or very long words
        filtered_words = {word for word in all_words if 3 <= len(word) <= 30}
        
        # Sort and return
        return sorted(list(filtered_words))
    
    def generate_categorized_wordlists(self):
        """Generate separate wordlists for different categories"""
        categories = {
            "input_fields": self.form_fields,
            "parameters": self.param_names,
            "javascript": self.js_variables,
            "api_paths": self.api_paths,
            "common_terms": self.common_terms
        }
        
        for category, words in categories.items():
            if words:
                file_path = os.path.join(self.wordlist_dir, f"{category}_wordlist.txt")
                save_to_file(sorted(list(words)), file_path)
                print_colored(f"[+] Saved {len(words)} {category} terms to {file_path}", Fore.GREEN)
    
    def enrich_with_custom_words(self):
        """Enrich the wordlist with custom derived words"""
        for word in list(self.form_fields) + list(self.param_names) + list(self.js_variables):
            # Add plurals
            if word.endswith("s"):
                self.custom_words.add(word[:-1])  # Remove trailing 's'
            else:
                self.custom_words.add(word + "s")  # Add trailing 's'
            
            # Add common variations
            self.custom_words.add(word + "_id")
            self.custom_words.add(word + "Id")
            self.custom_words.add(word + "_token")
            self.custom_words.add(word + "Token")
            self.custom_words.add(word + "_key")
            self.custom_words.add(word + "Key")
            
            # Convert camelCase to snake_case and vice versa
            if "_" in word:
                # snake_case to camelCase
                parts = word.split("_")
                camel = parts[0] + "".join(p.title() for p in parts[1:])
                self.custom_words.add(camel)
            else:
                # Try to convert camelCase to snake_case
                snake = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', word).lower()
                if snake != word:
                    self.custom_words.add(snake)
    
    def build_wordlist(self):
        """Run the complete wordlist building process"""
        print_colored("[*] Auto-building wordlist from sources...", Fore.BLUE)
        
        # Extract from HTML forms
        print_colored("[*] Extracting from HTML sources...", Fore.BLUE)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.extract_from_html, url): url for url in self.endpoints}
            
            for future in tqdm(future_to_url, desc="Processing HTML"):
                url = future_to_url[future]
                try:
                    form_fields = future.result()
                    if form_fields:
                        self.results_by_source["html_forms"].append({
                            "url": url,
                            "fields": list(form_fields)
                        })
                except Exception as e:
                    pass
        
        # Extract from JavaScript
        print_colored("[*] Extracting from JavaScript...", Fore.BLUE)
        js_files = [url for url in self.endpoints if url.endswith(".js")]
        
        if js_files:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_js = {executor.submit(self.extract_from_javascript, url): url for url in js_files[:50]}
                
                for future in tqdm(future_to_js, desc="Processing JS"):
                    url = future_to_js[future]
                    try:
                        js_data = future.result()
                        if js_data:
                            self.js_variables.update(js_data["variables"])
                            self.api_paths.update(js_data["api_paths"])
                            
                            self.results_by_source["javascript"].append({
                                "url": url,
                                "variables": list(js_data["variables"]),
                                "api_paths": list(js_data["api_paths"])
                            })
                    except Exception as e:
                        pass
        
        # Extract from URL parameters
        print_colored("[*] Extracting from URL parameters...", Fore.BLUE)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.extract_from_url_parameters, url): url for url in self.endpoints}
            
            for future in tqdm(future_to_url, desc="Processing URLs"):
                url = future_to_url[future]
                try:
                    params = future.result()
                    if params:
                        self.param_names.update(params)
                        
                        self.results_by_source["parameters"].append({
                            "url": url,
                            "params": list(params)
                        })
                except Exception as e:
                    pass
        
        # Generate custom enrichments
        self.enrich_with_custom_words()
        
        # Generate combined wordlist
        wordlist = self.generate_combined_wordlist()
        
        # Save wordlists
        main_wordlist_file = os.path.join(self.wordlist_dir, "learned_wordlist.txt")
        save_to_file(wordlist, main_wordlist_file)
        print_colored(f"[+] Learned {len(wordlist)} words/params from sources, saved to {main_wordlist_file}", Fore.GREEN)
        
        # Save JSON report with all data
        report_file = os.path.join(self.wordlist_dir, "wordlist_report.json")
        report = {
            "summary": {
                "total_words": len(wordlist),
                "form_fields": len(self.form_fields),
                "parameters": len(self.param_names),
                "js_variables": len(self.js_variables),
                "api_paths": len(self.api_paths),
                "common_terms": len(self.common_terms),
                "custom_words": len(self.custom_words)
            },
            "results_by_source": self.results_by_source
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate categorized wordlists
        self.generate_categorized_wordlists()
        
        return wordlist

def harvest_wordlist_from_sources(endpoints, output_dir):
    builder = WordlistBuilder(endpoints, output_dir)
    return builder.build_wordlist()
