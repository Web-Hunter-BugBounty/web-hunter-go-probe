#!/usr/bin/env python3
"""
Utility functions for Web-Hunter
"""

import os
import re
import time
import sys
import ipaddress
import socket
import random
import string
import shutil
import urllib3
import platform
import subprocess
from datetime import datetime
from colorama import Fore, Style, Back, init
from tqdm import tqdm

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Suppress only the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define custom colors for enhanced UI
MAIN_COLOR = Fore.CYAN
SUCCESS_COLOR = Fore.GREEN
WARNING_COLOR = Fore.YELLOW
ERROR_COLOR = Fore.RED
INFO_COLOR = Fore.BLUE
HIGHLIGHT_COLOR = Fore.MAGENTA
BRIGHT = Style.BRIGHT

# Box drawing characters for beautiful output
BOX_CHARS = {
    "top_left": "╔",
    "top_right": "╗",
    "bottom_left": "╚",
    "bottom_right": "╝",
    "horizontal": "═",
    "vertical": "║",
    "left_connector": "╠",
    "right_connector": "╣",
    "up_connector": "╩",
    "down_connector": "╦",
    "cross": "╬"
}

# Status symbols
STATUS_SYMBOLS = {
    "success": "✓",
    "error": "✗",
    "warning": "⚠",
    "info": "ℹ",
    "pending": "⏳",
    "question": "?",
    "bullet": "•",
    "arrow": "→",
    "star": "★"
}

def print_colored(text, color=Fore.WHITE, **kwargs):
    """Print colored text with support for end parameter"""
    print(f"{color}{text}{Style.RESET_ALL}", **kwargs)

def animate_text(text, color=Fore.CYAN, delay=0.03):
    """Animate text typing"""
    for char in text:
        sys.stdout.write(f"{color}{char}{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_spinner(seconds, text="Processing", color=MAIN_COLOR):
    """Show a spinner animation for a specified number of seconds"""
    spinners = [
        ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'],
        ['◜', '◠', '◝', '◞', '◡', '◟'],
        ['⬒', '⬔', '⬓', '⬕'],
        ['▁', '▃', '▄', '▅', '▆', '▇', '█', '▇', '▆', '▅', '▄', '▃'],
        ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
        ['▉', '▊', '▋', '▌', '▍', '▎', '▏', '▎', '▍', '▌', '▋', '▊', '▉'],
        ['▖', '▘', '▝', '▗'],
        ['▌', '▀', '▐', '▄']
    ]
    
    # Choose a random spinner style
    spinner = random.choice(spinners)
    
    start_time = time.time()
    i = 0
    while time.time() - start_time < seconds:
        sys.stdout.write(f"\r{color}{text} {spinner[i % len(spinner)]}{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write(f"\r{' ' * (len(text) + 10)}\r")
    sys.stdout.flush()

def show_progress(total, description="Processing", color=MAIN_COLOR):
    """Show an enhanced progress bar"""
    bar_format = "{desc}: {percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
    return tqdm(
        total=total, 
        desc=f"{color}{description}{Style.RESET_ALL}", 
        bar_format=bar_format,
        ncols=80,
        colour='cyan'
    )

def validate_domain(domain):
    """Validate domain format"""
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, domain))

def validate_ip(ip):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def parse_cidr(cidr):
    """Parse CIDR notation to get list of IPs"""
    try:
        ip_network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in ip_network.hosts()]
    except ValueError:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Invalid CIDR format: {cidr}", ERROR_COLOR)
        return []

def load_targets_from_file(file_path):
    """Load targets (domains, IPs, or URLs) from a file"""
    try:
        if not os.path.exists(file_path):
            print_colored(f"[{STATUS_SYMBOLS['error']}] File not found: {file_path}", ERROR_COLOR)
            return []
            
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        print_colored(f"[{STATUS_SYMBOLS['success']}] Loaded {len(targets)} targets from {os.path.basename(file_path)}", SUCCESS_COLOR)
        return targets
    except Exception as e:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Error loading targets from {file_path}: {str(e)}", ERROR_COLOR)
        return []

def create_project_directory(base_dir, project_name):
    """Create project directory structure with enhanced feedback"""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_dir = os.path.join(base_dir, f"{project_name}_{timestamp}")
    
    subdirs = [
        "subdomains",
        "ports",
        "technologies",
        "endpoints",
        "vulnerabilities",
        "js_analysis",
        "bypass",
        "cloud_assets",
        "osint",
        "screenshots",
        "reports",
        "attack_chain",
        "fuzzing",
        "live_recon",
        "security_headers",
        "cve_detection",
        "correlation",
        "dns_mutation",
        "spidering",
        "github_recon",
        "api_inventory",
        "typosquatting",
        "asset_tagging",
        "csp_cors",
        "risk_tagging",
        "secrets"
    ]
    
    try:
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        
        # Create main output directory
        os.makedirs(output_dir)
        
        # Print header
        print_colored("\n" + BOX_CHARS["top_left"] + BOX_CHARS["horizontal"] * 60 + BOX_CHARS["top_right"], INFO_COLOR)
        print_colored(f"{BOX_CHARS['vertical']} Creating Project Structure{' ' * 36}{BOX_CHARS['vertical']}", INFO_COLOR)
        print_colored(BOX_CHARS["left_connector"] + BOX_CHARS["horizontal"] * 60 + BOX_CHARS["right_connector"], INFO_COLOR)
        
        # Create subdirectories with visual feedback
        for i, subdir in enumerate(subdirs):
            full_path = os.path.join(output_dir, subdir)
            os.makedirs(full_path)
            
            # Calculate percentage
            percentage = int((i + 1) / len(subdirs) * 100)
            bar_length = int(percentage / 2)
            
            # Display stylish progress
            print_colored(f"{BOX_CHARS['vertical']} {subdir}{' ' * (15 - len(subdir))} [{Fore.GREEN}{'█' * bar_length}{' ' * (50 - bar_length)}{Fore.BLUE}] {percentage:3d}%{BOX_CHARS['vertical']}", INFO_COLOR)
            time.sleep(0.05)  # Small delay for visual effect
        
        # Print footer
        print_colored(BOX_CHARS["bottom_left"] + BOX_CHARS["horizontal"] * 60 + BOX_CHARS["bottom_right"], INFO_COLOR)
        
        # Print completion message
        print_colored(f"\n[{STATUS_SYMBOLS['success']}] Project directory created: {output_dir}", SUCCESS_COLOR)
        print_colored(f"    {STATUS_SYMBOLS['arrow']} Timestamp: {timestamp}", INFO_COLOR)
        print_colored(f"    {STATUS_SYMBOLS['arrow']} Total directories: {len(subdirs) + 1}", INFO_COLOR)
        
        return output_dir
    
    except Exception as e:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Error creating directories: {str(e)}", ERROR_COLOR)
        sys.exit(1)

def save_to_file(data, filepath, is_list=True):
    """Save data to file with enhanced feedback"""
    try:
        # Create directory if it doesn't exist
        directory = os.path.dirname(filepath)
        if not os.path.exists(directory):
            os.makedirs(directory)
            
        with open(filepath, 'w') as f:
            if is_list:
                f.write('\n'.join(data))
            else:
                f.write(data)
        
        print_colored(f"[{STATUS_SYMBOLS['success']}] Data saved to {os.path.basename(filepath)}", SUCCESS_COLOR)
        return True
    except Exception as e:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Error saving to file {filepath}: {str(e)}", ERROR_COLOR)
        return False

def read_file(filepath):
    """Read data from file with enhanced feedback"""
    try:
        if not os.path.exists(filepath):
            print_colored(f"[{STATUS_SYMBOLS['error']}] File not found: {filepath}", ERROR_COLOR)
            return []
            
        with open(filepath, 'r') as f:
            data = [line.strip() for line in f if line.strip()]
        
        print_colored(f"[{STATUS_SYMBOLS['success']}] Read {len(data)} lines from {os.path.basename(filepath)}", SUCCESS_COLOR)
        return data
    except Exception as e:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Error reading file {filepath}: {str(e)}", ERROR_COLOR)
        return []

def check_command(command):
    """Check if a command exists in the system"""
    return shutil.which(command) is not None

def generate_random_string(length=10):
    """Generate a random string"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def get_command_output(command):
    """Execute a command and return its output with enhanced feedback"""
    try:
        print_colored(f"[{STATUS_SYMBOLS['info']}] Running: {command}", INFO_COLOR)
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Command execution error: {str(e)}", ERROR_COLOR)
        if e.stderr:
            print_colored(f"[{STATUS_SYMBOLS['error']}] Error details: {e.stderr.strip()}", ERROR_COLOR)
        return ""
    except Exception as e:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Error executing command: {str(e)}", ERROR_COLOR)
        return ""

def print_section_header(title, width=80):
    """Print a formatted section header"""
    title_len = len(title)
    padding = (width - title_len - 4) // 2
    extra = (width - title_len - 4) % 2  # Handle odd widths
    
    print()
    print_colored(BOX_CHARS["top_left"] + BOX_CHARS["horizontal"] * width + BOX_CHARS["top_right"], HIGHLIGHT_COLOR)
    print_colored(BOX_CHARS["vertical"] + " " * padding + f"{BRIGHT}{title}" + " " * (padding + extra) + BOX_CHARS["vertical"], HIGHLIGHT_COLOR)
    print_colored(BOX_CHARS["bottom_left"] + BOX_CHARS["horizontal"] * width + BOX_CHARS["bottom_right"], HIGHLIGHT_COLOR)
    print()

def print_status(message, status, success=True):
    """Print a status message with icon"""
    icon = STATUS_SYMBOLS["success"] if success else STATUS_SYMBOLS["error"]
    color = SUCCESS_COLOR if success else ERROR_COLOR
    print_colored(f"[{icon}] {message}: {status}", color)

def print_table(headers, data, color=INFO_COLOR):
    """Print a formatted table with data"""
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in data:
        for i, col in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(col)))
    
    # Add some padding
    col_widths = [w + 2 for w in col_widths]
    
    # Calculate total width
    total_width = sum(col_widths) + len(headers) + 1
    
    # Print top border
    print_colored(BOX_CHARS["top_left"] + BOX_CHARS["horizontal"] * total_width + BOX_CHARS["top_right"], color)
    
    # Print headers
    header_line = BOX_CHARS["vertical"]
    for i, header in enumerate(headers):
        header_line += f" {header}{' ' * (col_widths[i] - len(header) - 1)}{BOX_CHARS['vertical']}"
    print_colored(header_line, color)
    
    # Print separator
    separator = BOX_CHARS["left_connector"]
    for width in col_widths:
        separator += BOX_CHARS["horizontal"] * (width + 1) + BOX_CHARS["down_connector"]
    separator = separator[:-1] + BOX_CHARS["right_connector"]
    print_colored(separator, color)
    
    # Print data
    for row in data:
        data_line = BOX_CHARS["vertical"]
        for i, col in enumerate(row):
            col_str = str(col)
            data_line += f" {col_str}{' ' * (col_widths[i] - len(col_str) - 1)}{BOX_CHARS['vertical']}"
        print_colored(data_line, color)
    
    # Print bottom border
    print_colored(BOX_CHARS["bottom_left"] + BOX_CHARS["horizontal"] * total_width + BOX_CHARS["bottom_right"], color)

def get_system_info():
    """Get system information for reporting"""
    try:
        system = platform.system()
        release = platform.release()
        python_version = platform.python_version()
        hostname = socket.gethostname()
        ip = socket.gethostbyname(socket.gethostname())
        
        tools = {
            "nmap": check_command("nmap"),
            "masscan": check_command("masscan"),
            "subfinder": check_command("subfinder"),
            "assetfinder": check_command("assetfinder"),
            "httpx": check_command("httpx"),
            "nuclei": check_command("nuclei"),
            "waybackurls": check_command("waybackurls"),
            "katana": check_command("katana"),
            "ghauri": check_command("ghauri"),
            "subjs": check_command("subjs"),
            "linkfinder": check_command("linkfinder"),
            "xnLinkFinder": check_command("xnLinkFinder"),
            "jsluice": check_command("jsluice"),
            "getjswords": check_command("getjswords"),
            "dnstwist": check_command("dnstwist"),
            "urlcrazy": check_command("urlcrazy")
        }
        
        installed_tools = [tool for tool, installed in tools.items() if installed]
        
        return {
            "system": f"{system} {release}",
            "python": python_version,
            "hostname": hostname,
            "ip": ip,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tools": installed_tools
        }
    except:
        return {
            "system": "Unknown",
            "python": platform.python_version(),
            "hostname": "Unknown",
            "ip": "Unknown",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tools": []
        }

def kill_all_processes(process_names):
    """Kill all specified processes (Panic Mode)"""
    try:
        print_colored(f"[{STATUS_SYMBOLS['warning']}] PANIC MODE ACTIVATED - Killing all child processes", ERROR_COLOR)
        
        killed = []
        not_killed = []
        
        if platform.system() == "Windows":
            for proc in process_names:
                try:
                    subprocess.run(f"taskkill /F /IM {proc}.exe", shell=True, check=False)
                    killed.append(proc)
                except:
                    not_killed.append(proc)
        else:  # Linux/Mac
            for proc in process_names:
                try:
                    subprocess.run(f"pkill -9 {proc}", shell=True, check=False)
                    killed.append(proc)
                except:
                    not_killed.append(proc)
        
        print_colored(f"[{STATUS_SYMBOLS['success']}] Successfully killed: {', '.join(killed)}", SUCCESS_COLOR)
        if not_killed:
            print_colored(f"[{STATUS_SYMBOLS['error']}] Failed to kill: {', '.join(not_killed)}", ERROR_COLOR)
        
        return True
    except Exception as e:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Error in panic mode: {str(e)}", ERROR_COLOR)
        return False

def tag_asset(asset, status="Unknown", asset_type="Unknown", technology="Unknown", risk_score=0):
    """Tag an asset with metadata for the Universal Asset Tagging System"""
    try:
        # Status: Live, Dead, Unknown
        # Type: CDN, API, Admin Panel, Login, etc.
        # Risk Score: 0-100
        
        return {
            "asset": asset,
            "status": status,
            "type": asset_type,
            "technology": technology,
            "risk_score": risk_score,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Error tagging asset: {str(e)}", ERROR_COLOR)
        return None

def assign_risk_level(risk_score):
    """Assign a risk level based on a risk score (0-100)"""
    if risk_score >= 75:
        return "Critical"
    elif risk_score >= 50:
        return "High"
    elif risk_score >= 25:
        return "Medium"
    else:
        return "Low"

def analyze_csp_headers(headers):
    """Analyze Content Security Policy Headers"""
    csp = headers.get('Content-Security-Policy', '')
    if not csp:
        return {"has_csp": False, "issues": ["No CSP header found"]}
    
    issues = []
    
    # Check for unsafe-inline in script-src
    if "script-src" in csp and "unsafe-inline" in csp:
        issues.append("CSP allows unsafe-inline scripts")
    
    # Check for unsafe-eval
    if "unsafe-eval" in csp:
        issues.append("CSP allows unsafe-eval")
    
    # Check for wildcard sources
    if "'*'" in csp:
        issues.append("CSP contains wildcard source")
    
    return {
        "has_csp": True,
        "raw": csp,
        "issues": issues
    }

def analyze_cors_headers(headers):
    """Analyze CORS Headers for misconfigurations"""
    acao = headers.get('Access-Control-Allow-Origin', '')
    acac = headers.get('Access-Control-Allow-Credentials', '')
    
    issues = []
    
    if acao == '*' and acac.lower() == 'true':
        issues.append("CORS misconfiguration: Wildcard origin with credentials")
    
    return {
        "has_cors": bool(acao),
        "allow_origin": acao,
        "allow_credentials": acac,
        "issues": issues
    }
