
#!/usr/bin/env python3
"""
Enhanced port scanner module for Web-Hunter
"""

import os
import subprocess
import concurrent.futures
import threading
import re
import sys
import time
import socket
import ipaddress
import json
from queue import Queue
from urllib.parse import urlparse
from colorama import Fore, Style
from tqdm import tqdm
from .utils import print_colored, save_to_file, check_command, get_command_output
from .banner import display_finding, PREMIUM_COLORS, display_section_header, display_result_header, display_result_footer

# Constants for port scanning
COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
UNCOMMON_PORTS = "81,300,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,10000,11371,12443,16080,18091,18092,20720,28017"

class PortScanResult:
    """Class to store port scan results"""
    def __init__(self):
        self.open_ports = {}
        self.total_open_ports = 0
        self.targets_with_open_ports = 0
        self.lock = threading.Lock()
    
    def add_result(self, target, ports):
        """Add scan result for a target"""
        with self.lock:
            if ports:
                self.open_ports[target] = ports
                self.total_open_ports += len(ports)
                self.targets_with_open_ports += 1

def perform_port_scan(targets, output_dir, scan_type="fast"):
    """Perform enhanced port scanning on targets with multiple scan types and threading"""
    display_section_header("PORT SCANNING")
    
    ports_dir = os.path.join(output_dir, "ports")
    os.makedirs(ports_dir, exist_ok=True)
    
    # Check for tools
    tools = {
        "masscan": check_command("masscan"),
        "nmap": check_command("nmap")
    }
    
    # Print available tools
    print_colored("[*] Checking available tools:", PREMIUM_COLORS["info"])
    for tool, available in tools.items():
        if available:
            print_colored(f"  ✓ {tool} found", PREMIUM_COLORS["success"])
        else:
            print_colored(f"  ✗ {tool} not found", PREMIUM_COLORS["warning"])
    
    if not any(tools.values()):
        print_colored("[!] No port scanning tools found. Using built-in socket scanner.", PREMIUM_COLORS["warning"])
    
    # Process targets to ensure they are valid for port scanning
    processed_targets = []
    for target in targets:
        # Strip protocol and path if present
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.netloc
        
        # Extract domain/IP from netloc if it includes port
        if ':' in target:
            target = target.split(':')[0]
        
        # Skip empty or invalid targets
        if not target:
            continue
            
        processed_targets.append(target)
    
    # Remove duplicates
    processed_targets = list(set(processed_targets))
    
    if not processed_targets:
        print_colored("[!] No valid targets found for port scanning", PREMIUM_COLORS["danger"])
        return
    
    # Select scan type and ports
    ports_to_scan = ""
    if scan_type == "common":
        ports_to_scan = COMMON_PORTS
        print_colored(f"[*] Using common ports scan: {ports_to_scan}", PREMIUM_COLORS["info"])
    elif scan_type == "uncommon":
        ports_to_scan = UNCOMMON_PORTS
        print_colored(f"[*] Using uncommon ports scan: {ports_to_scan}", PREMIUM_COLORS["info"])
    elif scan_type == "full":
        ports_to_scan = "1-65535"
        print_colored("[*] Using full port scan (1-65535)", PREMIUM_COLORS["info"])
    else:  # fast mode (default)
        ports_to_scan = COMMON_PORTS
        print_colored(f"[*] Using fast scan mode (common ports): {ports_to_scan}", PREMIUM_COLORS["info"])
    
    # Initialize results
    scan_results = PortScanResult()
    
    # Function to run masscan
    def run_masscan(target_list, results):
        # Create a temporary file with all targets
        targets_file = os.path.join(ports_dir, "masscan_targets.txt")
        save_to_file(target_list, targets_file)
        
        masscan_output = os.path.join(ports_dir, "masscan_results.json")
        
        # Build masscan command
        if scan_type == "full":
            rate = "5000"  # Lower rate for full scan to avoid overwhelming targets
            masscan_cmd = f"masscan -iL {targets_file} -p{ports_to_scan} --rate={rate} -oJ {masscan_output}"
        else:
            rate = "10000"
            masscan_cmd = f"masscan -iL {targets_file} -p{ports_to_scan} --rate={rate} -oJ {masscan_output}"
        
        print_colored(f"[*] Running masscan: {masscan_cmd}", PREMIUM_COLORS["info"])
        
        try:
            with tqdm(total=100, desc="Masscan Progress", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
                process = subprocess.Popen(
                    masscan_cmd, 
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Simulate progress since masscan doesn't provide easy progress indicators
                for i in range(100):
                    time.sleep(0.1)
                    pbar.update(1)
                    if process.poll() is not None:
                        break
                
                stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                print_colored(f"[!] Error running masscan: {stderr}", PREMIUM_COLORS["danger"])
                return False
            
            # Parse masscan output
            try:
                if os.path.exists(masscan_output) and os.path.getsize(masscan_output) > 0:
                    try:
                        with open(masscan_output, 'r') as f:
                            content = f.read().strip()
                            if content.endswith(','):
                                content = content[:-1]  # Remove trailing comma
                            if not content.startswith('['):
                                content = '[' + content
                            if not content.endswith(']'):
                                content = content + ']'
                            
                            scan_data = json.loads(content)
                            
                            # Process results
                            for item in scan_data:
                                if 'ip' in item and 'ports' in item:
                                    ip = item['ip']
                                    ports = [str(port['port']) for port in item['ports']]
                                    
                                    if ip not in results.open_ports:
                                        results.open_ports[ip] = []
                                    
                                    results.open_ports[ip].extend(ports)
                                    results.total_open_ports += len(ports)
                                    
                            results.targets_with_open_ports = len(results.open_ports)
                            return True
                    except json.JSONDecodeError as e:
                        print_colored(f"[!] Error parsing masscan JSON output: {str(e)}", PREMIUM_COLORS["danger"])
                        return False
                    except Exception as e:
                        print_colored(f"[!] Error reading masscan output: {str(e)}", PREMIUM_COLORS["danger"])
                        return False
                else:
                    print_colored("[!] Masscan output file is empty or does not exist", PREMIUM_COLORS["warning"])
                    return False
            except Exception as e:
                print_colored(f"[!] Error processing masscan results: {str(e)}", PREMIUM_COLORS["danger"])
                return False
            
            return True
        except Exception as e:
            print_colored(f"[!] Error running masscan: {str(e)}", PREMIUM_COLORS["danger"])
            return False
    
    # Function to run nmap scan
    def nmap_worker(target, ports_str, results):
        try:
            nmap_output = os.path.join(ports_dir, f"{target.replace('/', '_').replace(':', '_')}_nmap.xml")
            
            # Build nmap command based on scan type
            if scan_type == "full":
                nmap_cmd = f"nmap -sS -p{ports_str} --min-rate 1000 -T4 -oX {nmap_output} {target}"
            else:
                nmap_cmd = f"nmap -sS -p{ports_str} --min-rate 2000 -T4 -oX {nmap_output} {target}"
            
            # Execute nmap with a timeout
            result = subprocess.run(
                nmap_cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if result.returncode != 0:
                print_colored(f"[!] Error scanning {target} with nmap: {result.stderr}", PREMIUM_COLORS["warning"])
                return
            
            # Parse nmap XML output
            open_ports = []
            
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(nmap_output)
                root = tree.getroot()
                
                # Find all port elements that are open
                for port in root.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_id = port.get('portid')
                        if port_id:
                            open_ports.append(port_id)
            except Exception as e:
                print_colored(f"[!] Error parsing nmap XML for {target}: {str(e)}", PREMIUM_COLORS["warning"])
                
                # Fallback to text output parsing if XML parsing fails
                try:
                    with open(nmap_output, 'r') as f:
                        content = f.read()
                        port_pattern = r'(\d+)/tcp\s+open'
                        open_ports = re.findall(port_pattern, content)
                except Exception as e2:
                    print_colored(f"[!] Error with fallback parsing for {target}: {str(e2)}", PREMIUM_COLORS["danger"])
            
            # Add results
            if open_ports:
                results.add_result(target, open_ports)
                
        except subprocess.TimeoutExpired:
            print_colored(f"[!] Nmap scan timed out for {target}", PREMIUM_COLORS["warning"])
        except Exception as e:
            print_colored(f"[!] Error in nmap scan for {target}: {str(e)}", PREMIUM_COLORS["danger"])
    
    # Function to run socket scan (fallback if no tools available)
    def socket_worker(queue, results):
        while not queue.empty():
            target, port = queue.get()
            try:
                # Create socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                
                # Attempt connection
                result = s.connect_ex((target, int(port)))
                s.close()
                
                # If port is open
                if result == 0:
                    with results.lock:
                        if target not in results.open_ports:
                            results.open_ports[target] = []
                        
                        if port not in results.open_ports[target]:
                            results.open_ports[target].append(port)
                            results.total_open_ports += 1
            except:
                pass  # Silently fail on socket errors
            finally:
                queue.task_done()
    
    # Function to run socket-based port scan
    def run_socket_scan(target_list, ports_list, results):
        # Create job queue
        scan_queue = Queue()
        
        # Add all target/port combinations to queue
        for target in target_list:
            for port in ports_list:
                scan_queue.put((target, port))
        
        # Start worker threads
        thread_count = min(100, scan_queue.qsize())
        if thread_count <= 0:
            return
        
        with tqdm(total=scan_queue.qsize(), desc="Socket Scan Progress", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
            # Initial queue size
            initial_size = scan_queue.qsize()
            
            # Start worker threads
            for _ in range(thread_count):
                t = threading.Thread(target=socket_worker, args=(scan_queue, results))
                t.daemon = True
                t.start()
            
            # Monitor progress
            while not scan_queue.empty():
                current_size = scan_queue.qsize()
                completed = initial_size - current_size
                # Update progress bar with the number of completed tasks
                pbar.n = completed
                pbar.refresh()
                time.sleep(0.1)
            
            # Make sure the progress bar reaches 100%
            pbar.n = initial_size
            pbar.refresh()
    
    # Main scanning logic
    print_colored(f"[*] Starting port scan on {len(processed_targets)} target(s) using {scan_type} scan mode", PREMIUM_COLORS["info"])
    
    # Use masscan if available (faster for many targets)
    if tools["masscan"] and len(processed_targets) > 1:
        print_colored("[*] Using masscan for initial port discovery", PREMIUM_COLORS["info"])
        masscan_success = run_masscan(processed_targets, scan_results)
        
        # If masscan was successful and found open ports, use nmap for service detection on those
        if masscan_success and scan_results.open_ports:
            print_colored(f"[+] Masscan found {scan_results.total_open_ports} open ports across {scan_results.targets_with_open_ports} targets", PREMIUM_COLORS["success"])
            
            # Use nmap for service detection if available
            if tools["nmap"]:
                print_colored("[*] Running nmap for service detection on open ports", PREMIUM_COLORS["info"])
                
                # Create a list of nmap scan tasks
                nmap_tasks = []
                for target, ports in scan_results.open_ports.items():
                    ports_str = ",".join(ports)
                    nmap_tasks.append((target, ports_str))
                
                # Run nmap scans in parallel
                with tqdm(total=len(nmap_tasks), desc="Service Detection", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                        futures = []
                        for target, ports_str in nmap_tasks:
                            future = executor.submit(nmap_worker, target, ports_str, scan_results)
                            futures.append(future)
                        
                        # Update progress as futures complete
                        for _ in concurrent.futures.as_completed(futures):
                            pbar.update(1)
        else:
            print_colored("[!] Masscan didn't find any open ports or encountered an error", PREMIUM_COLORS["warning"])
            
            # Fallback to nmap or socket scan
            if tools["nmap"]:
                print_colored("[*] Falling back to nmap for port scanning", PREMIUM_COLORS["info"])
                
                # Convert port list to string based on scan type
                if scan_type == "full":
                    ports_str = "1-65535"
                else:
                    # For other scan types, use the pre-defined port lists
                    ports_str = ports_to_scan
                
                # Run nmap scans in parallel
                with tqdm(total=len(processed_targets), desc="Nmap Scan", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                        futures = []
                        for target in processed_targets:
                            future = executor.submit(nmap_worker, target, ports_str, scan_results)
                            futures.append(future)
                        
                        # Update progress as futures complete
                        for _ in concurrent.futures.as_completed(futures):
                            pbar.update(1)
            else:
                print_colored("[*] Falling back to socket scan", PREMIUM_COLORS["info"])
                ports_list = ports_to_scan.split(",") if "," in ports_to_scan else list(range(1, 1001))  # Default to first 1000 ports if full scan
                run_socket_scan(processed_targets, ports_list, scan_results)
    else:
        # If masscan is not available or we only have one target, use nmap or socket scan
        if tools["nmap"]:
            print_colored("[*] Using nmap for port scanning", PREMIUM_COLORS["info"])
            
            # Convert port list to string based on scan type
            if scan_type == "full":
                ports_str = "1-65535"
            else:
                # For other scan types, use the pre-defined port lists
                ports_str = ports_to_scan
            
            # Run nmap scans in parallel
            with tqdm(total=len(processed_targets), desc="Nmap Scan", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = []
                    for target in processed_targets:
                        future = executor.submit(nmap_worker, target, ports_str, scan_results)
                        futures.append(future)
                    
                    # Update progress as futures complete
                    for _ in concurrent.futures.as_completed(futures):
                        pbar.update(1)
        else:
            print_colored("[*] Using socket scan for port scanning", PREMIUM_COLORS["info"])
            ports_list = ports_to_scan.split(",") if "," in ports_to_scan else list(range(1, 1001))  # Default to first 1000 ports if full scan
            run_socket_scan(processed_targets, ports_list, scan_results)
    
    # Save results to files
    for target, ports in scan_results.open_ports.items():
        target_file = os.path.join(ports_dir, f"{target.replace('/', '_').replace(':', '_')}_ports.txt")
        save_to_file(ports, target_file)
    
    # Save summary
    summary_file = os.path.join(ports_dir, "port_scan_summary.json")
    with open(summary_file, 'w') as f:
        summary = {
            "total_targets_scanned": len(processed_targets),
            "targets_with_open_ports": scan_results.targets_with_open_ports,
            "total_open_ports": scan_results.total_open_ports,
            "scan_type": scan_type,
            "results": {target: ports for target, ports in scan_results.open_ports.items()}
        }
        json.dump(summary, f, indent=4)
    
    # Also save a text summary
    summary_text_file = os.path.join(ports_dir, "port_scan_summary.txt")
    with open(summary_text_file, 'w') as f:
        f.write(f"Total targets scanned: {len(processed_targets)}\n")
        f.write(f"Targets with open ports: {scan_results.targets_with_open_ports}\n")
        f.write(f"Total open ports found: {scan_results.total_open_ports}\n")
        f.write(f"Scan type: {scan_type}\n\n")
        
        for target, ports in scan_results.open_ports.items():
            f.write(f"{target}: {', '.join(ports)}\n")
    
    # Display results summary
    display_result_header("PORT SCAN RESULTS", PREMIUM_COLORS["highlight"])
    print_colored(f"Total targets scanned: {len(processed_targets)}", PREMIUM_COLORS["info"])
    print_colored(f"Targets with open ports: {scan_results.targets_with_open_ports}", PREMIUM_COLORS["info"])
    print_colored(f"Total open ports found: {scan_results.total_open_ports}", PREMIUM_COLORS["info"])
    
    # Display findings for targets with interesting ports
    for target, ports in scan_results.open_ports.items():
        # Check for interesting ports
        web_ports = [p for p in ports if p in ["80", "443", "8080", "8443", "3000", "8000", "8800"]]
        db_ports = [p for p in ports if p in ["3306", "5432", "1433", "6379", "27017", "9200", "9300", "8086"]]
        remote_access = [p for p in ports if p in ["22", "23", "3389", "5900", "5901"]]
        email_ports = [p for p in ports if p in ["25", "110", "143", "465", "587", "993", "995"]]
        
        if web_ports:
            severity = "MEDIUM" if "443" in web_ports else "LOW"
            display_finding(
                f"Web services detected on {target}",
                f"Open web ports: {', '.join(web_ports)}",
                severity
            )
        
        if db_ports:
            display_finding(
                f"Database services detected on {target}",
                f"Open database ports: {', '.join(db_ports)}",
                "HIGH"
            )
        
        if remote_access:
            display_finding(
                f"Remote access services detected on {target}",
                f"Open remote access ports: {', '.join(remote_access)}",
                "MEDIUM"
            )
        
        if email_ports:
            display_finding(
                f"Email services detected on {target}",
                f"Open email ports: {', '.join(email_ports)}",
                "LOW"
            )
    
    display_result_footer()
    print_colored(f"[+] Port scan complete. Results saved to {ports_dir}", PREMIUM_COLORS["success"])
    
    return scan_results.open_ports
