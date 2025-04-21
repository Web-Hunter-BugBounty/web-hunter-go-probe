
#!/usr/bin/env python3
"""
Panic Mode module for Web-Hunter
Allows for emergency shutdown of all processes
"""

import os
import signal
import platform
import psutil
import subprocess
import time
from colorama import Fore
from .utils import print_colored, STATUS_SYMBOLS, kill_all_processes

# Known tool processes
KNOWN_TOOLS = [
    "nmap", "masscan", "subfinder", "assetfinder", "httpx", "nuclei", 
    "waybackurls", "katana", "ghauri", "subjs", "linkfinder", "xnLinkFinder",
    "jsluice", "getjswords", "dnstwist", "urlcrazy", "python", "python3",
    "aiodns", "amass", "wfuzz", "ffuf", "dirb", "gobuster", "dig", "host",
    "curl", "wget", "brutespray", "hydra", "patator", "whatweb", "wappalyzer"
]

def get_all_child_processes():
    """Get all child processes of the current process"""
    current_pid = os.getpid()
    children = []
    
    try:
        parent = psutil.Process(current_pid)
        children = parent.children(recursive=True)
    except:
        pass
    
    return children

def activate_panic_mode():
    """Activate panic mode to kill all running tool processes"""
    print_colored("\n", Fore.RED)
    print_colored(" ╔════════════════════════════════════════════╗ ", Fore.RED)
    print_colored(" ║             PANIC MODE ACTIVATED           ║ ", Fore.RED)
    print_colored(" ║        ALL TOOL PROCESSES WILL STOP        ║ ", Fore.RED)
    print_colored(" ╚════════════════════════════════════════════╝ ", Fore.RED)
    print_colored("\n", Fore.RED)
    
    # First, try to kill all direct children of this process
    killed = []
    failed = []
    
    # Get all child processes
    child_processes = get_all_child_processes()
    
    if child_processes:
        for proc in child_processes:
            try:
                proc_name = proc.name()
                proc.kill()
                killed.append(f"{proc_name} (PID: {proc.pid})")
            except:
                failed.append(f"{proc.name() if hasattr(proc, 'name') else 'Unknown'} (PID: {proc.pid})")
    
    # Then kill known tool processes by name
    result = kill_all_processes(KNOWN_TOOLS)
    
    # Report results
    print_colored(f"[{STATUS_SYMBOLS['info']}] Attempted to kill {len(child_processes)} direct child processes", Fore.CYAN)
    
    if killed:
        print_colored(f"[{STATUS_SYMBOLS['success']}] Successfully terminated:", Fore.GREEN)
        for k in killed:
            print_colored(f"  - {k}", Fore.GREEN)
    
    if failed:
        print_colored(f"[{STATUS_SYMBOLS['error']}] Failed to terminate:", Fore.RED)
        for f in failed:
            print_colored(f"  - {f}", Fore.RED)
    
    print_colored(f"[{STATUS_SYMBOLS['info']}] Cleanup complete", Fore.CYAN)
    
    return len(killed)

def add_panic_mode_handler():
    """Add a panic mode handler for Ctrl+C"""
    def panic_handler(signum, frame):
        print_colored(f"\n[{STATUS_SYMBOLS['warning']}] Panic mode requested (Ctrl+C twice) - activating...", Fore.YELLOW)
        activate_panic_mode()
        print_colored(f"[{STATUS_SYMBOLS['info']}] You can press Ctrl+C again to exit completely", Fore.CYAN)
        
        # Reset handler to default after handling panic
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    # Set the panic handler
    signal.signal(signal.SIGINT, panic_handler)
    
    return True
