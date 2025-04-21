
#!/usr/bin/env python3
"""
Banner module for Web-Hunter
"""

import os
import random
import time
import sys
import platform
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Define color constants for premium output
PREMIUM_COLORS = {
    "success": Fore.GREEN,
    "error": Fore.RED,
    "warning": Fore.YELLOW,
    "info": Fore.CYAN,
    "highlight": Fore.MAGENTA,
    "danger": Fore.RED + Style.BRIGHT,
    "normal": Fore.WHITE
}

def get_system_info():
    """Get information about the system being used"""
    system = platform.system()
    if system == "Linux":
        distro = platform.freedesktop_os_release()['PRETTY_NAME'] if hasattr(platform, 'freedesktop_os_release') else "Linux"
        return f"{distro}"
    elif system == "Windows":
        if "microsoft" in platform.uname().release.lower():
            return f"Windows WSL {platform.uname().release}"
        return f"Windows {platform.release()}"
    elif system == "Darwin":
        return f"macOS {platform.mac_ver()[0]}"
    else:
        return system

def display_banner():
    """Display a stylish banner for the tool"""
    os.system('clear' if os.name != 'nt' else 'cls')
    
    # Random color selection for banner
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    selected_color = random.choice(colors)
    
    banner = f"""
{selected_color}██╗    ██╗███████╗██████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
{selected_color}██║    ██║██╔════╝██╔══██╗      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
{selected_color}██║ █╗ ██║█████╗  ██████╔╝█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
{selected_color}██║███╗██║██╔══╝  ██╔══██╗╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
{selected_color}╚███╔███╔╝███████╗██████╔╝      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
{selected_color} ╚══╝╚══╝ ╚══════╝╚═════╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Fore.WHITE}═════════════════════════════════════════════════════════════════════════════════════
{Fore.CYAN}                         Advanced Security Reconnaissance Tool
{Fore.WHITE}═════════════════════════════════════════════════════════════════════════════════════
{Fore.GREEN}                      Created by Nabaraj Lamichhane (@knobrazz)                         
{Fore.WHITE}═════════════════════════════════════════════════════════════════════════════════════
{Style.RESET_ALL}
    """
    
    # Print banner with typing effect
    for line in banner.split('\n'):
        print(line)
        time.sleep(0.05)
    
    # Get system information
    system_info = get_system_info()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"{Fore.RED}WARNING: {Fore.YELLOW}This tool is for ethical security testing only. Use responsibly and legally.")
    print(f"{Fore.RED}DO NOT {Fore.YELLOW}use against systems without proper authorization.")
    print(f"{Fore.CYAN}Version: {Fore.WHITE}2.0.0 {Fore.GREEN}| {Fore.CYAN}Type: {Fore.WHITE}Enterprise Edition")
    print(f"{Fore.CYAN}System: {Fore.WHITE}{system_info} {Fore.GREEN}| {Fore.CYAN}Time: {Fore.WHITE}{current_time}{Style.RESET_ALL}")
    print("\n")

def display_thanks():
    """Display a thank you message when exiting"""
    thanks = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║                                                                          ║
{Fore.CYAN}║  {Fore.GREEN}Thank you for using Web-Hunter - Advanced Security Reconnaissance Tool  {Fore.CYAN}║
{Fore.CYAN}║                                                                          ║
{Fore.CYAN}║  {Fore.WHITE}Created with ♥ for the security community                           {Fore.CYAN}║
{Fore.CYAN}║                                                                          ║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    
    print(thanks)

def display_progress_bar(current, total, bar_length=50, title="Progress"):
    """Display a progress bar"""
    percent = float(current) * 100 / total
    arrow = '-' * int(percent/100 * bar_length - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    
    sys.stdout.write(f"\r{Fore.CYAN}{title}: [{Fore.GREEN}{arrow}{Fore.WHITE}{spaces}] {percent:.2f}%")
    sys.stdout.flush()

def display_section_header(title):
    """Display a section header with a title"""
    header_length = 80
    padding = (header_length - len(title) - 2) // 2
    print(f"\n{Fore.CYAN}{'=' * header_length}")
    print(f"{Fore.CYAN}{'=' * padding} {Fore.WHITE}{title} {Fore.CYAN}{'=' * padding}")
    print(f"{Fore.CYAN}{'=' * header_length}{Style.RESET_ALL}\n")

def display_result_header(title, color=Fore.CYAN):
    """Display a result header with a title"""
    header_length = 80
    print(f"\n{color}┌{'─' * (header_length - 2)}┐")
    padding = (header_length - len(title) - 4) // 2
    print(f"{color}│{' ' * padding} {title} {' ' * padding}│")
    print(f"{color}└{'─' * (header_length - 2)}┘{Style.RESET_ALL}\n")

def display_result_footer():
    """Display a result footer"""
    print(f"\n{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}\n")

def display_finding(title, details, severity="INFO"):
    """Display a security finding with severity"""
    severity = severity.upper()
    
    # Determine color based on severity
    if severity == "HIGH" or severity == "CRITICAL":
        color = Fore.RED + Style.BRIGHT
    elif severity == "MEDIUM":
        color = Fore.YELLOW
    elif severity == "LOW":
        color = Fore.GREEN
    else:
        color = Fore.CYAN
    
    print(f"\n{color}[{severity}] {title}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{details}")
    print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")
