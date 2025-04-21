
#!/usr/bin/env python3
"""
Responsive & Rich Terminal Reporting, Risk Grouping, and Final Report Table
"""
import os
import time
import platform
import json
from datetime import datetime
from colorama import Fore, Style
from .utils import print_colored, save_to_file

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

def rich_summary(endpoints, vulns_dict, output_dir):
    """Generate a rich summary of findings with risk grouping"""
    print_colored("\n[::] ===== Final Recon Summary =====", Fore.BLUE + Style.BRIGHT)
    risk_levels = ["critical", "high", "medium", "low", "info"]
    summary = []
    
    # Header for the summary file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    system_info = get_system_info()
    
    summary.append(f"Web-Hunter Scan Report - {timestamp}")
    summary.append(f"System: {system_info}")
    summary.append(f"Total Endpoints Discovered: {len(endpoints)}")
    summary.append("=" * 80)
    summary.append("\nRISK SUMMARY:")
    
    # Count total vulnerabilities
    total_vulns = sum(len(vulns_dict.get(level, [])) for level in risk_levels)
    
    if total_vulns == 0:
        print_colored("[INFO] No vulnerabilities were found in this scan.", Fore.WHITE)
        summary.append("No vulnerabilities were found in this scan.")
    else:
        # Display and record findings by risk level
        for level in risk_levels:
            findings = vulns_dict.get(level, [])
            if findings:
                color = getattr(Fore, level.upper(), Fore.WHITE)
                count = len(findings)
                print_colored(f"[{level.upper()}] {count} findings", color)
                
                # Add to summary
                summary.append(f"\n{level.upper()} SEVERITY ({count} findings):")
                for idx, finding in enumerate(findings, 1):
                    summary.append(f"{idx}. {finding}")
    
    # Save detailed summary
    out = os.path.join(output_dir, "final_rich_report.txt")
    save_to_file(summary, out)
    
    # Also save as JSON for programmatic use
    json_out = os.path.join(output_dir, "scan_summary.json")
    json_data = {
        "timestamp": timestamp,
        "system_info": system_info, 
        "total_endpoints": len(endpoints),
        "vulnerabilities": {level: vulns_dict.get(level, []) for level in risk_levels},
        "total_vulnerabilities": total_vulns
    }
    
    with open(json_out, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print_colored(f"[+] Full summary saved to {out}", Fore.GREEN)
    print_colored(f"[+] JSON report saved to {json_out}", Fore.GREEN)
