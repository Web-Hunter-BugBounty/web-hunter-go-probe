
#!/usr/bin/env python3
"""
Attack Chain Mapping module for Web-Hunter
Visualizes and correlates vulnerabilities to show potential attack chains
"""

import os
import json
import networkx as nx
import matplotlib.pyplot as plt
from colorama import Fore
from .utils import print_colored, STATUS_SYMBOLS, save_to_file

def create_attack_graph(vulnerabilities, assets, output_dir):
    """Create an attack graph visualization showing potential attack chains"""
    print_colored(f"[{STATUS_SYMBOLS['info']}] Creating attack chain visualization...", Fore.CYAN)
    
    # Create attack chain directory
    attack_chain_dir = os.path.join(output_dir, "attack_chain")
    if not os.path.exists(attack_chain_dir):
        os.makedirs(attack_chain_dir)
    
    # Create a directed graph
    G = nx.DiGraph()
    
    # Add nodes for assets
    for asset in assets:
        asset_name = asset.get('asset', 'Unknown')
        asset_type = asset.get('type', 'Unknown')
        risk_score = asset.get('risk_score', 0)
        
        # Calculate node color based on risk score
        if risk_score >= 75:
            color = 'red'
        elif risk_score >= 50:
            color = 'orange'
        elif risk_score >= 25:
            color = 'yellow'
        else:
            color = 'green'
        
        G.add_node(asset_name, type=asset_type, risk_score=risk_score, color=color)
    
    # Add edges for potential attack paths based on vulnerabilities
    edge_labels = {}
    for vuln in vulnerabilities:
        source = vuln.get('source', None)
        target = vuln.get('target', None)
        vuln_type = vuln.get('type', 'Unknown')
        severity = vuln.get('severity', 'Low')
        
        if source and target and source in G and target in G:
            G.add_edge(source, target, type=vuln_type, severity=severity)
            edge_labels[(source, target)] = f"{vuln_type} ({severity})"
    
    # Draw the graph
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G)
    
    # Get node colors
    node_colors = [G.nodes[n].get('color', 'blue') for n in G.nodes()]
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=500, alpha=0.8)
    
    # Draw edges with different colors based on severity
    edge_colors = []
    for u, v, data in G.edges(data=True):
        severity = data.get('severity', 'Low')
        if severity == 'Critical':
            edge_colors.append('red')
        elif severity == 'High':
            edge_colors.append('orange')
        elif severity == 'Medium':
            edge_colors.append('yellow')
        else:
            edge_colors.append('green')
    
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors, width=2, alpha=0.7, arrows=True, arrowsize=20)
    
    # Draw labels
    nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='red')
    
    # Save the visualization
    plt.title('Attack Chain Visualization')
    plt.axis('off')
    
    graph_file = os.path.join(attack_chain_dir, "attack_chain.png")
    plt.savefig(graph_file, format="PNG", dpi=300, bbox_inches='tight')
    plt.close()
    
    # Save the graph data as JSON for interactive visualization
    graph_data = {
        "nodes": [{"id": n, "type": G.nodes[n].get('type', 'Unknown'), 
                  "risk_score": G.nodes[n].get('risk_score', 0)} for n in G.nodes()],
        "links": [{"source": u, "target": v, "type": G.edges[u, v].get('type', 'Unknown'),
                  "severity": G.edges[u, v].get('severity', 'Low')} for u, v in G.edges()]
    }
    
    json_file = os.path.join(attack_chain_dir, "attack_chain_data.json")
    with open(json_file, 'w') as f:
        json.dump(graph_data, f, indent=4)
    
    # Create a text report
    report_file = os.path.join(attack_chain_dir, "attack_chain_report.txt")
    with open(report_file, 'w') as f:
        f.write("ATTACK CHAIN ANALYSIS REPORT\n")
        f.write("===========================\n\n")
        
        f.write("CRITICAL ASSETS:\n")
        for node in G.nodes():
            risk_score = G.nodes[node].get('risk_score', 0)
            if risk_score >= 75:
                f.write(f"  - {node} (Risk Score: {risk_score}, Type: {G.nodes[node].get('type', 'Unknown')})\n")
        
        f.write("\nPOTENTIAL ATTACK PATHS:\n")
        for u, v in G.edges():
            f.write(f"  - {u} -> {v} [{G.edges[u, v].get('type', 'Unknown')} ({G.edges[u, v].get('severity', 'Low')})]\n")
        
        # Find critical paths (paths to high-value targets with multiple critical vulnerabilities)
        high_value_targets = [n for n in G.nodes() if G.nodes[n].get('risk_score', 0) >= 75]
        
        f.write("\nCRITICAL ATTACK PATHS:\n")
        for target in high_value_targets:
            for source in G.nodes():
                if source != target and nx.has_path(G, source, target):
                    paths = list(nx.all_simple_paths(G, source, target))
                    for path in paths:
                        path_str = " -> ".join(path)
                        critical_vulns = sum(1 for i in range(len(path)-1) if G.edges[path[i], path[i+1]].get('severity', 'Low') in ['Critical', 'High'])
                        if critical_vulns > 0:
                            f.write(f"  - {path_str} [{critical_vulns} critical/high vulnerabilities]\n")
    
    print_colored(f"[{STATUS_SYMBOLS['success']}] Attack chain analysis complete", Fore.GREEN)
    print_colored(f"[{STATUS_SYMBOLS['info']}] Results saved to {attack_chain_dir}", Fore.CYAN)
    
    return graph_file, json_file, report_file

def analyze_attack_surface(assets, vulnerabilities, output_dir):
    """Analyze the attack surface and identify the most critical vulnerabilities"""
    print_colored(f"[{STATUS_SYMBOLS['info']}] Analyzing attack surface...", Fore.CYAN)
    
    # Create attack surface directory
    attack_surface_dir = os.path.join(output_dir, "attack_chain", "attack_surface")
    if not os.path.exists(attack_surface_dir):
        os.makedirs(attack_surface_dir)
    
    # Group vulnerabilities by asset
    vuln_by_asset = {}
    for vuln in vulnerabilities:
        asset = vuln.get('asset', None)
        if not asset:
            continue
            
        if asset not in vuln_by_asset:
            vuln_by_asset[asset] = []
        
        vuln_by_asset[asset].append(vuln)
    
    # Calculate risk scores for each asset
    asset_risk_scores = {}
    for asset in assets:
        asset_name = asset.get('asset', 'Unknown')
        base_risk = asset.get('risk_score', 0)
        
        # Add vulnerability risk
        vuln_risk = 0
        if asset_name in vuln_by_asset:
            for vuln in vuln_by_asset[asset_name]:
                severity = vuln.get('severity', 'Low')
                if severity == 'Critical':
                    vuln_risk += 25
                elif severity == 'High':
                    vuln_risk += 15
                elif severity == 'Medium':
                    vuln_risk += 10
                elif severity == 'Low':
                    vuln_risk += 5
        
        # Cap at 100
        total_risk = min(base_risk + vuln_risk, 100)
        asset_risk_scores[asset_name] = total_risk
    
    # Sort assets by risk score
    sorted_assets = sorted(asset_risk_scores.items(), key=lambda x: x[1], reverse=True)
    
    # Create attack surface report
    report_file = os.path.join(attack_surface_dir, "attack_surface_report.txt")
    with open(report_file, 'w') as f:
        f.write("ATTACK SURFACE ANALYSIS REPORT\n")
        f.write("=============================\n\n")
        
        f.write("TOP 10 HIGHEST RISK ASSETS:\n")
        for i, (asset_name, risk_score) in enumerate(sorted_assets[:10], 1):
            f.write(f"{i}. {asset_name} (Risk Score: {risk_score})\n")
            
            # List vulnerabilities for this asset
            if asset_name in vuln_by_asset:
                for vuln in vuln_by_asset[asset_name]:
                    f.write(f"   - {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Low')}): {vuln.get('details', '')}\n")
            
            f.write("\n")
        
        f.write("\nMOST COMMON VULNERABILITY TYPES:\n")
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1
        
        for i, (vuln_type, count) in enumerate(sorted(vuln_types.items(), key=lambda x: x[1], reverse=True), 1):
            f.write(f"{i}. {vuln_type}: {count} occurrences\n")
    
    # Save risk scores JSON for visualization
    risk_scores_file = os.path.join(attack_surface_dir, "risk_scores.json")
    with open(risk_scores_file, 'w') as f:
        json.dump(asset_risk_scores, f, indent=4)
    
    print_colored(f"[{STATUS_SYMBOLS['success']}] Attack surface analysis complete", Fore.GREEN)
    print_colored(f"[{STATUS_SYMBOLS['info']}] Results saved to {attack_surface_dir}", Fore.CYAN)
    
    return report_file, risk_scores_file
