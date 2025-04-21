
<h1 align="center">🔍 Web-Hunter 🔍</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20|%20MacOS%20|%20Windows%20(WSL)-orange?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.7+-yellow?style=for-the-badge" alt="Python Version">
  <img src="https://img.shields.io/badge/Ethical%20Hacking-Only-red?style=for-the-badge" alt="Ethical Hacking Only">
</p>

<p align="center">
  <strong>Advanced Security Reconnaissance Tool for Ethical Hackers and Security Professionals</strong><br>
  Comprehensive Attack Surface Mapping | Vulnerability Identification | Advanced Exploitation Techniques
</p>

<hr>

## 💠 Enterprise Features

✅ **Advanced Reconnaissance Techniques**
- **Subdomain Enumeration** - Active and Passive methods to discover all subdomains
- **Port Scanning** - Intelligent scanning for open services and vulnerable entry points
- **Technology Detection** - Identify frameworks, servers, and technologies in use
- **Endpoint Discovery** - Find API endpoints, hidden directories, and sensitive resources
- **JS Analysis** - Extract endpoints, tokens, and secrets from JavaScript files

✅ **Vulnerability Detection**
- **Automated SQL Injection** - Using Ghauri for efficient SQLI detection
- **XSS Detection** - Identify cross-site scripting vulnerabilities
- **SSRF, LFI, RFI** - Detect server-side request forgery and file inclusion flaws
- **IDOR & Access Control** - Find insecure direct object references
- **Nuclei Integration** - Run thousands of security templates against targets

✅ **OSINT & Metadata Analysis**
- **API Key & Secret Detection** - Find exposed credentials in source code
- **Email Harvesting** - Discover associated email addresses
- **Data Leak Checks** - Verify if credentials have been exposed in breaches
- **Cloud Asset Discovery** - Identify AWS/Azure/GCP resources linked to target
- **Document Metadata** - Extract information from documents and resources

✅ **Advanced Techniques**
- **WAF Bypass** - Techniques to evade web application firewalls
- **Attack Chain Mapping** - Visual representation of potential attack paths
- **Cloud Security Analysis** - Evaluate misconfigurations and vulnerabilities in cloud assets
- **Sensitive Information Extraction** - Find PII, API keys, and security risks

## 🌟 Key Features

- **Interactive Menu System** - User-friendly interface with intuitive options
- **Progress Tracking** - Real-time progress indicators for all operations
- **Output Organization** - Well-structured results for easy analysis
- **Smart Filtering** - Intelligent detection of critical endpoints and vulnerabilities
- **Customizable Scans** - Tailor reconnaissance and scanning to specific needs
- **Persistent Results** - Continue scans or analyze previous findings

## 📋 Prerequisites

### Required Tools
- Python 3.7 or higher
- Git
- PIP (Python package manager)

### Optional Tools (for Enhanced Functionality)
- Nuclei
- Ghauri
- Naabu/Nmap
- Subfinder
- Assetfinder
- HTTPX

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/knobrazz/web-hunter.git

# Navigate to the directory
cd web-hunter

# Install the required dependencies
pip3 install -r requirements.txt

# Make the script executable
chmod +x web-hunter.py

# Run the setup script to install optional tools
./setup.sh
```

## 💻 Usage

### Basic Usage
```bash
python3 web-hunter.py
```

This will launch the interactive menu where you can select:

1. **Domain Reconnaissance** - Full scan of a domain
2. **IP/CIDR Reconnaissance** - Scan single IP or CIDR range
3. **Wildcard Domain Reconnaissance** - Extended scanning for wildcard domains
4. **Continue from Existing Scan** - Resume previous scans
5. **Load Endpoints and Scan** - Scan from endpoint list

### Advanced Usage

```bash
python3 web-hunter.py --domain example.com --all
python3 web-hunter.py --cidr 192.168.0.0/24 --port-scan --vuln-scan
python3 web-hunter.py --wildcard *.example.com --subdomain-enum --tech-detect
python3 web-hunter.py --continue-from results/example.com_20230215-120145
```

## 📊 Scan Phases

1. **Subdomain Enumeration** - Discover all related subdomains
2. **Port Scanning** - Identify open ports and services
3. **Technology Detection** - Fingerprint technologies in use
4. **Endpoint Discovery** - Find endpoints and resources
5. **Vulnerability Scanning** - Detect common security flaws
6. **OSINT Information Gathering** - Gather additional intelligence
7. **Specialized Vulnerability Scanning** - Run focused security checks

## 📁 Output Structure

```
results/
└── example.com_20230215-120145/
    ├── subdomains/
    │   ├── passive_subdomains.txt
    │   ├── active_subdomains.txt
    │   └── valid_subdomains.txt
    ├── ports/
    │   └── port_scan_results.json
    ├── technologies/
    │   └── tech_results.json
    ├── endpoints/
    │   ├── all_endpoints.txt
    │   ├── critical_endpoints.txt
    │   ├── js_files.txt
    │   └── sensitive_info/
    │       ├── api_key_findings.json
    │       └── sensitive_info_summary.txt
    ├── vulnerabilities/
    │   ├── sqli/
    │   ├── xss/
    │   ├── nuclei/
    │   └── ...
    └── osint/
        ├── whois_results.json
        └── email_findings.txt
```

## 🛡️ Security and Ethical Usage

**Web-Hunter is designed for ethical security testing only.**

⚠️ Always obtain proper authorization before scanning any systems or networks.

⚠️ Unauthorized scanning may be illegal and unethical.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

Special thanks to the security research community and the developers of the fantastic tools that Web-Hunter integrates.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📧 Contact

Nabaraj Lamichhane - [GitHub](https://github.com/knobrazz)

Project Link: [https://github.com/knobrazz/web-hunter](https://github.com/knobrazz/web-hunter)

---

<p align="center">
  <strong>Web-Hunter: Illuminate the Shadows, Secure the Future</strong>
</p>
