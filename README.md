# PhantomSurface: Intelligent Attack Surface Mapping System

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

## 📋 Overview

**PhantomSurface** is an automated attack surface mapping and reconnaissance system designed for defensive security operations. It helps security teams and organizations identify, analyze, and visualize their exposed digital assets to understand potential attack vectors before malicious actors do.

In today's threat landscape, organizations face increasing risks from exposed services, forgotten subdomains, and misconfigured infrastructure. PhantomSurface addresses this challenge by providing comprehensive visibility into an organization's external attack surface.

### Problem Statement
- Organizations struggle to maintain visibility of their external-facing assets
- Shadow IT and forgotten subdomains create blind spots in security posture
- Manual reconnaissance is time-consuming and error-prone
- Lack of visualization makes it difficult to communicate risk to stakeholders

### Solution
PhantomSurface automates the discovery, scanning, and mapping of digital assets, providing:
- Automated subdomain enumeration and asset discovery
- Intelligent network scanning and service identification
- Risk-based threat assessment of exposed services
- Visual attack surface mapping for security teams
- Web-based dashboard for easy access and reporting

---

## ✨ Features

### Core Capabilities
- **🔍 Asset Discovery**: Automated domain resolution, subdomain enumeration, and IP mapping
- **🌐 Network Scanning**: Port scanning, service identification, and banner grabbing
- **⚠️ Threat Assessment**: Risk scoring for exposed services and vulnerable configurations
- **📊 Visualization**: Graph-based attack surface mapping using NetworkX
- **🖥️ Web Dashboard**: Flask-based interface for scan management and result viewing
- **📄 Reporting**: JSON-based scan results and exportable visualizations

### Technical Highlights
- Modular architecture for easy extension
- Asynchronous scanning capabilities
- Intelligent rate limiting to avoid detection
- Error handling and logging
- Ethical scanning with built-in safety checks

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     PhantomSurface System                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Asset      │───▶│   Network    │───▶│    Threat    │  │
│  │  Discovery   │    │   Scanner    │    │    Mapper    │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                    │                    │          │
│         └────────────────────┼────────────────────┘          │
│                              ▼                               │
│                    ┌──────────────────┐                      │
│                    │   Visualizer     │                      │
│                    └──────────────────┘                      │
│                              │                               │
│                              ▼                               │
│                    ┌──────────────────┐                      │
│                    │  Web Dashboard   │                      │
│                    └──────────────────┘                      │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Component Flow
1. **Asset Discovery**: Enumerates subdomains and resolves IP addresses
2. **Network Scanner**: Performs port scans and identifies running services
3. **Threat Mapper**: Analyzes results and assigns risk scores
4. **Visualizer**: Creates graph representations of the attack surface
5. **Dashboard**: Presents results through a web interface

---

## 🔧 How PhantomSurface Works

### Step-by-Step Workflow

**Phase 1: Asset Discovery**
1. User provides target domain (e.g., example.com)
2. System performs DNS resolution to find primary IP address
3. Subdomain enumeration begins using:
   - Common subdomain wordlist
   - DNS queries for standard prefixes (www, mail, ftp, dev, api, etc.)
4. All discovered subdomains are resolved to IP addresses
5. Results are stored for next phase

**Phase 2: Network Scanning**
1. For each discovered IP address:
   - Perform SYN scan on common ports (1-1024 + common high ports)
   - Identify open ports and listening services
   - Grab service banners to determine versions
2. Service fingerprinting identifies:
   - Web servers (HTTP/HTTPS)
   - Mail servers (SMTP, POP3, IMAP)
   - Database servers (MySQL, PostgreSQL, MongoDB)
   - Remote access (SSH, RDP, Telnet)
   - File transfer (FTP, SFTP)

**Phase 3: Threat Assessment**
1. Each discovered service is analyzed for risk:
   - **Critical Risk**: Exposed databases, unencrypted remote access
   - **High Risk**: Outdated web servers, unnecessary services
   - **Medium Risk**: Standard services with known CVEs
   - **Low Risk**: Properly configured essential services
2. Risk scores are calculated based on:
   - Service type and sensitivity
   - Port exposure (well-known vs. non-standard)
   - Service version (outdated vs. current)
3. Recommendations are generated for each finding

**Phase 4: Visualization**
1. Attack surface graph is constructed:
   - **Nodes**: Root domain, subdomains, IP addresses, services
   - **Edges**: Relationships (domain→subdomain, subdomain→IP, IP→service)
   - **Colors**: Risk level indicators (red=critical, orange=high, yellow=medium, green=low)
2. Graph is rendered using NetworkX and Matplotlib
3. Output saved as PNG image

**Phase 5: Reporting**
1. All results compiled into JSON format
2. Web dashboard displays:
   - Summary statistics
   - Discovered assets list
   - Threat assessment details
   - Attack surface visualization
3. Results can be exported for further analysis

---

## 🛠️ Tech Stack

### Programming Language
- **Python 3.8+**: Core development language

### Core Libraries
- **requests**: HTTP requests for web-based reconnaissance
- **socket**: Low-level network operations
- **subprocess**: Integration with system tools
- **dnspython**: DNS query and resolution
- **python-nmap**: Network scanning wrapper
- **networkx**: Graph theory and network analysis
- **matplotlib**: Data visualization and graph rendering
- **Flask**: Web framework for dashboard

### External Tools
- **Nmap**: Network discovery and security auditing (must be installed separately)

### Development Tools
- **Git**: Version control
- **Virtual Environment**: Dependency isolation

---

## 📦 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Nmap installed on system
- Linux/macOS/Windows with admin/root privileges (for network scanning)

### System-specific Nmap Installation

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download installer from https://nmap.org/download.html

### Project Installation

**Step 1: Clone the Repository**
```bash
git clone https://github.com/skuser404/PhantomSurface.git
cd PhantomSurface
```

**Step 2: Create Virtual Environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**Step 3: Install Dependencies**
```bash
pip install -r requirements.txt
```

**Step 4: Verify Installation**
```bash
python src/main.py --help
```

---

## 🚀 Usage Instructions

### Command-Line Interface

**Basic Scan:**
```bash
python src/main.py --target example.com
```

**Comprehensive Scan with All Options:**
```bash
python src/main.py --target example.com --scan-type full --output-dir ./results
```

**Quick Scan (Top 100 Ports Only):**
```bash
python src/main.py --target example.com --scan-type quick
```

### Command-Line Arguments
- `--target`: Target domain to scan (required)
- `--scan-type`: Scan type - 'quick' or 'full' (default: full)
- `--output-dir`: Directory for output files (default: ./output)
- `--threads`: Number of concurrent threads (default: 10)
- `--timeout`: Scan timeout in seconds (default: 300)

### Web Dashboard

**Step 1: Start the Flask Server**
```bash
python src/dashboard.py
```

**Step 2: Access Dashboard**
Open browser and navigate to:
```
http://localhost:5000
```

**Step 3: Submit Scan**
1. Enter target domain in the input field
2. Select scan type (Quick/Full)
3. Click "Start Scan"
4. View results in real-time

### Output Files

After scanning, find results in the `output/` directory:
- `scan_results.json`: Complete scan data in JSON format
- `attack_surface.png`: Visual graph of attack surface
- `scan_log.txt`: Detailed scan log

---

## 📊 Sample Output

### Console Output
```
[*] PhantomSurface - Intelligent Attack Surface Mapping
[*] Target: example.com
[*] Scan Started: 2024-01-15 14:30:22

[+] Asset Discovery Phase
  ├─ Resolving primary domain...
  ├─ Found IP: 93.184.216.34
  ├─ Enumerating subdomains...
  ├─ Discovered: www.example.com → 93.184.216.34
  ├─ Discovered: mail.example.com → 93.184.216.35
  └─ Total Assets: 3 subdomains, 2 unique IPs

[+] Network Scanning Phase
  ├─ Scanning 93.184.216.34...
  ├─ Open Ports: 22, 80, 443
  ├─ Service: 22/tcp - OpenSSH 8.2p1
  ├─ Service: 80/tcp - Apache httpd 2.4.41
  └─ Service: 443/tcp - Apache httpd 2.4.41 (SSL)

[+] Threat Assessment Phase
  ├─ Analyzing 6 discovered services...
  ├─ Critical: 0 | High: 1 | Medium: 2 | Low: 3
  └─ Risk Score: 45/100 (Medium Risk)

[+] Visualization Generated: output/attack_surface.png
[+] Results Saved: output/scan_results.json
[+] Scan Completed in 147 seconds
```

### JSON Output Structure
```json
{
  "scan_metadata": {
    "target": "example.com",
    "start_time": "2024-01-15T14:30:22Z",
    "end_time": "2024-01-15T14:32:49Z",
    "duration": 147
  },
  "assets": [
    {
      "domain": "www.example.com",
      "ip": "93.184.216.34",
      "ports": [22, 80, 443],
      "services": [
        {"port": 80, "service": "http", "banner": "Apache 2.4.41"}
      ]
    }
  ],
  "threats": [
    {
      "severity": "HIGH",
      "service": "SSH",
      "port": 22,
      "description": "SSH exposed on standard port",
      "recommendation": "Move SSH to non-standard port, implement fail2ban"
    }
  ]
}
```

### Attack Surface Visualization
The generated PNG shows a network graph with:
- **Blue nodes**: Domain and subdomains
- **Green nodes**: IP addresses
- **Red/Orange/Yellow nodes**: Services (colored by risk level)
- **Edges**: Relationships between entities

---

## 💼 Use Cases

### For Security Teams
- **Periodic Security Audits**: Schedule regular scans to monitor attack surface changes
- **Penetration Testing**: Initial reconnaissance phase for authorized pentests
- **Asset Management**: Maintain inventory of external-facing infrastructure
- **Vulnerability Management**: Identify exposed services for prioritized patching

### For DevOps Engineers
- **Deployment Verification**: Ensure only intended services are publicly exposed
- **Configuration Validation**: Verify security group and firewall rules
- **Shadow IT Discovery**: Identify unauthorized services and subdomains

### For Academic Projects
- **Cybersecurity Research**: Study attack surface patterns and trends
- **Network Security Labs**: Educational tool for learning reconnaissance techniques
- **Capstone Projects**: Demonstrate practical security skills to recruiters

### For Bug Bounty Hunters
- **Reconnaissance Phase**: Automated initial information gathering (only on authorized targets)
- **Scope Understanding**: Map the full extent of target infrastructure
- **Reporting**: Generate professional visualizations for bug reports

---

## ⚖️ Ethical Disclaimer

**IMPORTANT: LEGAL AND ETHICAL USE ONLY**

PhantomSurface is designed for **defensive security purposes** and **authorized security testing** only.

### Legal Requirements
✅ **DO:**
- Only scan domains you own or have explicit written permission to test
- Use for authorized penetration testing engagements
- Employ for internal security audits of your organization
- Use in educational labs with properly configured test environments

❌ **DO NOT:**
- Scan domains without explicit authorization
- Use for malicious hacking or unauthorized access
- Violate computer fraud and abuse laws (CFAA in US, Computer Misuse Act in UK, etc.)
- Use to harm, disrupt, or compromise systems

### User Responsibility
By using PhantomSurface, you agree to:
1. Obtain proper authorization before scanning any target
2. Comply with all applicable local, national, and international laws
3. Use the tool ethically and responsibly
4. Accept full legal responsibility for your actions

**The developers and contributors of PhantomSurface are not responsible for any misuse or illegal activities conducted with this tool.**

### Rate Limiting and Respectful Scanning
PhantomSurface includes built-in rate limiting to avoid overwhelming target systems. Users should:
- Scan during approved maintenance windows
- Respect robots.txt and security.txt files
- Avoid aggressive scanning that could impact service availability

---

## 🚀 Future Enhancements

### Planned Features
- [ ] **AI-Powered Risk Assessment**: Machine learning models for threat prioritization
- [ ] **Integration with Threat Intelligence**: Cross-reference findings with CVE databases
- [ ] **Automated Remediation Suggestions**: Actionable security recommendations
- [ ] **Cloud Asset Discovery**: Support for AWS, Azure, GCP asset enumeration
- [ ] **Continuous Monitoring**: Daemon mode for real-time attack surface monitoring
- [ ] **API Endpoint Discovery**: Automated API reconnaissance and testing
- [ ] **Certificate Analysis**: SSL/TLS certificate validation and expiration tracking
- [ ] **Email Security Analysis**: SPF, DKIM, DMARC record verification
- [ ] **Web Application Fingerprinting**: CMS, framework, and technology detection
- [ ] **Multi-target Campaigns**: Scan multiple domains in a single operation
- [ ] **Export Formats**: PDF reports, CSV exports, integration with SIEM systems
- [ ] **Collaborative Features**: Team workspaces and shared scan results
- [ ] **Mobile Dashboard**: Responsive design for mobile access

### Contribution Areas
- Additional subdomain enumeration techniques
- Enhanced visualization options (3D graphs, interactive dashboards)
- Performance optimizations for large-scale scans
- Integration with popular security tools (Metasploit, Burp Suite)
- Custom plugin system for extensibility

---

## 👨‍💻 Author Details

**Developer**: Security Engineering Student  
**GitHub**: [@skuser404](https://github.com/skuser404)  
**Project**: PhantomSurface  
**Purpose**: Final Year Engineering Project | Cybersecurity Portfolio  

### Skills Demonstrated
- Advanced Python Programming
- Network Security & Reconnaissance
- Web Development (Flask)
- Data Visualization
- Graph Theory & Network Analysis
- Security Tool Development
- Documentation & Technical Writing

### Connect
- 🐙 GitHub: [github.com/skuser404](https://github.com/skuser404)
- 💼 LinkedIn: [Connect for collaboration]
- 📧 Email: Available on GitHub profile

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 skuser404

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🙏 Acknowledgments

- **Nmap Project**: For the powerful network scanning engine
- **OWASP**: For security best practices and guidelines
- **Python Community**: For excellent libraries and tools
- **Open Source Contributors**: For inspiration and code examples

---

## 📚 References & Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Nmap Documentation](https://nmap.org/book/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**⚡ PhantomSurface - Map Your Attack Surface Before Attackers Do**

*If you find this project helpful, please consider giving it a ⭐ on GitHub!*
