# PhantomSurface Workflow

## Overview

This document provides a detailed walkthrough of PhantomSurface's operational workflow, from initial execution to final report generation. Understanding the workflow helps users, developers, and security analysts maximize the tool's effectiveness.

---

## Workflow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    START: User Initiates Scan                │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 0: Initialization & Validation                        │
│  ─────────────────────────────────────────────────────────  │
│  • Validate target domain format                             │
│  • Check Nmap availability                                   │
│  • Verify write permissions for output directory             │
│  • Initialize logging system                                 │
│  • Display ethical usage warning                             │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 1: Asset Discovery                                    │
│  ─────────────────────────────────────────────────────────  │
│  Step 1: Resolve Primary Domain                              │
│    └─→ DNS A/AAAA query for target.com                      │
│    └─→ Store primary IP address                             │
│                                                               │
│  Step 2: Subdomain Enumeration                               │
│    └─→ Load subdomain wordlist                              │
│    └─→ For each subdomain candidate:                        │
│         • Attempt DNS resolution                             │
│         • If successful, record subdomain + IP               │
│         • Follow CNAME chains                                │
│    └─→ Parallel processing with thread pool                 │
│                                                               │
│  Step 3: IP Address Mapping                                  │
│    └─→ Deduplicate IP addresses                             │
│    └─→ Group assets by IP                                   │
│    └─→ Identify shared hosting                              │
│                                                               │
│  Output: Asset Inventory                                     │
│    • List of domains and subdomains                          │
│    • IP address mappings                                     │
│    • CNAME records                                           │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 2: Network Scanning                                   │
│  ─────────────────────────────────────────────────────────  │
│  Step 1: Port Scanning                                       │
│    └─→ For each unique IP:                                  │
│         • Perform SYN scan (nmap -sS)                        │
│         • Scan ports based on scan type:                     │
│           - Quick: Top 100 ports                             │
│           - Full: Ports 1-65535                              │
│         • Set timing template (-T3 or -T4)                   │
│         • Apply timeout values                               │
│                                                               │
│  Step 2: Service Identification                              │
│    └─→ For each open port:                                  │
│         • Perform version detection (-sV)                    │
│         • Identify service name                              │
│         • Extract version information                        │
│         • Detect operating system (-O)                       │
│                                                               │
│  Step 3: Banner Grabbing                                     │
│    └─→ For HTTP/HTTPS services:                             │
│         • Grab HTTP headers                                  │
│         • Extract Server header                              │
│         • Identify web technologies                          │
│    └─→ For other services:                                  │
│         • Connect and retrieve banner                        │
│         • Extract service identification strings             │
│                                                               │
│  Output: Network Scan Results                                │
│    • Open ports per IP                                       │
│    • Service names and versions                              │
│    • Banners and headers                                     │
│    • OS fingerprints                                         │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 3: Threat Assessment                                  │
│  ─────────────────────────────────────────────────────────  │
│  Step 1: Risk Analysis                                       │
│    └─→ For each discovered service:                         │
│         • Check against threat database                      │
│         • Evaluate based on:                                 │
│           - Service type (DB, admin, etc.)                   │
│           - Port number (standard vs non-standard)           │
│           - Version (outdated vs current)                    │
│           - Configuration (secure vs insecure)               │
│         • Assign severity: CRITICAL/HIGH/MEDIUM/LOW          │
│                                                               │
│  Step 2: Risk Scoring                                        │
│    └─→ Calculate individual risk scores:                    │
│         • Base score from service type                       │
│         • Multiplier for known vulnerabilities               │
│         • Penalty for outdated versions                      │
│         • Adjustment for encryption status                   │
│    └─→ Calculate overall attack surface score               │
│                                                               │
│  Step 3: Recommendation Generation                           │
│    └─→ For each threat:                                     │
│         • Generate remediation steps                         │
│         • Provide configuration examples                     │
│         • Link to security standards (CIS, NIST)             │
│         • Estimate remediation effort                        │
│                                                               │
│  Output: Threat Assessment Report                            │
│    • Categorized threats by severity                         │
│    • Individual risk scores                                  │
│    • Overall risk score                                      │
│    • Actionable recommendations                              │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 4: Visualization                                      │
│  ─────────────────────────────────────────────────────────  │
│  Step 1: Graph Construction                                  │
│    └─→ Create NetworkX directed graph                       │
│    └─→ Add nodes:                                           │
│         • Root domain (blue, large)                          │
│         • Subdomains (light blue, medium)                    │
│         • IP addresses (green, medium)                       │
│         • Services (colored by risk, small)                  │
│    └─→ Add edges:                                           │
│         • domain → subdomain                                 │
│         • subdomain → IP                                     │
│         • IP → service                                       │
│                                                               │
│  Step 2: Layout Computation                                  │
│    └─→ Apply spring layout algorithm                        │
│    └─→ Optimize node positioning                            │
│    └─→ Prevent overlapping                                  │
│    └─→ Balance visual hierarchy                             │
│                                                               │
│  Step 3: Rendering                                           │
│    └─→ Initialize Matplotlib figure                         │
│    └─→ Draw nodes with appropriate:                         │
│         • Colors (by risk level)                             │
│         • Sizes (by node type)                               │
│         • Labels (domain/IP/service)                         │
│    └─→ Draw edges with styling                              │
│    └─→ Add legend and metadata                              │
│    └─→ Save as PNG/SVG                                      │
│                                                               │
│  Output: Attack Surface Visualization                        │
│    • attack_surface.png                                      │
│    • Interactive legend                                      │
│    • Metadata annotations                                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 5: Reporting & Output                                 │
│  ─────────────────────────────────────────────────────────  │
│  Step 1: Compile Results                                     │
│    └─→ Aggregate data from all phases                       │
│    └─→ Structure into JSON format                           │
│    └─→ Add metadata:                                        │
│         • Scan timestamp                                     │
│         • Target information                                 │
│         • Scan parameters                                    │
│         • Duration and statistics                            │
│                                                               │
│  Step 2: Generate JSON Report                                │
│    └─→ Create scan_results.json                             │
│    └─→ Include:                                             │
│         • Complete asset inventory                           │
│         • Detailed scan results                              │
│         • Threat assessment                                  │
│         • Recommendations                                    │
│                                                               │
│  Step 3: Save Artifacts                                      │
│    └─→ Save JSON to output directory                        │
│    └─→ Copy visualization PNG                               │
│    └─→ Generate scan log                                    │
│                                                               │
│  Step 4: Display Summary                                     │
│    └─→ Console output:                                      │
│         • Total assets discovered                            │
│         • Open ports found                                   │
│         • Threats by severity                                │
│         • Overall risk score                                 │
│         • File locations                                     │
│                                                               │
│  Output: Complete Scan Package                               │
│    • scan_results.json                                       │
│    • attack_surface.png                                      │
│    • scan_log.txt                                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    END: Scan Complete                        │
│  User can now:                                               │
│    • Review results in terminal                              │
│    • Open JSON in text editor                                │
│    • View visualization in image viewer                      │
│    • Access web dashboard for interactive view               │
└─────────────────────────────────────────────────────────────┘
```

---

## Detailed Phase Breakdown

### Phase 0: Initialization & Validation

**Purpose**: Ensure system readiness and valid inputs before starting scan

**Steps**:

1. **Parse Command-Line Arguments**
   ```bash
   python main.py --target example.com --scan-type full
   ```
   - Validate target format (valid domain)
   - Check scan type (quick/full)
   - Verify output directory path

2. **System Requirements Check**
   ```python
   # Check Nmap installation
   if not nmap_available():
       print("[!] Error: Nmap not found. Please install nmap.")
       exit(1)
   
   # Check Python version
   if sys.version_info < (3, 8):
       print("[!] Error: Python 3.8+ required")
       exit(1)
   ```

3. **Permission Verification**
   - Check write permissions for output directory
   - Verify network access
   - Validate root/admin privileges (if required for SYN scan)

4. **Display Ethical Warning**
   ```
   ⚠️  ETHICAL USAGE WARNING ⚠️
   
   You are about to scan: example.com
   
   Ensure you have:
   ✓ Written authorization to scan this target
   ✓ Legal right to perform security testing
   ✓ Understanding of applicable laws (CFAA, GDPR, etc.)
   
   Unauthorized scanning is illegal and unethical.
   
   Continue? (yes/no):
   ```

5. **Initialize Logging**
   ```python
   logging.basicConfig(
       filename='output/scan_log.txt',
       level=logging.INFO,
       format='%(asctime)s - %(levelname)s - %(message)s'
   )
   ```

**Duration**: 5-10 seconds  
**Failure Points**: Missing Nmap, invalid domain, insufficient permissions

---

### Phase 1: Asset Discovery

**Purpose**: Enumerate all digital assets associated with target domain

#### Step 1: Primary Domain Resolution

**Process**:
```python
import dns.resolver

def resolve_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"[+] {domain} → {rdata.address}")
            return rdata.address
    except dns.resolver.NXDOMAIN:
        print(f"[!] Domain not found: {domain}")
        return None
```

**Output**:
```
[+] example.com → 93.184.216.34
```

#### Step 2: Subdomain Enumeration

**Wordlist Generation**:
```python
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1',
    'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
    'dev', 'staging', 'test', 'api', 'portal', 'blog', 'shop',
    'vpn', 'remote', 'cloud', 'cdn', 'assets', 'static', 'media'
]
```

**Parallel Enumeration**:
```python
from concurrent.futures import ThreadPoolExecutor

def enumerate_subdomains(domain, wordlist):
    discovered = []
    
    def check_subdomain(sub):
        fqdn = f"{sub}.{domain}"
        ip = resolve_domain(fqdn)
        if ip:
            return (fqdn, ip)
        return None
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_subdomain, wordlist)
    
    return [r for r in results if r is not None]
```

**Progress Display**:
```
[*] Enumerating subdomains for example.com...
[+] www.example.com → 93.184.216.34
[+] mail.example.com → 93.184.216.35
[+] ftp.example.com → 93.184.216.36
[+] api.example.com → 93.184.216.37
[*] Found 4 subdomains in 12.3 seconds
```

#### Step 3: IP Mapping

**Deduplication**:
```python
def map_ips(assets):
    ip_map = {}
    for domain, ip in assets:
        if ip not in ip_map:
            ip_map[ip] = []
        ip_map[ip].append(domain)
    return ip_map
```

**Output Structure**:
```json
{
    "93.184.216.34": ["example.com", "www.example.com"],
    "93.184.216.35": ["mail.example.com"],
    "93.184.216.36": ["ftp.example.com"],
    "93.184.216.37": ["api.example.com"]
}
```

**Duration**: 30-120 seconds (depends on wordlist size and parallelism)  
**Typical Results**: 5-50 subdomains for most targets

---

### Phase 2: Network Scanning

**Purpose**: Identify open ports and running services on discovered IPs

#### Step 1: Port Scanning

**Nmap Configuration**:
```python
import nmap

def scan_ports(ip, scan_type='full'):
    nm = nmap.PortScanner()
    
    if scan_type == 'quick':
        # Top 100 ports, fast timing
        nm.scan(ip, arguments='-sS -T4 --top-ports 100')
    else:
        # Full port range, moderate timing
        nm.scan(ip, arguments='-sS -T3 -p 1-65535 -sV')
    
    return nm[ip]
```

**Progress Display**:
```
[*] Scanning 93.184.216.34...
[*] Progress: ████████░░░░░░░░ 45% (Ports 1-30000/65535)
```

**Open Port Detection**:
```
[+] 93.184.216.34:22 - open
[+] 93.184.216.34:80 - open
[+] 93.184.216.34:443 - open
[+] 93.184.216.34:3306 - open (CRITICAL: MySQL exposed!)
```

#### Step 2: Service Identification

**Version Detection**:
```python
def identify_service(ip, port):
    nm = nmap.PortScanner()
    nm.scan(ip, str(port), arguments='-sV')
    
    if ip in nm.all_hosts():
        if port in nm[ip]['tcp']:
            service = nm[ip]['tcp'][port]
            return {
                'port': port,
                'state': service['state'],
                'name': service['name'],
                'product': service.get('product', 'unknown'),
                'version': service.get('version', 'unknown')
            }
```

**Output**:
```
[+] Service Details:
    Port: 22
    Service: ssh
    Product: OpenSSH
    Version: 8.2p1
    OS: Ubuntu Linux
```

#### Step 3: Banner Grabbing

**HTTP Header Grabbing**:
```python
import requests

def grab_http_banner(ip, port):
    try:
        url = f"http://{ip}:{port}"
        response = requests.get(url, timeout=5)
        headers = {
            'Server': response.headers.get('Server'),
            'X-Powered-By': response.headers.get('X-Powered-By'),
            'X-AspNet-Version': response.headers.get('X-AspNet-Version')
        }
        return {k: v for k, v in headers.items() if v}
    except:
        return {}
```

**Generic Banner Grabbing**:
```python
import socket

def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return None
```

**Duration**: 2-30 minutes (depends on scan type and number of IPs)  
**Typical Results**: 5-20 open ports per IP

---

### Phase 3: Threat Assessment

**Purpose**: Analyze discovered services for security risks

#### Step 1: Risk Analysis

**Threat Database**:
```python
THREAT_RULES = {
    'exposed_database': {
        'ports': [3306, 5432, 27017, 6379, 9200],
        'severity': 'CRITICAL',
        'score': 95,
        'description': 'Database service exposed to internet'
    },
    'weak_remote_access': {
        'ports': [23, 21],
        'severity': 'CRITICAL',
        'score': 90,
        'description': 'Unencrypted remote access protocol'
    },
    'ssh_standard_port': {
        'ports': [22],
        'severity': 'HIGH',
        'score': 75,
        'description': 'SSH on standard port (brute-force risk)'
    },
    'http_no_https': {
        'ports': [80],
        'severity': 'MEDIUM',
        'score': 50,
        'description': 'HTTP without HTTPS encryption'
    }
}
```

**Risk Evaluation**:
```python
def analyze_threats(scan_results):
    threats = []
    
    for ip, services in scan_results.items():
        for service in services:
            port = service['port']
            
            # Check against threat rules
            for threat_name, rule in THREAT_RULES.items():
                if port in rule['ports']:
                    threats.append({
                        'ip': ip,
                        'port': port,
                        'service': service['name'],
                        'threat': threat_name,
                        'severity': rule['severity'],
                        'score': rule['score'],
                        'description': rule['description']
                    })
    
    return threats
```

#### Step 2: Risk Scoring

**Individual Service Scores**:
```python
def calculate_service_risk(service):
    base_score = 0
    
    # Score by service type
    if service['port'] in [3306, 5432, 27017]:
        base_score = 95  # Database
    elif service['port'] in [22, 3389]:
        base_score = 75  # Remote access
    elif service['port'] in [80, 443]:
        base_score = 40  # Web
    
    # Adjust for outdated versions
    if is_outdated(service['version']):
        base_score += 20
    
    # Adjust for encryption
    if service['port'] == 80 and not has_https_redirect():
        base_score += 15
    
    return min(base_score, 100)
```

**Overall Risk Score**:
```python
def calculate_overall_risk(threats):
    if not threats:
        return 0
    
    # Weighted average based on severity
    weights = {'CRITICAL': 1.0, 'HIGH': 0.7, 'MEDIUM': 0.4, 'LOW': 0.2}
    
    total_score = sum(t['score'] * weights[t['severity']] for t in threats)
    total_weight = sum(weights[t['severity']] for t in threats)
    
    return int(total_score / total_weight)
```

#### Step 3: Recommendation Generation

**Recommendation Templates**:
```python
RECOMMENDATIONS = {
    'exposed_database': {
        'immediate': 'Restrict database port {port} to internal IPs only',
        'steps': [
            'Configure firewall to block external access',
            'Bind database to localhost (127.0.0.1)',
            'Use SSH tunneling for remote access',
            'Implement strong authentication'
        ],
        'references': ['CIS Benchmark 2.1.3', 'NIST 800-123']
    },
    'ssh_standard_port': {
        'immediate': 'Move SSH to non-standard port',
        'steps': [
            'Edit /etc/ssh/sshd_config',
            'Change Port 22 to Port 2222',
            'Restart SSH service',
            'Update firewall rules',
            'Disable root login',
            'Use key-based authentication'
        ],
        'references': ['CIS Benchmark 5.2.2']
    }
}
```

**Output**:
```
[!] THREAT FOUND: Exposed MySQL Database
    IP: 93.184.216.34
    Port: 3306
    Severity: CRITICAL
    Risk Score: 95/100
    
    Recommendation:
    → Immediate: Restrict database port 3306 to internal IPs only
    
    Steps to remediate:
    1. Configure firewall to block external access
    2. Bind database to localhost (127.0.0.1)
    3. Use SSH tunneling for remote access
    4. Implement strong authentication
    
    References:
    - CIS Benchmark 2.1.3
    - NIST 800-123
```

**Duration**: 10-30 seconds  
**Output**: Prioritized threat list with remediation steps

---

### Phase 4: Visualization

**Purpose**: Create visual representation of attack surface

#### Step 1: Graph Construction

**NetworkX Graph**:
```python
import networkx as nx

def build_graph(scan_data):
    G = nx.DiGraph()
    
    # Add root domain node
    G.add_node('example.com', type='root', color='#2E86AB', size=3000)
    
    # Add subdomain nodes
    for subdomain in scan_data['subdomains']:
        G.add_node(subdomain, type='subdomain', color='#A23B72', size=2000)
        G.add_edge('example.com', subdomain)
    
    # Add IP nodes
    for ip in scan_data['ips']:
        G.add_node(ip, type='ip', color='#F18F01', size=2000)
    
    # Add service nodes
    for service in scan_data['services']:
        color = get_risk_color(service['risk'])
        G.add_node(
            f"{service['port']}/{service['name']}", 
            type='service', 
            color=color, 
            size=1000
        )
    
    # Add edges
    for subdomain, ip in scan_data['mappings'].items():
        G.add_edge(subdomain, ip)
    
    for ip, services in scan_data['services_by_ip'].items():
        for service in services:
            G.add_edge(ip, f"{service['port']}/{service['name']}")
    
    return G
```

**Risk Color Mapping**:
```python
def get_risk_color(risk_score):
    if risk_score >= 90:
        return '#D62828'  # Red (Critical)
    elif risk_score >= 70:
        return '#F77F00'  # Orange (High)
    elif risk_score >= 40:
        return '#FCBF49'  # Yellow (Medium)
    else:
        return '#06A77D'  # Green (Low)
```

#### Step 2: Layout Computation

**Spring Layout**:
```python
def compute_layout(G):
    pos = nx.spring_layout(
        G,
        k=0.5,  # Optimal distance between nodes
        iterations=50,
        seed=42  # Reproducible layout
    )
    return pos
```

#### Step 3: Rendering

**Matplotlib Visualization**:
```python
import matplotlib.pyplot as plt

def render_graph(G, pos, output_file):
    plt.figure(figsize=(16, 12))
    
    # Draw nodes by type
    for node_type in ['root', 'subdomain', 'ip', 'service']:
        nodes = [n for n, d in G.nodes(data=True) if d['type'] == node_type]
        colors = [G.nodes[n]['color'] for n in nodes]
        sizes = [G.nodes[n]['size'] for n in nodes]
        
        nx.draw_networkx_nodes(
            G, pos,
            nodelist=nodes,
            node_color=colors,
            node_size=sizes,
            alpha=0.9
        )
    
    # Draw edges
    nx.draw_networkx_edges(G, pos, alpha=0.5, arrows=True)
    
    # Draw labels
    nx.draw_networkx_labels(G, pos, font_size=8)
    
    # Add legend
    legend_elements = [
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#D62828', markersize=10, label='Critical Risk'),
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#F77F00', markersize=10, label='High Risk'),
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#FCBF49', markersize=10, label='Medium Risk'),
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#06A77D', markersize=10, label='Low Risk')
    ]
    plt.legend(handles=legend_elements, loc='upper left')
    
    # Add title
    plt.title('Attack Surface Map - example.com', fontsize=16, fontweight='bold')
    
    # Save
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"[+] Visualization saved: {output_file}")
```

**Duration**: 5-15 seconds  
**Output**: High-resolution PNG image

---

### Phase 5: Reporting & Output

**Purpose**: Compile and present scan results

#### Complete JSON Report Structure

```json
{
    "scan_metadata": {
        "target": "example.com",
        "scan_type": "full",
        "start_time": "2024-01-15T14:30:22Z",
        "end_time": "2024-01-15T14:47:19Z",
        "duration_seconds": 1017,
        "scanner_version": "PhantomSurface v1.0"
    },
    "asset_inventory": {
        "total_subdomains": 4,
        "total_ips": 4,
        "domains": [
            {
                "domain": "example.com",
                "ip": "93.184.216.34",
                "cname": null
            },
            {
                "domain": "www.example.com",
                "ip": "93.184.216.34",
                "cname": null
            }
        ]
    },
    "network_scan": {
        "total_ports_scanned": 262140,
        "total_open_ports": 6,
        "ips": [
            {
                "ip": "93.184.216.34",
                "open_ports": [22, 80, 443],
                "services": [
                    {
                        "port": 22,
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "8.2p1",
                        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
                    }
                ]
            }
        ]
    },
    "threat_assessment": {
        "overall_risk_score": 62,
        "risk_level": "MEDIUM",
        "critical_count": 0,
        "high_count": 1,
        "medium_count": 2,
        "low_count": 3,
        "threats": [
            {
                "severity": "HIGH",
                "service": "SSH",
                "port": 22,
                "ip": "93.184.216.34",
                "description": "SSH exposed on standard port",
                "risk_score": 75,
                "recommendation": "Move SSH to non-standard port, implement fail2ban",
                "references": ["CIS Benchmark 5.2.2"]
            }
        ]
    },
    "recommendations": [
        {
            "priority": 1,
            "action": "Secure SSH service",
            "effort": "Low",
            "impact": "High"
        }
    ]
}
```

#### Console Summary

```
╔══════════════════════════════════════════════════════════╗
║           PhantomSurface - Scan Complete                 ║
╚══════════════════════════════════════════════════════════╝

Target: example.com
Duration: 16 minutes 57 seconds

ASSETS DISCOVERED:
  ├─ Subdomains: 4
  ├─ Unique IPs: 4
  └─ Open Ports: 6

THREAT SUMMARY:
  ├─ Critical: 0
  ├─ High: 1
  ├─ Medium: 2
  └─ Low: 3

OVERALL RISK SCORE: 62/100 (MEDIUM)

OUTPUT FILES:
  ├─ Results: output/scan_results.json
  ├─ Visualization: output/attack_surface.png
  └─ Log: output/scan_log.txt

TOP RECOMMENDATIONS:
  1. [HIGH] Secure SSH service on 93.184.216.34:22
  2. [MEDIUM] Enable HTTPS on 93.184.216.34:80
  3. [MEDIUM] Update Apache to latest version

For detailed analysis, open output/scan_results.json
For visual review, open output/attack_surface.png
For web interface, run: python src/dashboard.py
```

---

## Error Handling Workflow

### Common Error Scenarios

1. **DNS Resolution Failure**
   ```
   [!] Error: Cannot resolve example.com
   Possible causes:
     - Invalid domain name
     - DNS server unreachable
     - Network connectivity issue
   Action: Verify domain name and network connection
   ```

2. **Nmap Execution Failure**
   ```
   [!] Error: Nmap scan failed for 93.184.216.34
   Possible causes:
     - Insufficient privileges (need root/admin for SYN scan)
     - Firewall blocking scan traffic
     - Target blocking/rate-limiting scans
   Action: Run with sudo/admin rights or use TCP connect scan
   ```

3. **Timeout During Scan**
   ```
   [!] Warning: Scan timeout for 93.184.216.34
   Action: Continuing with next target
   Recommendation: Increase timeout value with --timeout flag
   ```

---

## Performance Optimization

### Parallelization Strategy

```python
# Subdomain enumeration: 10 threads
ThreadPoolExecutor(max_workers=10)

# Port scanning: Sequential per IP (Nmap internal parallelization)
# Service identification: 5 concurrent connections
ThreadPoolExecutor(max_workers=5)
```

### Resource Management

```python
# Memory: Stream large results instead of loading all at once
# Network: Rate limit to 10 requests/second
# CPU: Use process pool for graph rendering
```

---

## Continuous Monitoring Workflow

For organizations needing continuous monitoring:

```bash
# Schedule daily scans
crontab -e
0 2 * * * /usr/bin/python3 /path/to/main.py --target example.com --output-dir /var/scans/$(date +\%Y\%m\%d)

# Compare results over time
python compare_scans.py --scan1 20240115 --scan2 20240116
```

---

## Conclusion

The PhantomSurface workflow is designed to be:
- **Systematic**: Follows a logical progression from discovery to assessment
- **Efficient**: Leverages parallelization and intelligent scanning
- **Comprehensive**: Covers all aspects of attack surface mapping
- **Actionable**: Provides clear remediation steps
- **Reproducible**: Can be automated and scheduled

Understanding this workflow enables users to maximize the tool's effectiveness and integrate it into their security operations.
