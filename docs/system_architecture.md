# System Architecture

## Overview

PhantomSurface employs a modular, pipeline-based architecture designed for scalability, maintainability, and extensibility. The system follows a layered approach where each component has a specific responsibility and interfaces with other components through well-defined contracts.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                          USER INTERFACE LAYER                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌────────────────────┐              ┌─────────────────────┐       │
│  │   CLI Interface    │              │   Web Dashboard      │       │
│  │   (main.py)        │              │   (Flask App)        │       │
│  └─────────┬──────────┘              └──────────┬──────────┘       │
│            │                                     │                   │
└────────────┼─────────────────────────────────────┼───────────────────┘
             │                                     │
             └──────────────┬──────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────────────┐
│                        ORCHESTRATION LAYER                            │
├───────────────────────────────────────────────────────────────────────┤
│                                                                        │
│                      ┌──────────────────────┐                        │
│                      │  Scan Controller     │                        │
│                      │  - Workflow Manager  │                        │
│                      │  - State Management  │                        │
│                      │  - Error Handler     │                        │
│                      └──────────┬───────────┘                        │
│                                 │                                     │
└─────────────────────────────────┼─────────────────────────────────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
┌───────────▼─────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│   PROCESSING LAYER   │  │                 │  │                 │
├──────────────────────┤  │                 │  │                 │
│                      │  │                 │  │                 │
│ ┌──────────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │
│ │ Asset Discovery  │ │  │ │  Network    │ │  │ │   Threat    │ │
│ │                  │ │  │ │  Scanner    │ │  │ │   Mapper    │ │
│ │ - DNS Resolver   │ │  │ │             │ │  │ │             │ │
│ │ - Subdomain Enum │ │  │ │ - Port Scan │ │  │ │ - Risk Anal │ │
│ │ - IP Mapping     │ │  │ │ - Service ID│ │  │ │ - Scoring   │ │
│ │                  │ │  │ │ - Banner Gr │ │  │ │ - Recommend │ │
│ └──────────────────┘ │  │ └─────────────┘ │  │ └─────────────┘ │
│                      │  │                 │  │                 │
└──────────┬───────────┘  └────────┬────────┘  └────────┬────────┘
           │                       │                     │
           └───────────────────────┼─────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│                        VISUALIZATION LAYER                           │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│                    ┌───────────────────────┐                        │
│                    │   Visualizer          │                        │
│                    │   - Graph Builder     │                        │
│                    │   - Layout Engine     │                        │
│                    │   - Renderer          │                        │
│                    └───────────┬───────────┘                        │
│                                │                                     │
└────────────────────────────────┼─────────────────────────────────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────────────┐
│                         DATA LAYER                                   │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │   JSON Store │  │  Image Files │  │   Log Files  │             │
│  │   (Results)  │  │  (PNG/SVG)   │  │   (Audit)    │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. User Interface Layer

#### CLI Interface (main.py)
**Purpose**: Command-line interface for direct system interaction

**Responsibilities**:
- Parse command-line arguments
- Validate user inputs
- Initiate scan workflows
- Display real-time progress
- Present results in terminal

**Key Features**:
- Argument validation using argparse
- Progress bars for long-running operations
- Colored output for better readability
- Error handling and user feedback

**Technologies**: Python argparse, colorama

#### Web Dashboard (dashboard.py)
**Purpose**: Browser-based interface for ease of use

**Responsibilities**:
- Serve web application
- Handle scan requests
- Display results and visualizations
- Provide file downloads
- Manage session state

**Key Features**:
- RESTful API endpoints
- Asynchronous scan execution
- Real-time status updates
- Result caching
- Responsive design

**Technologies**: Flask, HTML/CSS/JavaScript, Bootstrap

### 2. Orchestration Layer

#### Scan Controller
**Purpose**: Coordinate execution of scanning modules

**Responsibilities**:
- Manage workflow execution order
- Pass data between modules
- Handle errors and retries
- Track scan progress
- Aggregate results

**Workflow**:
```python
1. Initialize scan session
2. Execute Asset Discovery
3. Pass discovered assets to Network Scanner
4. Feed scan results to Threat Mapper
5. Send all data to Visualizer
6. Compile final report
7. Clean up resources
```

**Design Pattern**: Pipeline pattern with error handling

### 3. Processing Layer

#### Asset Discovery Module (asset_discovery.py)
**Purpose**: Enumerate all digital assets associated with target

**Components**:

**a) DNS Resolver**
- Resolves domain names to IP addresses
- Handles DNS queries and responses
- Implements caching for efficiency
- Supports IPv4 and IPv6

**b) Subdomain Enumerator**
- **Passive Enumeration**: Uses public DNS records
- **Active Enumeration**: Brute-force common subdomains
- **Wordlist-based**: Tests against predefined subdomain lists
- **Recursive Discovery**: Follows CNAME records

**c) IP Mapper**
- Maps discovered domains to IP addresses
- Identifies shared hosting environments
- Detects CDN usage (Cloudflare, Akaike, etc.)
- Groups assets by IP ranges

**Algorithm**:
```python
1. Resolve target domain → primary IP
2. Generate subdomain candidates from wordlist
3. For each candidate:
   a. Attempt DNS resolution
   b. If successful, store subdomain + IP
   c. Check for CNAME records
   d. Follow CNAME chains
4. Deduplicate results
5. Return asset inventory
```

**Data Structure**:
```python
{
    "domain": "example.com",
    "ip": "93.184.216.34",
    "subdomains": [
        {"name": "www.example.com", "ip": "93.184.216.34"},
        {"name": "mail.example.com", "ip": "93.184.216.35"}
    ]
}
```

#### Network Scanner Module (network_scanner.py)
**Purpose**: Identify open ports and running services

**Components**:

**a) Port Scanner**
- Uses python-nmap wrapper for Nmap
- Implements SYN scan (stealthy)
- Scans common ports by default
- Supports custom port ranges
- Configurable timeout values

**b) Service Identifier**
- Determines service type from port number
- Cross-references with Nmap service database
- Detects service versions
- Identifies operating systems (OS fingerprinting)

**c) Banner Grabber**
- Connects to open ports
- Retrieves service banners
- Extracts version information
- Collects server headers (HTTP)

**Scanning Strategy**:
```python
Quick Scan:
- Top 100 most common ports
- Fast timing template (-T4)
- Basic service detection

Full Scan:
- Ports 1-65535
- Moderate timing template (-T3)
- Version detection (-sV)
- OS detection (-O)
- Script scanning (--script=default)
```

**Data Structure**:
```python
{
    "ip": "93.184.216.34",
    "ports": [
        {
            "port": 80,
            "state": "open",
            "service": "http",
            "version": "Apache httpd 2.4.41",
            "banner": "Apache/2.4.41 (Ubuntu)"
        }
    ]
}
```

#### Threat Mapper Module (threat_mapper.py)
**Purpose**: Analyze discovered services for security risks

**Components**:

**a) Risk Analyzer**
- Evaluates each service against security criteria
- Checks for common misconfigurations
- Identifies outdated software versions
- Detects unnecessary service exposure

**b) Scoring Engine**
- Assigns risk scores (0-100)
- Weights risks by severity
- Calculates overall attack surface score
- Prioritizes findings

**c) Recommendation Generator**
- Provides remediation steps
- Suggests security best practices
- Links to relevant documentation
- Estimates remediation effort

**Risk Criteria**:
```python
CRITICAL (90-100):
- Exposed databases (MySQL, PostgreSQL, MongoDB)
- Unencrypted remote access (Telnet, FTP)
- Known critical vulnerabilities (CVEs)

HIGH (70-89):
- SSH on standard port (22)
- Outdated web servers
- Unnecessary administrative interfaces

MEDIUM (40-69):
- HTTP without HTTPS
- Verbose service banners
- Non-standard port usage

LOW (0-39):
- Properly configured HTTPS
- Updated software versions
- Expected business services
```

**Data Structure**:
```python
{
    "threats": [
        {
            "severity": "HIGH",
            "service": "SSH",
            "port": 22,
            "ip": "93.184.216.34",
            "description": "SSH exposed on standard port",
            "risk_score": 75,
            "recommendation": "Move SSH to non-standard port, implement fail2ban",
            "references": ["CIS Benchmark 5.2", "NIST 800-123"]
        }
    ],
    "overall_risk_score": 62
}
```

### 4. Visualization Layer

#### Visualizer Module (visualizer.py)
**Purpose**: Create visual representations of attack surface

**Components**:

**a) Graph Builder**
- Constructs NetworkX graph from scan data
- Defines node types (domain, IP, service)
- Creates edges based on relationships
- Applies attributes (colors, sizes, labels)

**b) Layout Engine**
- Calculates node positions
- Implements spring layout algorithm
- Prevents node overlapping
- Optimizes for readability

**c) Renderer**
- Generates PNG images using Matplotlib
- Applies color schemes by risk level
- Adds legend and metadata
- Exports in multiple formats

**Graph Schema**:
```python
Nodes:
- Type: domain (blue, large)
- Type: subdomain (light blue, medium)
- Type: ip (green, medium)
- Type: service (color by risk, small)

Edges:
- domain → subdomain (solid)
- subdomain → ip (dashed)
- ip → service (dotted)

Colors:
- Red: Critical risk
- Orange: High risk
- Yellow: Medium risk
- Green: Low risk
```

### 5. Data Layer

#### Storage Components

**JSON Store**:
- Structured result storage
- Scan metadata and timestamps
- Complete asset inventory
- Threat assessment details
- Easy parsing for automation

**Image Files**:
- Attack surface visualizations
- Graph exports (PNG, SVG)
- Embedded in reports
- Shareable artifacts

**Log Files**:
- Detailed operation logs
- Error tracking
- Audit trail
- Debugging information

## Data Flow

### End-to-End Scan Flow

```
1. User Input
   ├─ Target domain
   ├─ Scan parameters
   └─ Output preferences

2. Asset Discovery
   ├─ DNS resolution
   ├─ Subdomain enumeration
   └─ IP mapping
   
3. Network Scanning
   ├─ Port scanning per IP
   ├─ Service identification
   └─ Banner grabbing
   
4. Threat Assessment
   ├─ Risk analysis
   ├─ Scoring calculation
   └─ Recommendation generation
   
5. Visualization
   ├─ Graph construction
   ├─ Layout computation
   └─ Image rendering
   
6. Output Generation
   ├─ JSON export
   ├─ Image saving
   └─ Dashboard display
```

## Design Principles

### 1. Modularity
Each component is self-contained with clear interfaces, enabling:
- Independent testing
- Easy maintenance
- Component reuse
- Parallel development

### 2. Scalability
Architecture supports:
- Large target environments
- Concurrent scanning
- Distributed execution (future)
- Resource optimization

### 3. Extensibility
System designed for easy extension:
- Plugin architecture for new scanners
- Custom threat rules
- Additional visualization formats
- Integration with external tools

### 4. Error Resilience
Robust error handling:
- Graceful degradation
- Retry mechanisms
- Timeout management
- Detailed error reporting

### 5. Security
Built-in security considerations:
- Rate limiting to avoid DoS
- Input validation
- Safe execution of external tools
- Audit logging

## Technology Stack Justification

| Technology | Purpose | Justification |
|------------|---------|---------------|
| Python 3.8+ | Core language | Rich ecosystem, excellent library support, readability |
| python-nmap | Network scanning | Industry-standard tool wrapper, reliable results |
| dnspython | DNS operations | Comprehensive DNS support, pure Python |
| NetworkX | Graph theory | Powerful graph algorithms, mature library |
| Matplotlib | Visualization | Flexible plotting, publication-quality output |
| Flask | Web framework | Lightweight, easy to deploy, RESTful |
| JSON | Data format | Universal support, human-readable, parseable |

## Performance Considerations

### Optimization Strategies

**Concurrency**:
- Thread pool for parallel subdomain enumeration
- Asynchronous I/O for network operations
- Process pool for CPU-intensive tasks

**Caching**:
- DNS result caching
- Service signature caching
- Graph layout caching

**Resource Management**:
- Connection pooling
- Memory-efficient data structures
- Streaming for large datasets

**Estimated Performance**:
- Small target (< 10 subdomains): 2-5 minutes
- Medium target (10-50 subdomains): 5-15 minutes
- Large target (50+ subdomains): 15-45 minutes

## Future Architecture Enhancements

1. **Microservices**: Split components into independent services
2. **Message Queue**: Implement RabbitMQ/Redis for async processing
3. **Database**: Add PostgreSQL for persistent storage
4. **Containerization**: Docker containers for each service
5. **Orchestration**: Kubernetes for scaling and management
6. **API Gateway**: Central API for all client interactions
7. **Monitoring**: Prometheus + Grafana for system metrics

## Conclusion

PhantomSurface's architecture provides a solid foundation for attack surface mapping while maintaining flexibility for future enhancements. The modular design ensures maintainability, the pipeline approach ensures reliability, and the layered structure ensures scalability.
