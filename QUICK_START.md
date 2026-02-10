# PhantomSurface - Quick Start Guide

## ⚡ 5-Minute Setup

### Prerequisites Check
```bash
# Check Python version (need 3.8+)
python3 --version

# Check if Nmap is installed
nmap --version
```

### Installation
```bash
# 1. Navigate to project
cd PhantomSurface

# 2. Create virtual environment
python3 -m venv venv

# 3. Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify installation
python src/main.py --version
```

### First Scan (CLI)
```bash
# Run a quick scan on example.com
python src/main.py --target example.com --scan-type quick

# Output files will be in: output/
# - scan_results.json
# - attack_surface.png
# - scan_log.txt
```

### Web Dashboard
```bash
# Start the web server
python src/dashboard.py

# Open browser to:
# http://localhost:5000

# Enter target domain and click "Start Scan"
```

---

## 🎯 Common Use Cases

### 1. Security Audit
```bash
# Comprehensive scan
python src/main.py --target yourdomain.com --scan-type full

# Review output/scan_results.json for threats
# Open output/attack_surface.png for visualization
```

### 2. Continuous Monitoring
```bash
# Schedule daily scans (Linux/macOS cron)
0 2 * * * cd /path/to/PhantomSurface && ./venv/bin/python src/main.py --target yourdomain.com
```

### 3. Custom Output Directory
```bash
# Save results to specific location
python src/main.py --target example.com --output-dir /path/to/results
```

---

## 🔧 Troubleshooting

### Nmap Not Found
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Verify
nmap --version
```

### Permission Denied (Port Scanning)
```bash
# Some scan types require root/admin
# Quick scans usually work without root

# Run with sudo if needed (Linux/macOS)
sudo python src/main.py --target example.com
```

### Module Not Found
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

---

## 📊 Understanding Results

### Risk Scores
- **90-100**: 🔴 CRITICAL - Immediate action required
- **70-89**: 🟠 HIGH - Address within 24 hours
- **40-69**: 🟡 MEDIUM - Address within 1 week
- **0-39**: 🟢 LOW - Monitor and plan remediation

### Common Threats
1. **Exposed Database** (CRITICAL): Close ports 3306, 5432, 27017
2. **SSH on Port 22** (HIGH): Move to non-standard port
3. **HTTP without HTTPS** (MEDIUM): Implement SSL/TLS
4. **Outdated Software** (varies): Update to latest versions

---

## ⚖️ Legal Reminder

**ALWAYS obtain written authorization before scanning!**

✅ Your own domains  
✅ Company-owned infrastructure (with permission)  
✅ Authorized penetration testing engagements  
❌ Any domain without explicit permission  

---

## 🆘 Need Help?

1. Check `docs/workflow.md` for detailed operation
2. Review `docs/threat_model.md` for threat explanations
3. Read `PROJECT_COMPLETION_REPORT.md` for full details
4. Examine code comments in source files

---

## 🚀 Next Steps

1. **Test on Safe Targets**: Start with your own domains
2. **Analyze Results**: Review threat assessment and recommendations
3. **Implement Fixes**: Follow remediation steps
4. **Re-scan**: Verify improvements with follow-up scans
5. **Automate**: Set up scheduled scans for continuous monitoring

---

**Ready to secure your attack surface? Start scanning! 🔐**

*Remember: Use responsibly and ethically.*
