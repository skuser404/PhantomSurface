#!/usr/bin/env python3
"""
PhantomSurface - Threat Mapper Module
Analyzes discovered services and identifies security threats.

Author: Security Engineering Student
License: MIT
"""

import logging
from typing import Dict, List, Tuple


class ThreatMapper:
    """
    Threat Mapper Module for PhantomSurface
    Analyzes scan results to identify security threats and assign risk scores.
    """

    # Threat assessment rules
    THREAT_RULES = {
        # Critical threats - score 90-100
        'exposed_database': {
            'ports': [3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 9042, 7000, 7001],
            'services': ['mysql', 'postgresql', 'ms-sql-s', 'oracle', 'mongodb', 'redis', 'elasticsearch', 'couchdb'],
            'severity': 'CRITICAL',
            'base_score': 95,
            'description': 'Database service exposed to internet - high risk of data breach',
            'recommendation': 'Immediately restrict database access to internal IPs only. Use firewall rules or security groups.'
        },
        'unencrypted_remote_access': {
            'ports': [23, 512, 513, 514],
            'services': ['telnet', 'rexec', 'rlogin', 'rsh'],
            'severity': 'CRITICAL',
            'base_score': 90,
            'description': 'Unencrypted remote access protocol detected - credentials can be intercepted',
            'recommendation': 'Disable unencrypted protocols immediately. Use SSH instead of Telnet.'
        },
        
        # High threats - score 70-89
        'ssh_standard_port': {
            'ports': [22],
            'services': ['ssh'],
            'severity': 'HIGH',
            'base_score': 75,
            'description': 'SSH exposed on standard port - susceptible to brute-force attacks',
            'recommendation': 'Move SSH to non-standard port (e.g., 2222), disable root login, use key-based authentication, install fail2ban.'
        },
        'rdp_exposed': {
            'ports': [3389],
            'services': ['ms-wbt-server'],
            'severity': 'HIGH',
            'base_score': 80,
            'description': 'RDP exposed to internet - known vulnerabilities and brute-force risk',
            'recommendation': 'Restrict RDP to VPN access only. Enable Network Level Authentication (NLA). Use strong passwords.'
        },
        'ftp_exposed': {
            'ports': [21],
            'services': ['ftp'],
            'severity': 'HIGH',
            'base_score': 78,
            'description': 'FTP service detected - often transmits credentials in plaintext',
            'recommendation': 'Replace FTP with SFTP or FTPS. If FTP is necessary, ensure it uses explicit TLS (FTPS).'
        },
        'admin_panel_risk': {
            'ports': [8080, 8443, 10000],
            'services': ['http-proxy', 'https-alt', 'webmin'],
            'severity': 'HIGH',
            'base_score': 72,
            'description': 'Administrative interface potentially exposed on non-standard port',
            'recommendation': 'Restrict administrative interfaces to internal IPs or VPN. Implement strong authentication.'
        },
        
        # Medium threats - score 40-69
        'http_no_https': {
            'ports': [80],
            'services': ['http'],
            'severity': 'MEDIUM',
            'base_score': 50,
            'description': 'HTTP service without HTTPS - data transmitted in plaintext',
            'recommendation': 'Implement HTTPS with valid SSL/TLS certificate. Redirect all HTTP traffic to HTTPS.'
        },
        'smtp_exposed': {
            'ports': [25, 587],
            'services': ['smtp', 'submission'],
            'severity': 'MEDIUM',
            'base_score': 45,
            'description': 'SMTP service exposed - potential spam relay or credential attacks',
            'recommendation': 'Ensure SMTP requires authentication. Implement SPF, DKIM, and DMARC records. Use submission port (587) with TLS.'
        },
        'vnc_exposed': {
            'ports': [5900, 5901, 5902],
            'services': ['vnc'],
            'severity': 'MEDIUM',
            'base_score': 68,
            'description': 'VNC remote desktop exposed - weak authentication by default',
            'recommendation': 'Restrict VNC to local network or VPN. Use SSH tunneling for remote access.'
        },
        
        # Low threats - score 0-39
        'https_service': {
            'ports': [443],
            'services': ['https', 'ssl/http'],
            'severity': 'LOW',
            'base_score': 20,
            'description': 'HTTPS service detected - generally secure if properly configured',
            'recommendation': 'Ensure strong TLS configuration (TLS 1.2+), valid certificate, and HSTS header.'
        },
        'dns_service': {
            'ports': [53],
            'services': ['domain'],
            'severity': 'LOW',
            'base_score': 25,
            'description': 'DNS service exposed - check for DNS amplification vulnerability',
            'recommendation': 'Disable DNS recursion for public queries. Implement rate limiting.'
        }
    }

    def __init__(self):
        """Initialize Threat Mapper module."""
        self.logger = logging.getLogger(__name__)
        self.threats = []
        self.overall_risk_score = 0

    def analyze_service(self, ip: str, port_info: Dict) -> List[Dict]:
        """
        Analyze a single service for threats.

        Args:
            ip: IP address of the service
            port_info: Dictionary containing port and service information

        Returns:
            List of threat dictionaries
        """
        threats_found = []
        port = port_info['port']
        service = port_info['service']

        # Check each threat rule
        for threat_name, rule in self.THREAT_RULES.items():
            # Check if port or service matches rule
            port_match = port in rule['ports']
            service_match = service in rule['services']

            if port_match or service_match:
                # Calculate risk score
                risk_score = rule['base_score']

                # Adjust score based on additional factors
                # Check for version information (outdated = higher risk)
                if port_info.get('version') and 'old' in port_info.get('version', '').lower():
                    risk_score += 5

                # Check for known vulnerable products
                product = port_info.get('product', '').lower()
                if any(vuln in product for vuln in ['apache/2.2', 'nginx/1.0', 'openssh/5', 'openssh/6']):
                    risk_score += 10

                # Cap at 100
                risk_score = min(risk_score, 100)

                # Create threat entry
                threat = {
                    'threat_type': threat_name,
                    'ip': ip,
                    'port': port,
                    'service': service,
                    'product': port_info.get('product', 'Unknown'),
                    'version': port_info.get('version', 'Unknown'),
                    'severity': rule['severity'],
                    'risk_score': risk_score,
                    'description': rule['description'],
                    'recommendation': rule['recommendation']
                }

                threats_found.append(threat)
                self.logger.info(f"Threat identified: {threat_name} on {ip}:{port}")

        return threats_found

    def analyze_scan_results(self, scan_results: Dict) -> Dict:
        """
        Analyze complete scan results for threats.

        Args:
            scan_results: Dictionary containing network scan results

        Returns:
            Dictionary containing threat assessment
        """
        print("\n" + "=" * 60)
        print("PHASE 3: THREAT ASSESSMENT")
        print("=" * 60)

        all_threats = []

        # Analyze each scanned host
        for result in scan_results.get('results', []):
            if result['status'] != 'up':
                continue

            ip = result['ip']
            print(f"\n[*] Analyzing {ip}...")

            # Analyze each open port
            for port_info in result['ports']:
                threats = self.analyze_service(ip, port_info)
                all_threats.extend(threats)

                if threats:
                    for threat in threats:
                        severity_color = self._get_severity_symbol(threat['severity'])
                        print(f"  {severity_color} {threat['severity']}: {threat['service']} on port {threat['port']}")

        # Sort threats by risk score (highest first)
        all_threats.sort(key=lambda x: x['risk_score'], reverse=True)

        # Calculate overall risk score
        if all_threats:
            # Weighted average based on severity
            severity_weights = {'CRITICAL': 1.0, 'HIGH': 0.7, 'MEDIUM': 0.4, 'LOW': 0.2}
            total_weighted_score = sum(
                t['risk_score'] * severity_weights[t['severity']]
                for t in all_threats
            )
            total_weight = sum(severity_weights[t['severity']] for t in all_threats)
            overall_score = int(total_weighted_score / total_weight)
        else:
            overall_score = 0

        # Count threats by severity
        severity_counts = {
            'CRITICAL': len([t for t in all_threats if t['severity'] == 'CRITICAL']),
            'HIGH': len([t for t in all_threats if t['severity'] == 'HIGH']),
            'MEDIUM': len([t for t in all_threats if t['severity'] == 'MEDIUM']),
            'LOW': len([t for t in all_threats if t['severity'] == 'LOW'])
        }

        # Determine overall risk level
        if overall_score >= 80:
            risk_level = 'CRITICAL'
        elif overall_score >= 60:
            risk_level = 'HIGH'
        elif overall_score >= 40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        # Display summary
        print(f"\n[+] Threat Assessment Summary:")
        print(f"  ├─ Total Threats: {len(all_threats)}")
        print(f"  ├─ Critical: {severity_counts['CRITICAL']}")
        print(f"  ├─ High: {severity_counts['HIGH']}")
        print(f"  ├─ Medium: {severity_counts['MEDIUM']}")
        print(f"  ├─ Low: {severity_counts['LOW']}")
        print(f"  ├─ Overall Risk Score: {overall_score}/100")
        print(f"  └─ Risk Level: {risk_level}")

        # Display top recommendations
        if all_threats:
            print(f"\n[!] Top Security Recommendations:")
            for i, threat in enumerate(all_threats[:5], 1):
                print(f"\n  {i}. [{threat['severity']}] {threat['ip']}:{threat['port']} - {threat['service']}")
                print(f"     → {threat['recommendation']}")

        self.threats = all_threats
        self.overall_risk_score = overall_score

        return {
            'total_threats': len(all_threats),
            'severity_counts': severity_counts,
            'overall_risk_score': overall_score,
            'risk_level': risk_level,
            'threats': all_threats
        }

    def _get_severity_symbol(self, severity: str) -> str:
        """
        Get colored symbol for severity level.

        Args:
            severity: Severity level string

        Returns:
            Colored symbol string
        """
        symbols = {
            'CRITICAL': '[🔴]',
            'HIGH': '[🟠]',
            'MEDIUM': '[🟡]',
            'LOW': '[🟢]'
        }
        return symbols.get(severity, '[⚪]')

    def generate_recommendations(self) -> List[Dict]:
        """
        Generate prioritized remediation recommendations.

        Returns:
            List of recommendation dictionaries
        """
        recommendations = []

        # Group threats by type
        threat_groups = {}
        for threat in self.threats:
            threat_type = threat['threat_type']
            if threat_type not in threat_groups:
                threat_groups[threat_type] = []
            threat_groups[threat_type].append(threat)

        # Generate recommendations for each threat type
        priority = 1
        for threat_type, threats in threat_groups.items():
            if threats:
                first_threat = threats[0]
                recommendation = {
                    'priority': priority,
                    'threat_type': threat_type,
                    'severity': first_threat['severity'],
                    'affected_count': len(threats),
                    'action': first_threat['recommendation'],
                    'affected_services': [
                        f"{t['ip']}:{t['port']}" for t in threats
                    ]
                }
                recommendations.append(recommendation)
                priority += 1

        return recommendations


def main():
    """Test function for standalone execution."""
    import json

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Sample scan results for testing
    sample_results = {
        'results': [
            {
                'ip': '93.184.216.34',
                'status': 'up',
                'ports': [
                    {'port': 22, 'service': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1'},
                    {'port': 80, 'service': 'http', 'product': 'Apache', 'version': '2.4.41'},
                    {'port': 443, 'service': 'https', 'product': 'Apache', 'version': '2.4.41'},
                    {'port': 3306, 'service': 'mysql', 'product': 'MySQL', 'version': '5.7.32'}
                ]
            }
        ]
    }

    # Initialize and run threat mapper
    mapper = ThreatMapper()
    threat_assessment = mapper.analyze_scan_results(sample_results)

    print("\n[+] Threat assessment completed!")
    print(f"[+] Risk Score: {threat_assessment['overall_risk_score']}/100")
    print(f"[+] Risk Level: {threat_assessment['risk_level']}")

    # Generate recommendations
    recommendations = mapper.generate_recommendations()
    print(f"\n[+] Generated {len(recommendations)} recommendations")


if __name__ == "__main__":
    main()
