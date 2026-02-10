#!/usr/bin/env python3
"""
PhantomSurface - Network Scanner Module
Performs port scanning, service identification, and banner grabbing.

Author: Security Engineering Student
License: MIT
"""

import nmap
import socket
import logging
import requests
from typing import Dict, List, Optional
from requests.exceptions import RequestException, Timeout


class NetworkScanner:
    """
    Network Scanner Module for PhantomSurface
    Handles port scanning, service identification, and banner grabbing.
    """

    # Port scan configurations
    QUICK_SCAN_PORTS = '21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443'
    COMMON_PORTS = list(range(1, 1025)) + [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017]

    def __init__(self, scan_type: str = 'full', timeout: int = 300):
        """
        Initialize Network Scanner module.

        Args:
            scan_type: Type of scan - 'quick' or 'full'
            timeout: Scan timeout in seconds
        """
        self.scan_type = scan_type
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

        try:
            self.nm = nmap.PortScanner()
            self.logger.info("Nmap initialized successfully")
        except nmap.PortScannerError:
            self.logger.error("Nmap not found. Please install nmap.")
            raise Exception("Nmap not found. Please install nmap on your system.")

        # Storage for scan results
        self.scan_results = {}

    def check_nmap_version(self) -> str:
        """
        Check installed Nmap version.

        Returns:
            Nmap version string
        """
        try:
            version = self.nm.nmap_version()
            version_str = f"{version[0]}.{version[1]}"
            self.logger.info(f"Nmap version: {version_str}")
            return version_str
        except Exception as e:
            self.logger.error(f"Error checking Nmap version: {str(e)}")
            return "Unknown"

    def scan_ports(self, ip: str) -> Dict:
        """
        Perform port scan on target IP.

        Args:
            ip: Target IP address

        Returns:
            Dictionary containing scan results
        """
        print(f"\n[*] Scanning {ip}...")

        try:
            if self.scan_type == 'quick':
                # Quick scan: top common ports with fast timing
                print(f"  [*] Quick scan mode: scanning common ports")
                self.nm.scan(
                    hosts=ip,
                    ports=self.QUICK_SCAN_PORTS,
                    arguments='-sV -T4 --max-retries 2'
                )
            else:
                # Full scan: comprehensive port range with service detection
                print(f"  [*] Full scan mode: scanning ports 1-1000 + common high ports")
                # Note: Full 65535 port scan takes very long, so we limit to 1-1000 + common
                port_range = '1-1000,' + ','.join(map(str, [p for p in self.COMMON_PORTS if p > 1000]))
                self.nm.scan(
                    hosts=ip,
                    ports=port_range,
                    arguments='-sV -T3 --max-retries 3'
                )

            if ip not in self.nm.all_hosts():
                print(f"  [!] No results for {ip}")
                return {'ip': ip, 'status': 'no_results', 'ports': []}

            # Extract host information
            host_info = self.nm[ip]

            # Check if host is up
            if host_info.state() != 'up':
                print(f"  [!] Host appears to be down")
                return {'ip': ip, 'status': 'down', 'ports': []}

            # Process TCP scan results
            ports_data = []
            if 'tcp' in host_info:
                tcp_ports = host_info['tcp']

                for port, port_info in tcp_ports.items():
                    if port_info['state'] == 'open':
                        service_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'cpe': port_info.get('cpe', '')
                        }
                        ports_data.append(service_info)
                        print(f"    [+] {port}/tcp - {service_info['service']} - {service_info['product']} {service_info['version']}")

            # Try to detect OS (requires root/admin)
            os_info = ''
            if 'osmatch' in host_info:
                if host_info['osmatch']:
                    os_info = host_info['osmatch'][0].get('name', '')

            scan_result = {
                'ip': ip,
                'status': 'up',
                'hostname': host_info.hostname() if host_info.hostname() else '',
                'os': os_info,
                'ports': ports_data,
                'total_open_ports': len(ports_data)
            }

            self.scan_results[ip] = scan_result
            print(f"  [+] Scan complete: {len(ports_data)} open ports found")

            return scan_result

        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan error for {ip}: {str(e)}")
            print(f"  [!] Scan error: {str(e)}")
            return {'ip': ip, 'status': 'error', 'error': str(e), 'ports': []}
        except Exception as e:
            self.logger.error(f"Unexpected error scanning {ip}: {str(e)}")
            print(f"  [!] Unexpected error: {str(e)}")
            return {'ip': ip, 'status': 'error', 'error': str(e), 'ports': []}

    def grab_http_banner(self, ip: str, port: int) -> Dict:
        """
        Grab HTTP headers and banner information.

        Args:
            ip: Target IP address
            port: Target port (usually 80 or 443)

        Returns:
            Dictionary containing HTTP headers and server info
        """
        headers_info = {}

        try:
            # Determine protocol
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{ip}:{port}"

            # Make request with timeout
            response = requests.get(
                url,
                timeout=5,
                verify=False,  # Ignore SSL verification for scanning
                allow_redirects=False
            )

            # Extract interesting headers
            headers_of_interest = [
                'Server', 'X-Powered-By', 'X-AspNet-Version',
                'X-AspNetMvc-Version', 'X-Framework', 'X-Generator'
            ]

            for header in headers_of_interest:
                if header in response.headers:
                    headers_info[header] = response.headers[header]

            # Check for common CMS signatures
            content = response.text[:1000].lower()  # Check first 1000 chars
            if 'wp-content' in content or 'wordpress' in content:
                headers_info['CMS'] = 'WordPress'
            elif 'joomla' in content:
                headers_info['CMS'] = 'Joomla'
            elif 'drupal' in content:
                headers_info['CMS'] = 'Drupal'

            return headers_info

        except Timeout:
            self.logger.debug(f"Timeout grabbing HTTP banner from {ip}:{port}")
            return {}
        except RequestException as e:
            self.logger.debug(f"HTTP request error for {ip}:{port}: {str(e)}")
            return {}
        except Exception as e:
            self.logger.debug(f"Error grabbing HTTP banner: {str(e)}")
            return {}

    def grab_generic_banner(self, ip: str, port: int) -> Optional[str]:
        """
        Grab banner from non-HTTP services.

        Args:
            ip: Target IP address
            port: Target port

        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))

            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            return banner if banner else None

        except socket.timeout:
            self.logger.debug(f"Timeout grabbing banner from {ip}:{port}")
            return None
        except socket.error as e:
            self.logger.debug(f"Socket error grabbing banner from {ip}:{port}: {str(e)}")
            return None
        except Exception as e:
            self.logger.debug(f"Error grabbing banner: {str(e)}")
            return None

    def enhanced_service_detection(self, scan_result: Dict) -> Dict:
        """
        Enhance scan results with additional banner information.

        Args:
            scan_result: Initial scan result dictionary

        Returns:
            Enhanced scan result with banner information
        """
        if scan_result['status'] != 'up':
            return scan_result

        print(f"\n[*] Performing enhanced detection on {scan_result['ip']}...")

        for port_info in scan_result['ports']:
            port = port_info['port']
            service = port_info['service']

            # Grab HTTP banners
            if service in ['http', 'https', 'http-proxy'] or port in [80, 443, 8000, 8080, 8443, 8888]:
                http_info = self.grab_http_banner(scan_result['ip'], port)
                if http_info:
                    port_info['http_headers'] = http_info
                    print(f"  [+] HTTP headers grabbed for port {port}")

            # Grab generic banners for other services
            elif service not in ['tcpwrapped']:
                banner = self.grab_generic_banner(scan_result['ip'], port)
                if banner:
                    port_info['banner'] = banner
                    print(f"  [+] Banner grabbed for port {port}: {banner[:50]}...")

        return scan_result

    def scan_targets(self, ip_list: List[str]) -> Dict:
        """
        Scan multiple IP addresses.

        Args:
            ip_list: List of IP addresses to scan

        Returns:
            Dictionary containing all scan results
        """
        print("\n" + "=" * 60)
        print("PHASE 2: NETWORK SCANNING")
        print("=" * 60)

        # Check Nmap version
        nmap_version = self.check_nmap_version()
        print(f"\n[*] Using Nmap version: {nmap_version}")
        print(f"[*] Scan type: {self.scan_type}")
        print(f"[*] Targets: {len(ip_list)} unique IP(s)")

        all_results = []

        for ip in ip_list:
            # Perform port scan
            result = self.scan_ports(ip)

            # Enhance with banner grabbing
            if result['status'] == 'up' and result['ports']:
                result = self.enhanced_service_detection(result)

            all_results.append(result)

        # Display summary
        total_open_ports = sum(r.get('total_open_ports', 0) for r in all_results)

        print(f"\n[+] Network Scanning Summary:")
        print(f"  ├─ IPs Scanned: {len(ip_list)}")
        print(f"  ├─ Hosts Up: {sum(1 for r in all_results if r['status'] == 'up')}")
        print(f"  └─ Total Open Ports: {total_open_ports}")

        return {
            'scan_type': self.scan_type,
            'targets_scanned': len(ip_list),
            'hosts_up': sum(1 for r in all_results if r['status'] == 'up'),
            'total_open_ports': total_open_ports,
            'results': all_results
        }


def main():
    """Test function for standalone execution."""
    import sys

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Disable SSL warnings for banner grabbing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Test with IP address
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    else:
        print("Usage: python network_scanner.py <target_ip>")
        print("Example: python network_scanner.py 93.184.216.34")
        sys.exit(1)

    # Initialize and run scanner
    scanner = NetworkScanner(scan_type='quick')
    results = scanner.scan_targets([target_ip])

    if results:
        print("\n[+] Scanning completed successfully!")
        print(f"[+] Found {results['total_open_ports']} open ports")
    else:
        print("\n[!] Scanning failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
