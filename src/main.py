#!/usr/bin/env python3
"""
PhantomSurface - Main Module
Entry point for PhantomSurface attack surface mapping system.

Author: Security Engineering Student
License: MIT
"""

import sys
import os
import argparse
import logging
import json
import time
from datetime import datetime
from typing import Dict

# Add src directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from asset_discovery import AssetDiscovery
from network_scanner import NetworkScanner
from threat_mapper import ThreatMapper
from visualizer import AttackSurfaceVisualizer


class PhantomSurface:
    """
    Main PhantomSurface class that orchestrates the attack surface mapping workflow.
    """

    VERSION = "1.0.0"
    BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
║   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
║                                                               ║
║   ███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗  ║
║   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝  ║
║   ███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗    ║
║   ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝    ║
║   ███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗  ║
║   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝  ║
║                                                               ║
║          Intelligent Attack Surface Mapping System            ║
║                      Version {version}                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """.format(version=VERSION)

    def __init__(self, target: str, scan_type: str = 'full',
                 output_dir: str = 'output', threads: int = 10):
        """
        Initialize PhantomSurface scanner.

        Args:
            target: Target domain to scan
            scan_type: Type of scan ('quick' or 'full')
            output_dir: Output directory for results
            threads: Number of threads for parallel operations
        """
        self.target = target
        self.scan_type = scan_type
        self.output_dir = output_dir
        self.threads = threads

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Configure logging
        log_file = os.path.join(output_dir, 'scan_log.txt')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.asset_discovery = None
        self.network_scanner = None
        self.threat_mapper = None
        self.visualizer = None

        # Results storage
        self.results = {
            'metadata': {},
            'assets': {},
            'network_scan': {},
            'threats': {},
            'visualization': {}
        }

    def display_banner(self):
        """Display PhantomSurface banner."""
        print(self.BANNER)

    def display_ethical_warning(self) -> bool:
        """
        Display ethical usage warning and get user confirmation.

        Returns:
            True if user confirms, False otherwise
        """
        print("\n" + "⚠️  " * 20)
        print("\n" + " " * 20 + "ETHICAL USAGE WARNING")
        print("\n" + "⚠️  " * 20)
        print("""
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║  You are about to scan: {target:^50} ║
║                                                                       ║
║  Before proceeding, ensure you have:                                  ║
║                                                                       ║
║  ✓ Written authorization to scan this target                         ║
║  ✓ Legal right to perform security testing                           ║
║  ✓ Understanding of applicable laws (CFAA, GDPR, etc.)               ║
║                                                                       ║
║  Unauthorized scanning is ILLEGAL and UNETHICAL.                      ║
║                                                                       ║
║  The developers of PhantomSurface are not responsible for misuse.     ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
        """.format(target=self.target))

        response = input("\nDo you have authorization to scan this target? (yes/no): ")
        return response.lower() in ['yes', 'y']

    def validate_requirements(self) -> bool:
        """
        Validate system requirements.

        Returns:
            True if all requirements met, False otherwise
        """
        print("\n[*] Validating system requirements...")

        # Check Python version
        if sys.version_info < (3, 8):
            print("[!] Error: Python 3.8+ required")
            return False
        print("  [+] Python version: {}.{}.{}".format(*sys.version_info[:3]))

        # Check nmap availability
        try:
            import nmap
            nm = nmap.PortScanner()
            version = nm.nmap_version()
            print(f"  [+] Nmap version: {version[0]}.{version[1]}")
        except Exception as e:
            print(f"  [!] Error: Nmap not found or not properly installed")
            print(f"  [!] {str(e)}")
            return False

        # Check write permissions
        try:
            test_file = os.path.join(self.output_dir, '.test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            print(f"  [+] Output directory writable: {self.output_dir}")
        except Exception as e:
            print(f"  [!] Error: Cannot write to output directory")
            print(f"  [!] {str(e)}")
            return False

        return True

    def run_scan(self) -> Dict:
        """
        Execute complete attack surface scanning workflow.

        Returns:
            Dictionary containing all scan results
        """
        start_time = time.time()
        timestamp = datetime.now().isoformat()

        print(f"\n[*] Scan started at: {timestamp}")
        print(f"[*] Target: {self.target}")
        print(f"[*] Scan type: {self.scan_type}")
        print(f"[*] Output directory: {self.output_dir}")

        # Store metadata
        self.results['metadata'] = {
            'target': self.target,
            'scan_type': self.scan_type,
            'start_time': timestamp,
            'version': self.VERSION
        }

        try:
            # Phase 1: Asset Discovery
            self.logger.info("Starting Phase 1: Asset Discovery")
            self.asset_discovery = AssetDiscovery(
                target_domain=self.target,
                threads=self.threads
            )
            asset_results = self.asset_discovery.discover()

            if not asset_results:
                print("\n[!] Asset discovery failed. Aborting scan.")
                return None

            self.results['assets'] = asset_results

            # Phase 2: Network Scanning
            self.logger.info("Starting Phase 2: Network Scanning")
            self.network_scanner = NetworkScanner(scan_type=self.scan_type)

            # Suppress SSL warnings for banner grabbing
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get unique IPs to scan
            unique_ips = list(asset_results['ip_map'].keys())
            scan_results = self.network_scanner.scan_targets(unique_ips)
            self.results['network_scan'] = scan_results

            # Phase 3: Threat Assessment
            self.logger.info("Starting Phase 3: Threat Assessment")
            self.threat_mapper = ThreatMapper()
            threat_results = self.threat_mapper.analyze_scan_results(scan_results)
            self.results['threats'] = threat_results

            # Generate recommendations
            recommendations = self.threat_mapper.generate_recommendations()
            self.results['recommendations'] = recommendations

            # Phase 4: Visualization
            self.logger.info("Starting Phase 4: Visualization")
            self.visualizer = AttackSurfaceVisualizer(output_dir=self.output_dir)
            self.visualizer.build_graph(
                asset_results,
                scan_results,
                threat_results
            )
            viz_path = self.visualizer.create_visualization(self.target)
            self.results['visualization'] = {
                'output_file': viz_path,
                'statistics': self.visualizer.generate_statistics()
            }

            # Phase 5: Save Results
            end_time = time.time()
            duration = int(end_time - start_time)

            self.results['metadata']['end_time'] = datetime.now().isoformat()
            self.results['metadata']['duration_seconds'] = duration

            # Save JSON results
            json_path = os.path.join(self.output_dir, 'scan_results.json')
            with open(json_path, 'w') as f:
                json.dump(self.results, f, indent=2)

            self.logger.info(f"Scan completed in {duration} seconds")

            # Display final summary
            self.display_summary(duration, json_path, viz_path)

            return self.results

        except KeyboardInterrupt:
            print("\n\n[!] Scan interrupted by user")
            self.logger.warning("Scan interrupted by user")
            return None
        except Exception as e:
            print(f"\n[!] Error during scan: {str(e)}")
            self.logger.error(f"Scan error: {str(e)}", exc_info=True)
            return None

    def display_summary(self, duration: int, json_path: str, viz_path: str):
        """
        Display final scan summary.

        Args:
            duration: Scan duration in seconds
            json_path: Path to JSON results file
            viz_path: Path to visualization file
        """
        print("\n" + "=" * 60)
        print("SCAN COMPLETE")
        print("=" * 60)

        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    SCAN SUMMARY                              ║
╚══════════════════════════════════════════════════════════════╝

Target: {self.target}
Duration: {duration // 60} minutes {duration % 60} seconds

ASSETS DISCOVERED:
  ├─ Total Domains: {self.results['assets']['total_assets']}
  ├─ Unique IPs: {self.results['assets']['unique_ips']}
  └─ Subdomains: {len(self.results['assets']['assets']) - 1}

NETWORK SCAN:
  ├─ Hosts Scanned: {self.results['network_scan']['targets_scanned']}
  ├─ Hosts Up: {self.results['network_scan']['hosts_up']}
  └─ Open Ports: {self.results['network_scan']['total_open_ports']}

THREAT ASSESSMENT:
  ├─ Total Threats: {self.results['threats']['total_threats']}
  ├─ Critical: {self.results['threats']['severity_counts']['CRITICAL']}
  ├─ High: {self.results['threats']['severity_counts']['HIGH']}
  ├─ Medium: {self.results['threats']['severity_counts']['MEDIUM']}
  ├─ Low: {self.results['threats']['severity_counts']['LOW']}
  └─ Overall Risk Score: {self.results['threats']['overall_risk_score']}/100 ({self.results['threats']['risk_level']})

OUTPUT FILES:
  ├─ Results: {json_path}
  ├─ Visualization: {viz_path}
  └─ Log: {os.path.join(self.output_dir, 'scan_log.txt')}

╔══════════════════════════════════════════════════════════════╗
║                  TOP RECOMMENDATIONS                         ║
╚══════════════════════════════════════════════════════════════╝
        """)

        # Display top 5 recommendations
        for i, rec in enumerate(self.results.get('recommendations', [])[:5], 1):
            print(f"{i}. [{rec['severity']}] {rec['threat_type']}")
            print(f"   Affected: {rec['affected_count']} service(s)")
            print(f"   → {rec['action']}\n")

        print("\n[+] For detailed analysis, review the JSON file:")
        print(f"    {json_path}")
        print("\n[+] For visual analysis, open the visualization:")
        print(f"    {viz_path}")
        print("\n[+] To view results in web dashboard, run:")
        print(f"    python src/dashboard.py")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='PhantomSurface - Intelligent Attack Surface Mapping System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target example.com
  python main.py --target example.com --scan-type quick
  python main.py --target example.com --output-dir ./results

For more information, visit: https://github.com/skuser404/PhantomSurface
        """
    )

    parser.add_argument(
        '--target',
        required=True,
        help='Target domain to scan (e.g., example.com)'
    )

    parser.add_argument(
        '--scan-type',
        choices=['quick', 'full'],
        default='full',
        help='Scan type: quick (fast, common ports) or full (comprehensive) [default: full]'
    )

    parser.add_argument(
        '--output-dir',
        default='output',
        help='Output directory for results [default: output]'
    )

    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of threads for parallel operations [default: 10]'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'PhantomSurface {PhantomSurface.VERSION}'
    )

    args = parser.parse_args()

    # Initialize PhantomSurface
    scanner = PhantomSurface(
        target=args.target,
        scan_type=args.scan_type,
        output_dir=args.output_dir,
        threads=args.threads
    )

    # Display banner
    scanner.display_banner()

    # Validate requirements
    if not scanner.validate_requirements():
        print("\n[!] System requirements not met. Exiting.")
        sys.exit(1)

    # Display ethical warning
    if not scanner.display_ethical_warning():
        print("\n[!] Scan cancelled by user. Exiting.")
        sys.exit(0)

    # Run scan
    results = scanner.run_scan()

    if results:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
