#!/usr/bin/env python3
"""
PhantomSurface - Asset Discovery Module
Discovers and enumerates digital assets associated with a target domain.

Author: Security Engineering Student
License: MIT
"""

import dns.resolver
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional


class AssetDiscovery:
    """
    Asset Discovery Module for PhantomSurface
    Handles domain resolution, subdomain enumeration, and IP mapping.
    """

    # Common subdomain wordlist for enumeration
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'dev', 'staging', 'test',
        'api', 'portal', 'blog', 'shop', 'store', 'cdn', 'assets', 'static', 'media',
        'vpn', 'remote', 'cloud', 'admin', 'administrator', 'demo', 'support', 'help',
        'secure', 'ssl', 'ftp2', 'backup', 'news', 'forum', 'forums', 'download',
        'downloads', 'mysql', 'sql', 'database', 'db', 'video', 'stream', 'mobile',
        'm', 'mx', 'mx1', 'mx2', 'dns', 'dns1', 'dns2', 'email', 'direct', 'img',
        'images', 'pics', 'photos', 'upload', 'uploads', 'prod', 'production',
        'crm', 'erp', 'intranet', 'extranet', 'git', 'svn', 'jenkins', 'jira',
        'confluence', 'wiki', 'docs', 'documentation', 'dashboard', 'app', 'apps'
    ]

    def __init__(self, target_domain: str, timeout: int = 5, threads: int = 10):
        """
        Initialize Asset Discovery module.

        Args:
            target_domain: The primary domain to scan
            timeout: DNS resolution timeout in seconds
            threads: Number of concurrent threads for subdomain enumeration
        """
        self.target_domain = target_domain.lower().strip()
        self.timeout = timeout
        self.threads = threads
        self.logger = logging.getLogger(__name__)

        # Storage for discovered assets
        self.discovered_assets = []
        self.ip_map = {}

        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def resolve_domain(self, domain: str) -> Optional[str]:
        """
        Resolve a domain name to its IP address.

        Args:
            domain: Domain name to resolve

        Returns:
            IP address as string, or None if resolution fails
        """
        try:
            # Try A record (IPv4)
            answers = self.resolver.resolve(domain, 'A')
            ip_address = str(answers[0])
            self.logger.info(f"Resolved {domain} → {ip_address}")
            return ip_address
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"Domain not found: {domain}")
            return None
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No A record for: {domain}")
            return None
        except dns.resolver.Timeout:
            self.logger.warning(f"DNS timeout for: {domain}")
            return None
        except Exception as e:
            self.logger.error(f"Error resolving {domain}: {str(e)}")
            return None

    def get_cname_record(self, domain: str) -> Optional[str]:
        """
        Get CNAME record for a domain if it exists.

        Args:
            domain: Domain to check for CNAME

        Returns:
            CNAME target as string, or None if no CNAME exists
        """
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            cname = str(answers[0].target).rstrip('.')
            self.logger.info(f"CNAME: {domain} → {cname}")
            return cname
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception as e:
            self.logger.debug(f"Error getting CNAME for {domain}: {str(e)}")
            return None

    def check_subdomain(self, subdomain: str) -> Optional[Dict]:
        """
        Check if a subdomain exists and resolve its IP.

        Args:
            subdomain: Subdomain prefix (e.g., 'www')

        Returns:
            Dictionary with subdomain info, or None if not found
        """
        fqdn = f"{subdomain}.{self.target_domain}"

        # First check for CNAME
        cname = self.get_cname_record(fqdn)

        # Resolve IP address
        ip_address = self.resolve_domain(fqdn)

        if ip_address:
            return {
                'domain': fqdn,
                'subdomain': subdomain,
                'ip': ip_address,
                'cname': cname
            }

        return None

    def enumerate_subdomains(self, custom_wordlist: Optional[List[str]] = None) -> List[Dict]:
        """
        Enumerate subdomains using wordlist-based approach.

        Args:
            custom_wordlist: Optional custom subdomain wordlist

        Returns:
            List of discovered subdomain dictionaries
        """
        wordlist = custom_wordlist if custom_wordlist else self.COMMON_SUBDOMAINS

        print(f"\n[*] Enumerating subdomains for {self.target_domain}")
        print(f"[*] Testing {len(wordlist)} subdomain candidates with {self.threads} threads...")

        discovered = []

        # Use ThreadPoolExecutor for parallel subdomain checking
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all subdomain checks
            future_to_subdomain = {
                executor.submit(self.check_subdomain, sub): sub
                for sub in wordlist
            }

            # Process results as they complete
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    discovered.append(result)
                    print(f"  [+] Found: {result['domain']} → {result['ip']}")

        self.discovered_assets.extend(discovered)
        self.logger.info(f"Discovered {len(discovered)} subdomains")

        return discovered

    def map_ips(self) -> Dict[str, List[str]]:
        """
        Map IP addresses to their associated domains.

        Returns:
            Dictionary mapping IPs to list of domains
        """
        ip_map = {}

        for asset in self.discovered_assets:
            ip = asset['ip']
            domain = asset['domain']

            if ip not in ip_map:
                ip_map[ip] = []

            ip_map[ip].append(domain)

        self.ip_map = ip_map
        return ip_map

    def discover(self) -> Dict:
        """
        Main discovery workflow: resolve primary domain and enumerate subdomains.

        Returns:
            Dictionary containing all discovered assets and mappings
        """
        print("\n" + "=" * 60)
        print("PHASE 1: ASSET DISCOVERY")
        print("=" * 60)

        # Step 1: Resolve primary domain
        print(f"\n[*] Resolving primary domain: {self.target_domain}")
        primary_ip = self.resolve_domain(self.target_domain)

        if not primary_ip:
            print(f"[!] Error: Could not resolve primary domain {self.target_domain}")
            print("[!] Please verify the domain name and your network connection")
            return None

        print(f"  [+] {self.target_domain} → {primary_ip}")

        # Add primary domain to discovered assets
        self.discovered_assets.append({
            'domain': self.target_domain,
            'subdomain': None,
            'ip': primary_ip,
            'cname': None
        })

        # Step 2: Enumerate subdomains
        subdomains = self.enumerate_subdomains()

        # Step 3: Map IPs to domains
        print(f"\n[*] Mapping IP addresses...")
        ip_map = self.map_ips()

        # Display summary
        print(f"\n[+] Asset Discovery Summary:")
        print(f"  ├─ Total Domains: {len(self.discovered_assets)}")
        print(f"  ├─ Unique IPs: {len(ip_map)}")
        print(f"  └─ Subdomains Found: {len(subdomains)}")

        # Display IP mapping
        print(f"\n[*] IP Address Mapping:")
        for ip, domains in ip_map.items():
            print(f"  ├─ {ip}")
            for domain in domains:
                print(f"  │  └─ {domain}")

        return {
            'target': self.target_domain,
            'primary_ip': primary_ip,
            'total_assets': len(self.discovered_assets),
            'unique_ips': len(ip_map),
            'assets': self.discovered_assets,
            'ip_map': ip_map
        }


def main():
    """Test function for standalone execution."""
    import sys

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Test with example domain
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        print("Usage: python asset_discovery.py <target_domain>")
        print("Example: python asset_discovery.py example.com")
        sys.exit(1)

    # Initialize and run discovery
    discovery = AssetDiscovery(target_domain=target, threads=10)
    results = discovery.discover()

    if results:
        print("\n[+] Discovery completed successfully!")
        print(f"[+] Found {results['total_assets']} assets across {results['unique_ips']} IPs")
    else:
        print("\n[!] Discovery failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
