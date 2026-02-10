#!/usr/bin/env python3
"""
PhantomSurface - Visualizer Module
Creates visual representations of attack surface using graph theory.

Author: Security Engineering Student
License: MIT
"""

import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import logging
from typing import Dict, List
import os


class AttackSurfaceVisualizer:
    """
    Visualizer Module for PhantomSurface
    Creates graph-based visualizations of the discovered attack surface.
    """

    # Color scheme for different node types and risk levels
    COLORS = {
        'root_domain': '#2E86AB',      # Blue
        'subdomain': '#A23B72',        # Purple
        'ip': '#F18F01',               # Orange
        'service_critical': '#D62828', # Red
        'service_high': '#F77F00',     # Dark Orange
        'service_medium': '#FCBF49',   # Yellow
        'service_low': '#06A77D',      # Green
        'service_unknown': '#6C757D'   # Gray
    }

    def __init__(self, output_dir: str = 'output'):
        """
        Initialize Visualizer module.

        Args:
            output_dir: Directory to save visualization output
        """
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
        self.graph = nx.DiGraph()

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

    def get_risk_color(self, risk_score: int) -> str:
        """
        Determine color based on risk score.

        Args:
            risk_score: Risk score (0-100)

        Returns:
            Color hex code
        """
        if risk_score >= 90:
            return self.COLORS['service_critical']
        elif risk_score >= 70:
            return self.COLORS['service_high']
        elif risk_score >= 40:
            return self.COLORS['service_medium']
        elif risk_score > 0:
            return self.COLORS['service_low']
        else:
            return self.COLORS['service_unknown']

    def get_service_label(self, service_info: Dict) -> str:
        """
        Create a concise label for a service node.

        Args:
            service_info: Service information dictionary

        Returns:
            Formatted label string
        """
        port = service_info['port']
        service = service_info['service']
        return f"{port}/{service}"

    def build_graph(self, asset_data: Dict, scan_data: Dict, threat_data: Dict) -> nx.DiGraph:
        """
        Build NetworkX graph from scan results.

        Args:
            asset_data: Asset discovery results
            scan_data: Network scan results
            threat_data: Threat assessment results

        Returns:
            NetworkX DiGraph object
        """
        print("\n[*] Building attack surface graph...")

        # Create threat lookup for quick access
        threat_lookup = {}
        for threat in threat_data.get('threats', []):
            key = (threat['ip'], threat['port'])
            if key not in threat_lookup:
                threat_lookup[key] = []
            threat_lookup[key].append(threat)

        # Add root domain node
        root_domain = asset_data['target']
        self.graph.add_node(
            root_domain,
            node_type='root_domain',
            color=self.COLORS['root_domain'],
            size=3000,
            label=root_domain
        )

        # Add subdomain and IP nodes
        for asset in asset_data['assets']:
            domain = asset['domain']
            ip = asset['ip']

            # Add domain node (if not root)
            if domain != root_domain:
                self.graph.add_node(
                    domain,
                    node_type='subdomain',
                    color=self.COLORS['subdomain'],
                    size=2000,
                    label=domain
                )
                # Add edge from root to subdomain
                self.graph.add_edge(root_domain, domain)

            # Add IP node if not already present
            if not self.graph.has_node(ip):
                self.graph.add_node(
                    ip,
                    node_type='ip',
                    color=self.COLORS['ip'],
                    size=2000,
                    label=ip
                )

            # Add edge from domain to IP
            self.graph.add_edge(domain, ip)

        # Add service nodes
        service_count = 0
        for result in scan_data.get('results', []):
            if result['status'] != 'up':
                continue

            ip = result['ip']

            for port_info in result['ports']:
                port = port_info['port']
                service = port_info['service']

                # Create unique service node ID
                service_id = f"{ip}:{port}/{service}"

                # Determine risk color
                threat_key = (ip, port)
                if threat_key in threat_lookup:
                    # Use highest risk score if multiple threats
                    max_risk = max(t['risk_score'] for t in threat_lookup[threat_key])
                    color = self.get_risk_color(max_risk)
                else:
                    color = self.COLORS['service_low']

                # Add service node
                self.graph.add_node(
                    service_id,
                    node_type='service',
                    color=color,
                    size=1000,
                    label=self.get_service_label(port_info),
                    port=port,
                    service=service
                )

                # Add edge from IP to service
                self.graph.add_edge(ip, service_id)
                service_count += 1

        print(f"  [+] Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
        print(f"  [+] Node breakdown: 1 root, {len([n for n in self.graph.nodes() if self.graph.nodes[n]['node_type'] == 'subdomain'])} subdomains, "
              f"{len([n for n in self.graph.nodes() if self.graph.nodes[n]['node_type'] == 'ip'])} IPs, {service_count} services")

        return self.graph

    def create_visualization(self, target_domain: str, filename: str = 'attack_surface.png') -> str:
        """
        Create and save visualization of attack surface.

        Args:
            target_domain: Target domain name (for title)
            filename: Output filename

        Returns:
            Path to saved visualization
        """
        print("\n" + "=" * 60)
        print("PHASE 4: VISUALIZATION")
        print("=" * 60)

        output_path = os.path.join(self.output_dir, filename)

        # Create figure
        fig, ax = plt.subplots(figsize=(20, 14))
        fig.patch.set_facecolor('white')

        # Calculate layout
        print("\n[*] Computing graph layout...")
        pos = nx.spring_layout(
            self.graph,
            k=2,           # Optimal distance between nodes
            iterations=50,
            seed=42        # Reproducible layout
        )

        # Draw nodes by type
        print("[*] Rendering nodes...")
        for node_type in ['root_domain', 'subdomain', 'ip', 'service']:
            # Get all nodes of this type
            nodes = [
                n for n in self.graph.nodes()
                if self.graph.nodes[n]['node_type'] == node_type
            ]

            if not nodes:
                continue

            # Get node attributes
            colors = [self.graph.nodes[n]['color'] for n in nodes]
            sizes = [self.graph.nodes[n]['size'] for n in nodes]
            labels = {n: self.graph.nodes[n]['label'] for n in nodes}

            # Draw nodes
            nx.draw_networkx_nodes(
                self.graph, pos,
                nodelist=nodes,
                node_color=colors,
                node_size=sizes,
                alpha=0.9,
                ax=ax
            )

            # Draw labels for non-service nodes (services would clutter)
            if node_type != 'service':
                nx.draw_networkx_labels(
                    self.graph, pos,
                    labels,
                    font_size=10,
                    font_weight='bold',
                    ax=ax
                )
            else:
                # Smaller labels for services
                nx.draw_networkx_labels(
                    self.graph, pos,
                    labels,
                    font_size=7,
                    ax=ax
                )

        # Draw edges
        print("[*] Rendering edges...")
        nx.draw_networkx_edges(
            self.graph, pos,
            alpha=0.3,
            arrows=True,
            arrowsize=15,
            width=1.5,
            edge_color='#666666',
            ax=ax
        )

        # Create legend
        print("[*] Adding legend...")
        legend_elements = [
            mpatches.Patch(color=self.COLORS['root_domain'], label='Root Domain'),
            mpatches.Patch(color=self.COLORS['subdomain'], label='Subdomain'),
            mpatches.Patch(color=self.COLORS['ip'], label='IP Address'),
            mpatches.Patch(color=self.COLORS['service_critical'], label='Critical Risk Service'),
            mpatches.Patch(color=self.COLORS['service_high'], label='High Risk Service'),
            mpatches.Patch(color=self.COLORS['service_medium'], label='Medium Risk Service'),
            mpatches.Patch(color=self.COLORS['service_low'], label='Low Risk Service'),
        ]

        ax.legend(
            handles=legend_elements,
            loc='upper left',
            fontsize=11,
            framealpha=0.9
        )

        # Add title
        ax.set_title(
            f'Attack Surface Map - {target_domain}',
            fontsize=18,
            fontweight='bold',
            pad=20
        )

        # Remove axis
        ax.axis('off')

        # Add metadata text
        metadata_text = (
            f"Nodes: {self.graph.number_of_nodes()} | "
            f"Edges: {self.graph.number_of_edges()} | "
            f"Generated by PhantomSurface"
        )
        fig.text(0.5, 0.02, metadata_text, ha='center', fontsize=10, style='italic')

        # Save figure
        plt.tight_layout()
        plt.savefig(
            output_path,
            dpi=300,
            bbox_inches='tight',
            facecolor='white',
            edgecolor='none'
        )
        plt.close()

        print(f"\n[+] Visualization saved: {output_path}")
        print(f"[+] Resolution: 300 DPI")
        print(f"[+] Format: PNG")

        return output_path

    def generate_statistics(self) -> Dict:
        """
        Generate graph statistics.

        Returns:
            Dictionary containing graph statistics
        """
        if not self.graph:
            return {}

        stats = {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'node_types': {},
            'average_degree': 0
        }

        # Count nodes by type
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node]['node_type']
            stats['node_types'][node_type] = stats['node_types'].get(node_type, 0) + 1

        # Calculate average degree
        if stats['total_nodes'] > 0:
            degrees = [self.graph.degree(n) for n in self.graph.nodes()]
            stats['average_degree'] = sum(degrees) / len(degrees)

        return stats


def main():
    """Test function for standalone execution."""
    import json

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Sample data for testing
    sample_asset_data = {
        'target': 'example.com',
        'assets': [
            {'domain': 'example.com', 'ip': '93.184.216.34'},
            {'domain': 'www.example.com', 'ip': '93.184.216.34'},
            {'domain': 'mail.example.com', 'ip': '93.184.216.35'}
        ]
    }

    sample_scan_data = {
        'results': [
            {
                'ip': '93.184.216.34',
                'status': 'up',
                'ports': [
                    {'port': 22, 'service': 'ssh'},
                    {'port': 80, 'service': 'http'},
                    {'port': 443, 'service': 'https'}
                ]
            },
            {
                'ip': '93.184.216.35',
                'status': 'up',
                'ports': [
                    {'port': 25, 'service': 'smtp'},
                    {'port': 587, 'service': 'submission'}
                ]
            }
        ]
    }

    sample_threat_data = {
        'threats': [
            {'ip': '93.184.216.34', 'port': 22, 'risk_score': 75}
        ]
    }

    # Initialize and run visualizer
    visualizer = AttackSurfaceVisualizer()
    visualizer.build_graph(sample_asset_data, sample_scan_data, sample_threat_data)
    output_path = visualizer.create_visualization('example.com')

    print(f"\n[+] Visualization created: {output_path}")

    # Display statistics
    stats = visualizer.generate_statistics()
    print(f"\n[+] Graph Statistics:")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
