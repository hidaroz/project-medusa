"""
MEDUSA World Model - Example Usage
Demonstrates how to use the WorldModelClient to interact with Neo4j
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "medusa-cli", "src"))

from medusa.world_model import (
    WorldModelClient,
    Domain,
    Subdomain,
    Host,
    Port,
    WebServer,
    Vulnerability,
)


def main():
    """Example usage of the World Model client"""

    print("=" * 80)
    print("MEDUSA World Model - Example Usage")
    print("=" * 80)

    # Initialize client
    print("\n[1] Connecting to Neo4j...")
    try:
        client = WorldModelClient()
        print("✓ Connected successfully")
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        print("\nMake sure Neo4j is running:")
        print("  docker-compose up -d medusa-neo4j")
        return

    try:
        # Create domain
        print("\n[2] Creating domain...")
        domain = Domain(name="example.com", scan_status="in_progress")
        client.create_domain(domain)
        print(f"✓ Created domain: {domain.name}")

        # Create subdomain
        print("\n[3] Creating subdomain...")
        subdomain = Subdomain(name="www.example.com")
        client.create_subdomain(subdomain, parent_domain="example.com")
        print(f"✓ Created subdomain: {subdomain.name}")

        # Create host
        print("\n[4] Creating host...")
        host = Host(
            ip="192.168.1.100",
            hostname="web-server-01",
            os_name="Linux",
            os_accuracy=95,
        )
        client.create_host(host)
        print(f"✓ Created host: {host.ip} ({host.hostname})")

        # Link subdomain to host
        print("\n[5] Linking subdomain to host...")
        client.link_subdomain_to_host("www.example.com", "192.168.1.100")
        print("✓ Created RESOLVES_TO relationship")

        # Create port
        print("\n[6] Creating port...")
        port = Port(
            number=80,
            protocol="tcp",
            state="open",
            service="http",
            product="nginx",
            version="1.18.0",
            host_id="192.168.1.100",
        )
        client.create_port(port, host_ip="192.168.1.100")
        print(f"✓ Created port: {port.number}/{port.protocol} ({port.service})")

        # Create web server
        print("\n[7] Creating web server...")
        webserver = WebServer(
            url="http://www.example.com",
            status_code=200,
            title="Example Website",
            web_server="nginx/1.18.0",
            technologies=["PHP", "MySQL", "WordPress"],
            ssl=False,
        )
        client.create_webserver(webserver, host_ip="192.168.1.100")
        print(f"✓ Created web server: {webserver.url}")

        # Create vulnerability
        print("\n[8] Creating vulnerability...")
        vuln = Vulnerability(
            id="vuln_example_001",
            type="SQL Injection",
            parameter="id",
            location="http://www.example.com/search.php?id=1",
            severity="high",
            exploited=False,
        )
        client.create_vulnerability(vuln, target_url="http://www.example.com")
        print(f"✓ Created vulnerability: {vuln.type} ({vuln.severity})")

        # Query data
        print("\n[9] Querying data...")
        print("\nAll hosts:")
        hosts = client.get_all_hosts(limit=10)
        for h in hosts:
            print(f"  - {h.get('ip')} ({h.get('hostname')})")

        print("\nVulnerabilities (high severity):")
        vulns = client.get_vulnerabilities(severity="high")
        for v in vulns:
            print(f"  - {v.get('type')} at {v.get('location')}")

        # Get attack surface
        print("\n[10] Getting attack surface for example.com...")
        attack_surface = client.get_attack_surface("example.com")
        print(f"✓ Domain: {attack_surface.get('d', {}).get('name')}")
        print(f"  - Subdomains: {len(attack_surface.get('subdomains', []))}")
        print(f"  - Hosts: {len(attack_surface.get('hosts', []))}")
        print(f"  - Ports: {len(attack_surface.get('ports', []))}")
        print(f"  - Web Servers: {len(attack_surface.get('webservers', []))}")
        print(f"  - Vulnerabilities: {len(attack_surface.get('vulnerabilities', []))}")

        # Get statistics
        print("\n[11] Getting graph statistics...")
        stats = client.get_graph_statistics()
        print("Node counts:")
        for label, count in stats.items():
            if label != "relationships":
                print(f"  - {label}: {count}")

        print("\nRelationship counts:")
        for rel_type, count in stats.get("relationships", {}).items():
            print(f"  - {rel_type}: {count}")

    finally:
        # Close connection
        print("\n[12] Closing connection...")
        client.close()
        print("✓ Connection closed")

    print("\n" + "=" * 80)
    print("Example completed successfully!")
    print("=" * 80)
    print("\nNext steps:")
    print("  1. View the graph in Neo4j Browser: http://localhost:7474")
    print("  2. Try running sample queries from the README")
    print("  3. Integrate World Model into MEDUSA CLI tools")
    print("=" * 80)


if __name__ == "__main__":
    main()
