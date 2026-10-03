#!/usr/bin/env python3
"""
CVE Database indexing
Indexes common CVEs for vulnerability search
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from medusa.context.vector_store import VectorStore


def get_common_cves():
    """Get curated list of common high-impact CVEs"""
    return [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 Remote Code Execution (Log4Shell) - JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints",
            "severity": "critical",
            "cvss": 10.0,
            "affected_software": ["Apache Log4j", "Java Applications", "Web Servers"]
        },
        {
            "cve_id": "CVE-2023-23397",
            "description": "Microsoft Outlook Elevation of Privilege - allows attackers to access a user's Net-NTLMv2 hash and use it for authentication",
            "severity": "critical",
            "cvss": 9.8,
            "affected_software": ["Microsoft Outlook", "Exchange Server"]
        },
        {
            "cve_id": "CVE-2023-27997",
            "description": "Fortinet FortiOS Heap Buffer Overflow - pre-authentication remote code execution via specially crafted requests",
            "severity": "critical",
            "cvss": 9.8,
            "affected_software": ["Fortinet FortiOS", "Fortinet FortiProxy"]
        },
        {
            "cve_id": "CVE-2022-22965",
            "description": "Spring4Shell - Spring Framework RCE via Data Binding on JDK 9+",
            "severity": "critical",
            "cvss": 9.8,
            "affected_software": ["Spring Framework", "Java Applications"]
        },
        {
            "cve_id": "CVE-2021-34527",
            "description": "PrintNightmare - Windows Print Spooler Remote Code Execution",
            "severity": "critical",
            "cvss": 8.8,
            "affected_software": ["Windows Server", "Windows 10", "Windows 11"]
        },
        {
            "cve_id": "CVE-2023-22515",
            "description": "Atlassian Confluence Data Center and Server - Broken Access Control allowing unauthorized creation of administrator accounts",
            "severity": "critical",
            "cvss": 10.0,
            "affected_software": ["Atlassian Confluence"]
        },
        {
            "cve_id": "CVE-2023-46604",
            "description": "Apache ActiveMQ RCE - allows remote code execution through specially crafted serialized objects",
            "severity": "critical",
            "cvss": 10.0,
            "affected_software": ["Apache ActiveMQ"]
        },
        {
            "cve_id": "CVE-2022-26134",
            "description": "Atlassian Confluence OGNL Injection RCE - unauthenticated remote code execution",
            "severity": "critical",
            "cvss": 9.8,
            "affected_software": ["Atlassian Confluence Server", "Atlassian Confluence Data Center"]
        },
        {
            "cve_id": "CVE-2023-34362",
            "description": "MOVEit Transfer SQL Injection leading to Remote Code Execution",
            "severity": "critical",
            "cvss": 9.8,
            "affected_software": ["Progress MOVEit Transfer"]
        },
        {
            "cve_id": "CVE-2023-20198",
            "description": "Cisco IOS XE Web UI Privilege Escalation - allows unauthenticated remote attacker to create account with privilege level 15 access",
            "severity": "critical",
            "cvss": 10.0,
            "affected_software": ["Cisco IOS XE"]
        },
        {
            "cve_id": "CVE-2019-0708",
            "description": "BlueKeep - Windows Remote Desktop Services RCE, wormable vulnerability",
            "severity": "critical",
            "cvss": 9.8,
            "affected_software": ["Windows Server 2008", "Windows Server 2003", "Windows XP"]
        },
        {
            "cve_id": "CVE-2017-0144",
            "description": "EternalBlue - Windows SMBv1 RCE used by WannaCry ransomware",
            "severity": "critical",
            "cvss": 9.3,
            "affected_software": ["Windows Server 2003-2016", "Windows Vista-10"]
        },
        {
            "cve_id": "CVE-2014-0160",
            "description": "Heartbleed - OpenSSL TLS Heartbeat Extension buffer over-read allowing memory disclosure",
            "severity": "high",
            "cvss": 7.5,
            "affected_software": ["OpenSSL", "Web Servers", "VPN Services"]
        },
        {
            "cve_id": "CVE-2021-3156",
            "description": "Baron Samedit - Sudo Heap-Based Buffer Overflow",
            "severity": "high",
            "cvss": 7.8,
            "affected_software": ["Linux Sudo"]
        },
        {
            "cve_id": "CVE-2022-0847",
            "description": "Dirty Pipe - Linux kernel local privilege escalation",
            "severity": "high",
            "cvss": 7.8,
            "affected_software": ["Linux Kernel 5.8+"]
        },
        {
            "cve_id": "CVE-2023-4911",
            "description": "Looney Tunables - glibc buffer overflow in dynamic loader's GLIBC_TUNABLES environment variable",
            "severity": "high",
            "cvss": 7.8,
            "affected_software": ["GNU C Library (glibc)", "Linux Systems"]
        },
        {
            "cve_id": "CVE-2022-31692",
            "description": "Spring Cloud Function SpEL Injection RCE",
            "severity": "high",
            "cvss": 8.1,
            "affected_software": ["Spring Cloud Function"]
        },
        {
            "cve_id": "CVE-2023-28252",
            "description": "Windows Common Log File System Driver Elevation of Privilege",
            "severity": "high",
            "cvss": 7.8,
            "affected_software": ["Windows 10", "Windows 11", "Windows Server"]
        },
        {
            "cve_id": "CVE-2020-1472",
            "description": "Zerologon - Netlogon Elevation of Privilege allowing DC compromise",
            "severity": "critical",
            "cvss": 10.0,
            "affected_software": ["Windows Server", "Active Directory"]
        },
        {
            "cve_id": "CVE-2022-40684",
            "description": "FortiOS Authentication Bypass - allows unauthorized access via crafted HTTP requests",
            "severity": "critical",
            "cvss": 9.3,
            "affected_software": ["Fortinet FortiOS", "FortiProxy"]
        }
    ]


def main():
    print("="*70)
    print("MEDUSA - CVE Database Indexer")
    print("="*70)

    # Get CVE data
    cves = get_common_cves()
    print(f"\n✓ Collected {len(cves)} high-impact CVEs")

    # Initialize vector store
    print("\nInitializing vector store...")
    vector_store = VectorStore()
    print(f"✓ Vector store initialized")

    # Index CVEs
    print(f"\nIndexing {len(cves)} CVEs...")
    vector_store.index_cves(cves)
    print(f"✓ Indexed CVE database")

    # Get stats
    stats = vector_store.get_stats()
    print("\n" + "="*70)
    print("Vector Store Statistics:")
    print("="*70)
    for collection, count in stats['collections'].items():
        print(f"  • {collection:30s} {count:>5} documents")

    # Severity breakdown
    critical = [c for c in cves if c['severity'] == 'critical']
    high = [c for c in cves if c['severity'] == 'high']
    print("\nSeverity Breakdown:")
    print(f"  • Critical: {len(critical)}")
    print(f"  • High: {len(high)}")

    # Test search
    print("\n" + "="*70)
    print("Testing CVE Search:")
    print("="*70)

    test_queries = [
        "Windows remote code execution",
        "Apache vulnerability",
        "privilege escalation Linux"
    ]

    for query in test_queries:
        print(f"\nQuery: '{query}'")
        results = vector_store.search_cves(query, n_results=3)
        for i, result in enumerate(results, 1):
            print(f"  {i}. {result['cve_id']} ({result['severity']}, CVSS: {result['cvss']})")
            print(f"     Relevance: {result['relevance_score']:.3f}")

    print("\n" + "="*70)
    print("✅ CVE database indexing completed!")
    print("="*70)


if __name__ == "__main__":
    main()
