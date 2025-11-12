#!/usr/bin/env python3
"""
Extract and index tool documentation
Creates searchable index of common security tools
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from medusa.context.vector_store import VectorStore


def get_nmap_docs():
    """Get Nmap command documentation"""
    return [
        {
            "tool": "nmap",
            "command": "nmap -sV -p- <target>",
            "description": "Service version detection scan on all 65535 ports",
            "category": "reconnaissance",
            "examples": "nmap -sV -p- 192.168.1.1"
        },
        {
            "tool": "nmap",
            "command": "nmap -sC -sV <target>",
            "description": "Default NSE script scan with version detection",
            "category": "reconnaissance",
            "examples": "nmap -sC -sV scanme.nmap.org"
        },
        {
            "tool": "nmap",
            "command": "nmap -sS -T4 <target>",
            "description": "Fast SYN stealth scan",
            "category": "reconnaissance",
            "examples": "nmap -sS -T4 192.168.1.0/24"
        },
        {
            "tool": "nmap",
            "command": "nmap -A <target>",
            "description": "Aggressive scan with OS detection, version detection, script scanning, and traceroute",
            "category": "reconnaissance",
            "examples": "nmap -A 192.168.1.1"
        },
        {
            "tool": "nmap",
            "command": "nmap -Pn <target>",
            "description": "Skip host discovery, treat all hosts as online",
            "category": "reconnaissance",
            "examples": "nmap -Pn 192.168.1.1"
        }
    ]


def get_sqlmap_docs():
    """Get SQLMap documentation"""
    return [
        {
            "tool": "sqlmap",
            "command": "sqlmap -u '<url>' --batch",
            "description": "Basic SQL injection test with automatic answers",
            "category": "vulnerability_analysis",
            "examples": "sqlmap -u 'http://example.com/page.php?id=1' --batch"
        },
        {
            "tool": "sqlmap",
            "command": "sqlmap -u '<url>' --dbs",
            "description": "Enumerate databases",
            "category": "exploitation",
            "examples": "sqlmap -u 'http://example.com/page.php?id=1' --dbs"
        },
        {
            "tool": "sqlmap",
            "command": "sqlmap -u '<url>' -D <db> --tables",
            "description": "Enumerate tables in specific database",
            "category": "exploitation",
            "examples": "sqlmap -u 'http://example.com/page.php?id=1' -D testdb --tables"
        },
        {
            "tool": "sqlmap",
            "command": "sqlmap -u '<url>' -D <db> -T <table> --dump",
            "description": "Dump table contents",
            "category": "exfiltration",
            "examples": "sqlmap -u 'http://example.com/page.php?id=1' -D testdb -T users --dump"
        },
        {
            "tool": "sqlmap",
            "command": "sqlmap -u '<url>' --level=5 --risk=3",
            "description": "Aggressive SQL injection testing with high risk/level",
            "category": "vulnerability_analysis",
            "examples": "sqlmap -u 'http://example.com/page.php?id=1' --level=5 --risk=3"
        }
    ]


def get_nikto_docs():
    """Get Nikto documentation"""
    return [
        {
            "tool": "nikto",
            "command": "nikto -h <host>",
            "description": "Basic web server vulnerability scan",
            "category": "vulnerability_analysis",
            "examples": "nikto -h http://example.com"
        },
        {
            "tool": "nikto",
            "command": "nikto -h <host> -Tuning x",
            "description": "Scan for specific vulnerability types (x=1-9)",
            "category": "vulnerability_analysis",
            "examples": "nikto -h http://example.com -Tuning 4"
        }
    ]


def get_amass_docs():
    """Get Amass documentation"""
    return [
        {
            "tool": "amass",
            "command": "amass enum -passive -d <domain>",
            "description": "Passive subdomain enumeration",
            "category": "reconnaissance",
            "examples": "amass enum -passive -d example.com"
        },
        {
            "tool": "amass",
            "command": "amass enum -active -d <domain>",
            "description": "Active subdomain enumeration with DNS resolution",
            "category": "reconnaissance",
            "examples": "amass enum -active -d example.com"
        }
    ]


def get_hydra_docs():
    """Get Hydra documentation"""
    return [
        {
            "tool": "hydra",
            "command": "hydra -l <user> -P <wordlist> <target> <service>",
            "description": "Brute force authentication",
            "category": "credential_access",
            "examples": "hydra -l admin -P rockyou.txt 192.168.1.1 ssh"
        },
        {
            "tool": "hydra",
            "command": "hydra -L <users> -P <wordlist> <target> http-post-form '<path>:<params>:<fail_string>'",
            "description": "HTTP POST form brute force",
            "category": "credential_access",
            "examples": "hydra -L users.txt -P pass.txt example.com http-post-form '/login.php:user=^USER^&pass=^PASS^:Invalid'"
        }
    ]


def get_metasploit_docs():
    """Get Metasploit documentation"""
    return [
        {
            "tool": "metasploit",
            "command": "msfconsole -q -x 'search <term>; exit'",
            "description": "Search for exploits and modules",
            "category": "exploitation",
            "examples": "msfconsole -q -x 'search apache; exit'"
        },
        {
            "tool": "metasploit",
            "command": "msfconsole -q -x 'use <exploit>; set RHOSTS <target>; exploit'",
            "description": "Run exploit against target",
            "category": "exploitation",
            "examples": "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; exploit'"
        }
    ]


def main():
    print("="*70)
    print("MEDUSA - Tool Documentation Indexer")
    print("="*70)

    # Collect all tool documentation
    all_docs = []
    all_docs.extend(get_nmap_docs())
    all_docs.extend(get_sqlmap_docs())
    all_docs.extend(get_nikto_docs())
    all_docs.extend(get_amass_docs())
    all_docs.extend(get_hydra_docs())
    all_docs.extend(get_metasploit_docs())

    print(f"\n✓ Collected {len(all_docs)} tool documentation entries")

    # Initialize vector store
    print("\nInitializing vector store...")
    vector_store = VectorStore()
    print(f"✓ Vector store initialized")

    # Index tool documentation
    print(f"\nIndexing {len(all_docs)} tool documentation entries...")
    vector_store.index_tool_documentation(all_docs)
    print(f"✓ Indexed tool documentation")

    # Get stats
    stats = vector_store.get_stats()
    print("\n" + "="*70)
    print("Vector Store Statistics:")
    print("="*70)
    for collection, count in stats['collections'].items():
        print(f"  • {collection:30s} {count:>5} documents")

    # Test search
    print("\n" + "="*70)
    print("Testing Tool Search:")
    print("="*70)

    test_queries = [
        "scan for open ports and services",
        "test for SQL injection vulnerabilities",
        "brute force SSH credentials"
    ]

    for query in test_queries:
        print(f"\nQuery: '{query}'")
        results = vector_store.search_tool_usage(query, n_results=2)
        for i, result in enumerate(results, 1):
            print(f"  {i}. {result['tool']}: {result['command']}")
            print(f"     Relevance: {result['relevance_score']:.3f}")

    print("\n" + "="*70)
    print("✅ Tool documentation indexing completed!")
    print("="*70)


if __name__ == "__main__":
    main()
