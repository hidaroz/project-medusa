#!/usr/bin/env python3
"""
Index MITRE ATT&CK framework into vector database
Downloads latest MITRE data and indexes for semantic search
"""

import requests
import sys
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from medusa.context.vector_store import VectorStore


def download_mitre_attack() -> list:
    """Download MITRE ATT&CK Enterprise matrix"""
    print("Downloading MITRE ATT&CK framework...")
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        print(f"Error downloading MITRE ATT&CK: {e}")
        print("Using cached/sample data...")
        return get_sample_techniques()

    techniques = []
    for obj in data["objects"]:
        if obj["type"] == "attack-pattern":
            # Extract technique information
            technique = {
                "id": obj["external_references"][0]["external_id"],
                "name": obj["name"],
                "description": obj.get("description", ""),
                "tactics": [
                    phase["phase_name"]
                    for phase in obj.get("kill_chain_phases", [])
                ],
                "platforms": obj.get("x_mitre_platforms", [])
            }
            techniques.append(technique)

    return techniques


def get_sample_techniques() -> list:
    """Get sample MITRE techniques for offline operation"""
    return [
        {
            "id": "T1046",
            "name": "Network Service Discovery",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation.",
            "tactics": ["discovery"],
            "platforms": ["Windows", "Linux", "macOS"]
        },
        {
            "id": "T1595",
            "name": "Active Scanning",
            "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
            "tactics": ["reconnaissance"],
            "platforms": ["PRE"]
        },
        {
            "id": "T1590",
            "name": "Gather Victim Network Information",
            "description": "Adversaries may gather information about the victim's networks that can be used during targeting.",
            "tactics": ["reconnaissance"],
            "platforms": ["PRE"]
        },
        {
            "id": "T1078",
            "name": "Valid Accounts",
            "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
            "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
            "platforms": ["Windows", "Linux", "macOS", "SaaS", "IaaS", "Azure AD", "Office 365", "Google Workspace", "Containers"]
        },
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
            "tactics": ["initial-access"],
            "platforms": ["Windows", "Linux", "macOS", "Containers"]
        },
        {
            "id": "T1071",
            "name": "Application Layer Protocol",
            "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
            "tactics": ["command-and-control"],
            "platforms": ["Windows", "Linux", "macOS"]
        },
        {
            "id": "T1021",
            "name": "Remote Services",
            "description": "Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as telnet, SSH, and VNC.",
            "tactics": ["lateral-movement"],
            "platforms": ["Windows", "Linux", "macOS"]
        },
        {
            "id": "T1003",
            "name": "OS Credential Dumping",
            "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
            "tactics": ["credential-access"],
            "platforms": ["Windows", "Linux", "macOS"]
        },
        {
            "id": "T1566",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages to gain access to victim systems.",
            "tactics": ["initial-access"],
            "platforms": ["Linux", "macOS", "Windows", "SaaS", "Office 365", "Google Workspace"]
        },
        {
            "id": "T1218",
            "name": "System Binary Proxy Execution",
            "description": "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries.",
            "tactics": ["defense-evasion"],
            "platforms": ["Windows"]
        }
    ]


def main():
    print("="*70)
    print("MEDUSA - MITRE ATT&CK Indexer")
    print("="*70)

    # Download techniques
    techniques = download_mitre_attack()
    print(f"✓ Downloaded {len(techniques)} techniques")

    # Initialize vector store
    print("\nInitializing vector store...")
    vector_store = VectorStore()
    print(f"✓ Vector store initialized at {vector_store.persist_dir}")

    # Index techniques
    print("\nIndexing MITRE ATT&CK techniques...")
    vector_store.index_mitre_attack(techniques)
    print(f"✓ Indexed {len(techniques)} techniques")

    # Get stats
    stats = vector_store.get_stats()
    print("\n" + "="*70)
    print("Vector Store Statistics:")
    print("="*70)
    print(f"Persist Directory: {stats['persist_directory']}")
    print(f"Total Documents: {stats['total_documents']}")
    print("\nCollections:")
    for collection, count in stats['collections'].items():
        print(f"  • {collection:30s} {count:>5} documents")

    # Test search
    print("\n" + "="*70)
    print("Testing Semantic Search:")
    print("="*70)

    test_queries = [
        "lateral movement using credentials",
        "network scanning and reconnaissance",
        "credential dumping and extraction"
    ]

    for query in test_queries:
        print(f"\nQuery: '{query}'")
        results = vector_store.search_mitre_techniques(query, n_results=3)
        for i, result in enumerate(results, 1):
            print(f"  {i}. {result['technique_id']} - {result['technique_name']}")
            print(f"     Relevance: {result['relevance_score']:.3f}")

    print("\n" + "="*70)
    print("✅ MITRE ATT&CK indexing completed successfully!")
    print("="*70)


if __name__ == "__main__":
    main()
