#!/usr/bin/env python3
"""
Tool Installation Verification Script
Checks if all required MEDUSA tools are installed and accessible
"""

import shutil
import sys
from pathlib import Path


def check_tool(tool_name: str) -> tuple[bool, str]:
    """
    Check if a tool is available in PATH
    
    Args:
        tool_name: Name of the tool binary
        
    Returns:
        Tuple of (is_available, path_or_empty)
    """
    path = shutil.which(tool_name)
    return (path is not None, path or "")


def main():
    """Main verification function"""
    tools = {
        "amass": "Subdomain enumeration",
        "httpx": "Web server validation",
        "kerbrute": "Kerberos enumeration",
        "sqlmap": "SQL injection testing",
        "nmap": "Port scanning"
    }
    
    print("=" * 70)
    print("MEDUSA Tool Installation Status")
    print("=" * 70)
    print()
    
    all_installed = True
    results = []
    
    for tool, description in tools.items():
        is_available, path = check_tool(tool)
        status = "✅ INSTALLED" if is_available else "❌ MISSING"
        results.append((tool, description, status, path))
        
        if not is_available:
            all_installed = False
    
    # Print results in formatted table
    print(f"{'Tool':<15} {'Status':<15} {'Description':<30} {'Path'}")
    print("-" * 70)
    
    for tool, description, status, path in results:
        path_display = path if path else "(not found)"
        print(f"{tool:<15} {status:<15} {description:<30} {path_display}")
    
    print()
    print("=" * 70)
    
    if all_installed:
        print("✅ All tools are installed and available!")
        return 0
    else:
        print("❌ Some tools are missing. Please install them:")
        print()
        print("Installation commands:")
        print()
        print("# Go-based tools (requires Go installed):")
        print("go install -v github.com/owasp-amass/amass/v4/...@master")
        print("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print("go install github.com/ropnop/kerbrute@latest")
        print()
        print("# Python-based tools:")
        print("pip install sqlmap  # or use system package manager")
        print()
        print("# System packages:")
        print("sudo apt install nmap  # Debian/Ubuntu")
        print("# OR")
        print("brew install nmap  # macOS")
        print()
        print("Make sure ~/go/bin is in your PATH:")
        print("export PATH=$PATH:~/go/bin")
        print("echo 'export PATH=$PATH:~/go/bin' >> ~/.zshrc  # or ~/.bashrc")
        return 1


if __name__ == "__main__":
    sys.exit(main())

