"""
Tool Auto-Detection
Automatically detects installed security tools
"""

import shutil
import subprocess
from typing import Dict, Any, Optional
import re


class ToolDetector:
    """Detects installed security tools"""

    # Tool definitions with detection commands
    TOOLS = {
        "nmap": {
            "binary": "nmap",
            "version_cmd": ["nmap", "--version"],
            "version_regex": r"Nmap version ([\d.]+)",
            "category": "network",
            "required": True,
        },
        "masscan": {
            "binary": "masscan",
            "version_cmd": ["masscan", "--version"],
            "version_regex": r"Masscan version ([\d.]+)",
            "category": "network",
            "required": False,
        },
        "nuclei": {
            "binary": "nuclei",
            "version_cmd": ["nuclei", "-version"],
            "version_regex": r"v([\d.]+)",
            "category": "web",
            "required": False,
        },
        "httpx": {
            "binary": "httpx",
            "version_cmd": ["httpx", "-version"],
            "version_regex": r"v([\d.]+)",
            "category": "web",
            "required": False,
        },
        "amass": {
            "binary": "amass",
            "version_cmd": ["amass", "-version"],
            "version_regex": r"v([\d.]+)",
            "category": "network",
            "required": False,
        },
        "ffuf": {
            "binary": "ffuf",
            "version_cmd": ["ffuf", "-V"],
            "version_regex": r"v([\d.]+)",
            "category": "web",
            "required": False,
        },
        "gobuster": {
            "binary": "gobuster",
            "version_cmd": ["gobuster", "version"],
            "version_regex": r"v([\d.]+)",
            "category": "web",
            "required": False,
        },
        "sqlmap": {
            "binary": "sqlmap",
            "version_cmd": ["sqlmap", "--version"],
            "version_regex": r"([\d.]+)",
            "category": "web",
            "required": False,
        },
        "metasploit": {
            "binary": "msfconsole",
            "version_cmd": ["msfconsole", "--version"],
            "version_regex": r"Framework: ([\d.]+)",
            "category": "exploitation",
            "required": False,
        },
        "nikto": {
            "binary": "nikto",
            "version_cmd": ["nikto", "-Version"],
            "version_regex": r"([\d.]+)",
            "category": "web",
            "required": False,
        },
        "wpscan": {
            "binary": "wpscan",
            "version_cmd": ["wpscan", "--version"],
            "version_regex": r"v([\d.]+)",
            "category": "web",
            "required": False,
        },
        "wafw00f": {
            "binary": "wafw00f",
            "version_cmd": ["wafw00f", "-v"],
            "version_regex": r"v([\d.]+)",
            "category": "web",
            "required": False,
        },
        "whatweb": {
            "binary": "whatweb",
            "version_cmd": ["whatweb", "--version"],
            "version_regex": r"v([\d.]+)",
            "category": "web",
            "required": False,
        },
        "hydra": {
            "binary": "hydra",
            "version_cmd": ["hydra", "-V"],
            "version_regex": r"v([\d.]+)",
            "category": "credentials",
            "required": False,
        },
        "hashcat": {
            "binary": "hashcat",
            "version_cmd": ["hashcat", "--version"],
            "version_regex": r"v([\d.]+)",
            "category": "credentials",
            "required": False,
        },
        "john": {
            "binary": "john",
            "version_cmd": ["john", "--version"],
            "version_regex": r"([\d.]+)",
            "category": "credentials",
            "required": False,
        },
        "responder": {
            "binary": "responder",
            "version_cmd": ["responder", "--version"],
            "version_regex": r"([\d.]+)",
            "category": "network",
            "required": False,
        },
        "crackmapexec": {
            "binary": "crackmapexec",
            "version_cmd": ["crackmapexec", "--version"],
            "version_regex": r"v([\d.]+)",
            "category": "network",
            "required": False,
        },
        "enum4linux": {
            "binary": "enum4linux",
            "version_cmd": ["enum4linux"],
            "version_regex": r"v([\d.]+)",
            "category": "network",
            "required": False,
        },
        "netcat": {
            "binary": "nc",
            "version_cmd": ["nc", "-h"],
            "version_regex": None,  # Just check existence
            "category": "network",
            "required": False,
        },
        "bloodhound": {
            "binary": "bloodhound-python",
            "version_cmd": ["bloodhound-python", "--version"],
            "version_regex": r"([\d.]+)",
            "category": "network",
            "required": False,
        },
    }

    def detect_tool(self, tool_name: str) -> Dict[str, Any]:
        """
        Detect if a specific tool is installed

        Args:
            tool_name: Name of the tool

        Returns:
            Dictionary with detection results
        """
        if tool_name not in self.TOOLS:
            return {
                "installed": False,
                "error": f"Unknown tool: {tool_name}"
            }

        tool_info = self.TOOLS[tool_name]
        binary = tool_info["binary"]

        # Check if binary exists in PATH
        if not shutil.which(binary):
            return {
                "installed": False,
                "binary": binary,
                "category": tool_info["category"],
                "required": tool_info["required"],
            }

        # Try to get version
        version = self._get_version(tool_info)

        return {
            "installed": True,
            "binary": binary,
            "version": version,
            "category": tool_info["category"],
            "required": tool_info["required"],
        }

    def detect_all(self) -> Dict[str, Dict[str, Any]]:
        """
        Detect all tools

        Returns:
            Dictionary mapping tool names to detection results
        """
        results = {}
        for tool_name in self.TOOLS:
            results[tool_name] = self.detect_tool(tool_name)

        return results

    def detect_by_category(self, category: str) -> Dict[str, Dict[str, Any]]:
        """
        Detect tools in a specific category

        Args:
            category: Tool category (network, web, exploitation, credentials)

        Returns:
            Dictionary mapping tool names to detection results
        """
        results = {}
        for tool_name, tool_info in self.TOOLS.items():
            if tool_info["category"] == category:
                results[tool_name] = self.detect_tool(tool_name)

        return results

    def get_missing_required(self) -> list:
        """
        Get list of missing required tools

        Returns:
            List of tool names
        """
        missing = []
        for tool_name, tool_info in self.TOOLS.items():
            if tool_info["required"]:
                result = self.detect_tool(tool_name)
                if not result["installed"]:
                    missing.append(tool_name)

        return missing

    def get_installation_summary(self) -> Dict[str, Any]:
        """
        Get summary of tool installation status

        Returns:
            Summary dictionary
        """
        all_tools = self.detect_all()

        installed = [name for name, info in all_tools.items() if info["installed"]]
        missing = [name for name, info in all_tools.items() if not info["installed"]]

        by_category = {}
        for category in ["network", "web", "exploitation", "credentials"]:
            category_tools = self.detect_by_category(category)
            by_category[category] = {
                "total": len(category_tools),
                "installed": len([t for t in category_tools.values() if t["installed"]]),
                "missing": len([t for t in category_tools.values() if not t["installed"]]),
            }

        return {
            "total": len(self.TOOLS),
            "installed": len(installed),
            "missing": len(missing),
            "installed_tools": installed,
            "missing_tools": missing,
            "by_category": by_category,
        }

    def _get_version(self, tool_info: Dict[str, Any]) -> Optional[str]:
        """Get version of a tool"""
        try:
            result = subprocess.run(
                tool_info["version_cmd"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            output = result.stdout + result.stderr

            if tool_info["version_regex"]:
                match = re.search(tool_info["version_regex"], output)
                if match:
                    return match.group(1)

            return "installed"

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        except Exception:
            return "installed"

    def check_dependencies(self) -> Dict[str, Any]:
        """
        Check system dependencies (Python libraries, system tools)

        Returns:
            Dictionary with dependency status
        """
        dependencies = {}

        # Check Python libraries
        python_libs = [
            "anthropic",
            "openai",
            "boto3",
            "neo4j",
            "chromadb",
            "rich",
            "textual",
            "click",
            "pyyaml",
            "questionary",
        ]

        for lib in python_libs:
            try:
                __import__(lib)
                dependencies[lib] = {"installed": True, "type": "python"}
            except ImportError:
                dependencies[lib] = {"installed": False, "type": "python"}

        # Check system tools
        system_tools = ["git", "docker", "docker-compose"]

        for tool in system_tools:
            if shutil.which(tool):
                dependencies[tool] = {"installed": True, "type": "system"}
            else:
                dependencies[tool] = {"installed": False, "type": "system"}

        return dependencies

    def suggest_installation(self, tool_name: str) -> str:
        """
        Get installation suggestion for a tool

        Args:
            tool_name: Name of the tool

        Returns:
            Installation command suggestion
        """
        suggestions = {
            "nmap": {
                "linux": "sudo apt install nmap",
                "macos": "brew install nmap",
                "windows": "Download from https://nmap.org/download.html",
            },
            "masscan": {
                "linux": "sudo apt install masscan",
                "macos": "brew install masscan",
                "windows": "Build from source: https://github.com/robertdavidgraham/masscan",
            },
            "nuclei": {
                "all": "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            },
            "httpx": {
                "all": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            },
            "amass": {
                "all": "go install -v github.com/owasp-amass/amass/v4/...@master",
            },
            "ffuf": {
                "all": "go install github.com/ffuf/ffuf/v2@latest",
            },
            "gobuster": {
                "all": "go install github.com/OJ/gobuster/v3@latest",
            },
            "sqlmap": {
                "linux": "sudo apt install sqlmap",
                "macos": "brew install sqlmap",
                "windows": "pip install sqlmap",
            },
            "metasploit": {
                "linux": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
                "macos": "brew install metasploit",
                "windows": "Download from https://www.metasploit.com/download",
            },
            "nikto": {
                "linux": "sudo apt install nikto",
                "macos": "brew install nikto",
                "windows": "Download from https://github.com/sullo/nikto",
            },
            "wpscan": {
                "all": "gem install wpscan",
            },
            "hydra": {
                "linux": "sudo apt install hydra",
                "macos": "brew install hydra",
                "windows": "Download from https://github.com/vanhauser-thc/thc-hydra",
            },
            "hashcat": {
                "linux": "sudo apt install hashcat",
                "macos": "brew install hashcat",
                "windows": "Download from https://hashcat.net/hashcat/",
            },
            "john": {
                "linux": "sudo apt install john",
                "macos": "brew install john",
                "windows": "Download from https://www.openwall.com/john/",
            },
            "crackmapexec": {
                "all": "pipx install crackmapexec",
            },
            "bloodhound": {
                "all": "pip install bloodhound",
            },
        }

        if tool_name in suggestions:
            return suggestions[tool_name].get("all", suggestions[tool_name])

        return f"No installation suggestion available for {tool_name}"
