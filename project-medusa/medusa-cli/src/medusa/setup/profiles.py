"""
Profile Management
Manages configuration profiles for different use cases
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
import yaml
from rich.console import Console


console = Console()


class ProfileManager:
    """Manages MEDUSA configuration profiles"""

    def __init__(self, profiles_dir: Optional[Path] = None):
        self.profiles_dir = profiles_dir or Path.home() / ".medusa" / "profiles"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)

        # Built-in profiles
        self.builtin_profiles = {
            "stealth": self._get_stealth_profile(),
            "aggressive": self._get_aggressive_profile(),
            "safe": self._get_safe_profile(),
            "comprehensive": self._get_comprehensive_profile(),
            "quick": self._get_quick_profile(),
        }

    def load_profile(self, name: str) -> Dict[str, Any]:
        """
        Load a profile by name

        Args:
            name: Profile name

        Returns:
            Profile configuration dictionary
        """
        # Check built-in profiles first
        if name in self.builtin_profiles:
            return self.builtin_profiles[name].copy()

        # Check custom profiles
        profile_path = self.profiles_dir / f"{name}.yaml"
        if profile_path.exists():
            with open(profile_path) as f:
                return yaml.safe_load(f)

        raise ValueError(f"Profile not found: {name}")

    def save_profile(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Save a custom profile

        Args:
            name: Profile name
            config: Configuration dictionary

        Returns:
            True if saved successfully
        """
        try:
            profile_path = self.profiles_dir / f"{name}.yaml"

            with open(profile_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)

            console.print(f"[green]Profile saved: {name}[/green]")
            return True

        except Exception as e:
            console.print(f"[red]Failed to save profile: {e}[/red]")
            return False

    def list_profiles(self) -> List[Dict[str, str]]:
        """
        List all available profiles

        Returns:
            List of profile dictionaries with name and description
        """
        profiles = []

        # Add built-in profiles
        for name in self.builtin_profiles:
            profile = self.builtin_profiles[name]
            profiles.append({
                "name": name,
                "description": profile.get("profile", {}).get("description", ""),
                "type": "built-in"
            })

        # Add custom profiles
        for profile_file in self.profiles_dir.glob("*.yaml"):
            if profile_file.stem not in self.builtin_profiles:
                try:
                    with open(profile_file) as f:
                        profile = yaml.safe_load(f)
                        profiles.append({
                            "name": profile_file.stem,
                            "description": profile.get("profile", {}).get("description", "Custom profile"),
                            "type": "custom"
                        })
                except Exception:
                    pass

        return profiles

    def delete_profile(self, name: str) -> bool:
        """
        Delete a custom profile

        Args:
            name: Profile name

        Returns:
            True if deleted successfully
        """
        if name in self.builtin_profiles:
            console.print("[red]Cannot delete built-in profile[/red]")
            return False

        profile_path = self.profiles_dir / f"{name}.yaml"
        if not profile_path.exists():
            console.print(f"[red]Profile not found: {name}[/red]")
            return False

        try:
            profile_path.unlink()
            console.print(f"[green]Profile deleted: {name}[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Failed to delete profile: {e}[/red]")
            return False

    def export_profile(self, name: str, output_path: Path) -> bool:
        """
        Export a profile to a file

        Args:
            name: Profile name
            output_path: Output file path

        Returns:
            True if exported successfully
        """
        try:
            profile = self.load_profile(name)

            with open(output_path, 'w') as f:
                yaml.dump(profile, f, default_flow_style=False)

            console.print(f"[green]Profile exported to {output_path}[/green]")
            return True

        except Exception as e:
            console.print(f"[red]Failed to export profile: {e}[/red]")
            return False

    def import_profile(self, name: str, input_path: Path) -> bool:
        """
        Import a profile from a file

        Args:
            name: Profile name
            input_path: Input file path

        Returns:
            True if imported successfully
        """
        try:
            with open(input_path) as f:
                config = yaml.safe_load(f)

            return self.save_profile(name, config)

        except Exception as e:
            console.print(f"[red]Failed to import profile: {e}[/red]")
            return False

    # Built-in profile definitions

    def _get_stealth_profile(self) -> Dict[str, Any]:
        """Stealth profile for low-noise scanning"""
        return {
            "profile": {
                "name": "stealth",
                "description": "Low-noise scanning for stealthy operations",
            },
            "llm": {
                "provider": "anthropic",
                "model": "claude-sonnet-4",
                "temperature": 0.3,
                "max_tokens": 4096,
            },
            "scanning": {
                "threads": 5,
                "timeout": 30,
                "rate_limit": 100,  # packets/sec
                "timing": "polite",
                "randomize": True,
            },
            "exploitation": {
                "mode": "simulation",
                "max_retries": 1,
                "require_approval": True,
            },
            "tools": {
                "enabled": ["nmap", "amass", "httpx"],
                "disabled": ["sqlmap", "masscan"],  # Too noisy
                "nmap_flags": "-sS -T2 -f",  # Stealth SYN scan, slow timing, fragmented
            },
            "output": {
                "format": "json",
                "verbosity": "warning",
            },
        }

    def _get_aggressive_profile(self) -> Dict[str, Any]:
        """Aggressive profile for fast, comprehensive scanning"""
        return {
            "profile": {
                "name": "aggressive",
                "description": "Fast, comprehensive scanning with maximum coverage",
            },
            "llm": {
                "provider": "anthropic",
                "model": "claude-sonnet-4",
                "temperature": 0.5,
                "max_tokens": 8192,
            },
            "scanning": {
                "threads": 50,
                "timeout": 10,
                "rate_limit": 10000,  # packets/sec
                "timing": "aggressive",
                "randomize": False,
            },
            "exploitation": {
                "mode": "real",
                "max_retries": 3,
                "require_approval": False,
            },
            "tools": {
                "enabled": ["nmap", "masscan", "nuclei", "sqlmap", "httpx", "ffuf"],
                "nmap_flags": "-sS -T4 -A",  # Aggressive scan
                "masscan_rate": "10000",
            },
            "output": {
                "format": "rich",
                "verbosity": "debug",
            },
        }

    def _get_safe_profile(self) -> Dict[str, Any]:
        """Safe profile with maximum safety checks"""
        return {
            "profile": {
                "name": "safe",
                "description": "Maximum safety with authorization required",
            },
            "llm": {
                "provider": "anthropic",
                "model": "claude-sonnet-4",
                "temperature": 0.2,
                "max_tokens": 4096,
            },
            "scanning": {
                "threads": 10,
                "timeout": 60,
                "rate_limit": 500,
                "timing": "normal",
            },
            "exploitation": {
                "mode": "simulation",
                "max_retries": 0,
                "require_approval": True,
            },
            "safety": {
                "require_authorization": True,
                "auto_rollback": True,
                "authorized_scope": [],  # Must be configured
                "audit_log": str(Path.home() / ".medusa" / "audit.log"),
                "emergency_stop_key": "ctrl+c",
            },
            "tools": {
                "enabled": ["nmap", "httpx", "nuclei"],
                "disabled": ["sqlmap", "metasploit", "hashcat"],
            },
            "output": {
                "format": "rich",
                "verbosity": "info",
            },
        }

    def _get_comprehensive_profile(self) -> Dict[str, Any]:
        """Comprehensive profile for thorough assessment"""
        return {
            "profile": {
                "name": "comprehensive",
                "description": "Thorough assessment with all tools enabled",
            },
            "llm": {
                "provider": "anthropic",
                "model": "claude-sonnet-4",
                "temperature": 0.4,
                "max_tokens": 8192,
            },
            "scanning": {
                "threads": 20,
                "timeout": 120,
                "rate_limit": 1000,
                "timing": "normal",
            },
            "exploitation": {
                "mode": "real",
                "max_retries": 2,
                "require_approval": True,
            },
            "tools": {
                "enabled": [
                    "nmap", "masscan", "amass", "httpx",
                    "nuclei", "nikto", "wpscan", "ffuf", "gobuster",
                    "sqlmap", "metasploit",
                    "hydra", "hashcat", "john",
                ],
            },
            "phases": {
                "reconnaissance": True,
                "vulnerability_analysis": True,
                "exploitation": True,
                "post_exploitation": True,
                "reporting": True,
            },
            "output": {
                "format": "rich",
                "verbosity": "info",
            },
        }

    def _get_quick_profile(self) -> Dict[str, Any]:
        """Quick profile for fast initial scan"""
        return {
            "profile": {
                "name": "quick",
                "description": "Fast initial scan with minimal tools",
            },
            "llm": {
                "provider": "anthropic",
                "model": "claude-3-5-haiku-20241022",  # Faster model
                "temperature": 0.3,
                "max_tokens": 2048,
            },
            "scanning": {
                "threads": 20,
                "timeout": 15,
                "rate_limit": 5000,
                "timing": "aggressive",
                "top_ports": 100,  # Only scan top 100 ports
            },
            "exploitation": {
                "mode": "simulation",
                "max_retries": 0,
                "require_approval": False,
            },
            "tools": {
                "enabled": ["nmap", "httpx", "nuclei"],
                "nmap_flags": "-sS -T4 --top-ports 100",
            },
            "phases": {
                "reconnaissance": True,
                "vulnerability_analysis": True,
                "exploitation": False,  # Skip exploitation
                "post_exploitation": False,
                "reporting": True,
            },
            "output": {
                "format": "rich",
                "verbosity": "info",
            },
        }

    def create_custom_profile(self, name: str, base_profile: str = "safe") -> Dict[str, Any]:
        """
        Create a custom profile based on a base profile

        Args:
            name: New profile name
            base_profile: Base profile to copy from

        Returns:
            New profile configuration
        """
        base_config = self.load_profile(base_profile)
        base_config["profile"]["name"] = name
        base_config["profile"]["description"] = f"Custom profile based on {base_profile}"

        return base_config
