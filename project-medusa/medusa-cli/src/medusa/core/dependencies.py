"""
Dependency checker and validator
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple
import subprocess
import importlib
from rich.console import Console
from rich.table import Table

console = Console()

@dataclass
class Dependency:
    name: str
    type: str  # 'python', 'system', 'service'
    required: bool
    check_cmd: Optional[str] = None
    install_hint: Optional[str] = None
    installed: bool = False
    version: Optional[str] = None


class DependencyChecker:
    """Check and validate all dependencies"""

    def __init__(self):
        self.dependencies = [
            # Python packages
            Dependency(
                "typer", "python", True,
                install_hint="pip install typer[all]==0.9.0"
            ),
            Dependency(
                "rich", "python", True,
                install_hint="pip install rich==13.7.1"
            ),
            Dependency(
                "prompt_toolkit", "python", True,
                install_hint="pip install prompt_toolkit==3.0.52"
            ),
            Dependency(
                "httpx", "python", True,
                install_hint="pip install httpx==0.26.0"
            ),
            Dependency(
                "google.generativeai", "python", False,
                install_hint="pip install google-generativeai==0.3.2"
            ),

            # System tools (optional but recommended)
            Dependency(
                "nmap", "system", False,
                check_cmd="nmap --version",
                install_hint="brew install nmap  # macOS\napt install nmap  # Ubuntu"
            ),
            Dependency(
                "docker", "system", False,
                check_cmd="docker --version",
                install_hint="https://docs.docker.com/get-docker/"
            ),
            Dependency(
                "docker-compose", "system", False,
                check_cmd="docker-compose --version",
                install_hint="https://docs.docker.com/compose/install/"
            ),

            # Services (optional)
            Dependency(
                "Ollama", "service", False,
                check_cmd="curl -s http://localhost:11434/api/tags",
                install_hint="curl -fsSL https://ollama.com/install.sh | sh"
            ),
        ]

    def check_python_package(self, package_name: str) -> Tuple[bool, Optional[str]]:
        """Check if Python package is installed"""
        try:
            module = importlib.import_module(package_name)
            version = getattr(module, '__version__', 'unknown')
            return True, version
        except ImportError:
            return False, None

    def check_system_tool(self, cmd: str) -> Tuple[bool, Optional[str]]:
        """Check if system tool is available"""
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Try to extract version from output
                version = result.stdout.split('\n')[0][:50]
                return True, version
            return False, None
        except:
            return False, None

    def check_service(self, cmd: str) -> Tuple[bool, Optional[str]]:
        """Check if service is running"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0, None
        except:
            return False, None

    def check_all(self) -> bool:
        """Check all dependencies"""
        console.print("\n[cyan]Checking dependencies...[/]\n")

        all_required_ok = True

        for dep in self.dependencies:
            if dep.type == "python":
                dep.installed, dep.version = self.check_python_package(dep.name)
            elif dep.type == "system":
                if dep.check_cmd:
                    dep.installed, dep.version = self.check_system_tool(dep.check_cmd)
            elif dep.type == "service":
                if dep.check_cmd:
                    dep.installed, dep.version = self.check_service(dep.check_cmd)

            if dep.required and not dep.installed:
                all_required_ok = False

        # Display results
        self.display_results()

        return all_required_ok

    def display_results(self):
        """Display dependency check results"""
        table = Table(title="Dependency Status")
        table.add_column("Component", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Status", style="bold")
        table.add_column("Version/Info", style="dim")

        for dep in self.dependencies:
            if dep.installed:
                status = "[green]✓ Installed[/]"
                version = dep.version or "OK"
            else:
                if dep.required:
                    status = "[red]✗ Missing (Required)[/]"
                else:
                    status = "[yellow]○ Missing (Optional)[/]"
                version = ""

            req_marker = "⚠️" if dep.required else ""
            table.add_row(
                f"{req_marker} {dep.name}",
                dep.type,
                status,
                version
            )

        console.print(table)

        # Show installation hints for missing required deps
        missing_required = [d for d in self.dependencies if d.required and not d.installed]
        if missing_required:
            console.print("\n[yellow]Missing required dependencies:[/]\n")
            for dep in missing_required:
                console.print(f"  [red]✗[/] {dep.name}")
                if dep.install_hint:
                    console.print(f"    [dim]{dep.install_hint}[/]")
            console.print()

    def install_missing_required(self):
        """Attempt to install missing required dependencies"""
        missing = [d for d in self.dependencies if d.required and not d.installed and d.type == "python"]

        if not missing:
            return True

        console.print(f"\n[yellow]Found {len(missing)} missing Python packages[/]")
        console.print("Installing automatically...\n")

        try:
            packages = [d.install_hint.split()[-1] for d in missing if d.install_hint]
            subprocess.run(
                ["pip", "install", "-q"] + packages,
                check=True
            )
            console.print("[green]✓[/] Dependencies installed!")
            return True
        except subprocess.CalledProcessError:
            console.print("[red]✗[/] Failed to install dependencies")
            console.print("Please install manually:")
            for dep in missing:
                console.print(f"  {dep.install_hint}")
            return False


def check_dependencies() -> bool:
    """Main function to check dependencies"""
    checker = DependencyChecker()
    return checker.check_all()
