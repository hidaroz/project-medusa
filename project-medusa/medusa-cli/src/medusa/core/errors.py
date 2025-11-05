"""
Smart error handling with helpful messages
"""
from typing import Optional, List
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()


class MEDUSAError(Exception):
    """Base exception with helpful error messages"""

    def __init__(
        self,
        message: str,
        cause: Optional[Exception] = None,
        suggestions: Optional[List[str]] = None,
        documentation_link: Optional[str] = None
    ):
        self.message = message
        self.cause = cause
        self.suggestions = suggestions or []
        self.documentation_link = documentation_link
        super().__init__(message)

    def display(self):
        """Display rich formatted error message"""
        content = f"## ❌ Error\n\n{self.message}\n\n"

        if self.cause:
            content += f"**Caused by:** `{str(self.cause)}`\n\n"

        if self.suggestions:
            content += "### 💡 Suggestions\n\n"
            for suggestion in self.suggestions:
                content += f"- {suggestion}\n"
            content += "\n"

        if self.documentation_link:
            content += f"📚 [See documentation]({self.documentation_link})\n"

        console.print(Panel(Markdown(content), border_style="red", title="MEDUSA Error"))


class ConfigurationError(MEDUSAError):
    """Configuration-related errors"""

    @classmethod
    def missing_api_key(cls):
        return cls(
            message="API key not found in configuration",
            suggestions=[
                "Run `medusa setup` to configure your API key",
                "Set environment variable: `export GEMINI_API_KEY=your_key`",
                "Get a free API key at https://aistudio.google.com/app/apikey",
                "Or use local Ollama: https://ollama.com"
            ],
            documentation_link="https://github.com/your-org/medusa/docs/setup.md"
        )

    @classmethod
    def invalid_config_file(cls, error: Exception):
        return cls(
            message="Configuration file is invalid or corrupted",
            cause=error,
            suggestions=[
                "Run `medusa setup` to recreate your configuration",
                "Check YAML syntax in ~/.medusa/config.yaml",
                "Remove the file and run setup again: `rm ~/.medusa/config.yaml && medusa setup`"
            ]
        )


class DependencyError(MEDUSAError):
    """Dependency-related errors"""

    @classmethod
    def missing_package(cls, package_name: str):
        return cls(
            message=f"Required package '{package_name}' is not installed",
            suggestions=[
                f"Install the package: `pip install {package_name}`",
                "Reinstall MEDUSA: `pip install -e . --upgrade`",
                "Check your virtual environment is activated"
            ]
        )

    @classmethod
    def docker_not_running(cls):
        return cls(
            message="Docker is not running or not accessible",
            suggestions=[
                "Start Docker Desktop",
                "Check Docker daemon: `docker ps`",
                "Ensure your user has Docker permissions: `sudo usermod -aG docker $USER`",
                "Restart Docker service: `sudo systemctl restart docker`"
            ],
            documentation_link="https://docs.docker.com/config/daemon/"
        )


class LLMError(MEDUSAError):
    """LLM-related errors"""

    @classmethod
    def api_key_invalid(cls):
        return cls(
            message="API key is invalid or expired",
            suggestions=[
                "Verify your API key at https://aistudio.google.com/app/apikey",
                "Update your configuration: `medusa setup`",
                "Check for typos in ~/.medusa/config.yaml",
                "Try regenerating your API key"
            ]
        )

    @classmethod
    def rate_limit_exceeded(cls):
        return cls(
            message="API rate limit exceeded",
            suggestions=[
                "Wait a few minutes before retrying",
                "Check your quota at https://console.cloud.google.com",
                "Consider using local Ollama for unlimited requests",
                "Upgrade your API plan for higher limits"
            ]
        )

    @classmethod
    def connection_failed(cls, error: Exception):
        return cls(
            message="Failed to connect to LLM service",
            cause=error,
            suggestions=[
                "Check your internet connection",
                "Verify the API endpoint is accessible",
                "Check if firewall is blocking the connection",
                "Try using a different network",
                "Use `--mock` flag to test without API"
            ]
        )


class TargetError(MEDUSAError):
    """Target-related errors"""

    @classmethod
    def unreachable(cls, target: str):
        return cls(
            message=f"Target '{target}' is unreachable",
            suggestions=[
                f"Check if {target} is accessible: `ping {target}`",
                "Verify the URL/IP is correct",
                "Check if target has firewall rules",
                "Ensure you have network connectivity"
            ]
        )

    @classmethod
    def unauthorized(cls, target: str):
        return cls(
            message=f"Not authorized to test '{target}'",
            suggestions=[
                "Ensure you have written permission to test this target",
                "Use the lab environment for practice: `cd lab-environment && docker-compose up`",
                "Only test systems you own or have explicit authorization for"
            ]
        )
