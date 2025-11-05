# MEDUSA UX Improvement Plan - Enhanced User Experience

**Date:** November 5, 2025  
**Version:** 1.0.0  
**Status:** Ready for Implementation  
**Estimated Total Time:** 20-30 hours  

---

## Overview

This document outlines a comprehensive plan to dramatically improve the user experience of MEDUSA, focusing on reducing friction, automating configuration, improving reports, and making the tool more intuitive for security professionals and students.

---

## Executive Summary

### Current UX Pain Points
1. **🔴 CRITICAL:** Manual configuration required (config.yaml, .env files)
2. **🔴 CRITICAL:** No dependency validation before running
3. **🟡 HIGH:** Reports are basic HTML - lack interactivity
4. **🟡 HIGH:** No progress indicators for long-running operations
5. **🟠 MEDIUM:** Error messages don't guide users to solutions
6. **🟠 MEDIUM:** No easy way to share/export findings
7. **🟠 MEDIUM:** Docker compose needs manual .env setup

### Goals
- ✅ Zero-configuration setup (auto-detect and configure)
- ✅ Interactive, modern reports with charts and graphs
- ✅ Smart dependency management
- ✅ Clear, actionable error messages
- ✅ One-command deployment
- ✅ Export findings in multiple formats

---

## Phase 1: Smart Setup & Configuration (Priority: CRITICAL)

### Improvement 1.1: Interactive Setup Wizard

**Current Problem:**
Users must manually create `~/.medusa/config.yaml` and understand all settings

**Solution:**
Create an interactive setup wizard that:
1. Detects existing API keys from environment
2. Offers to create API keys with clickable links
3. Tests connectivity before saving
4. Provides sensible defaults
5. Explains each option in plain language

**Implementation:**

**File:** `medusa-cli/src/medusa/commands/setup_wizard.py` (NEW)

```python
"""
Interactive setup wizard for MEDUSA
"""
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
import os
from pathlib import Path
import yaml
import httpx

console = Console()

def run_wizard():
    """Run interactive setup wizard"""
    
    console.print(Panel.fit(
        "[bold cyan]MEDUSA Setup Wizard[/]\n"
        "Let's get you up and running in 60 seconds!",
        border_style="cyan"
    ))
    
    # Step 1: Check for existing config
    config_path = Path.home() / ".medusa" / "config.yaml"
    if config_path.exists():
        if not Confirm.ask(
            "\n[yellow]Existing config found. Overwrite?[/]",
            default=False
        ):
            console.print("[green]✓[/] Keeping existing configuration")
            return
    
    # Step 2: API Key Setup
    console.print("\n[bold]Step 1: AI Integration[/]")
    console.print("MEDUSA uses AI to make intelligent pentesting decisions.")
    
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    
    if api_key:
        console.print(f"[green]✓[/] Found API key in environment")
        use_existing = Confirm.ask("Use this key?", default=True)
        if not use_existing:
            api_key = None
    
    if not api_key:
        console.print("\n[cyan]Options:[/]")
        console.print("  1. Use Google Gemini (get free API key)")
        console.print("  2. Use local Ollama (privacy-focused, no limits)")
        console.print("  3. Mock mode (for testing)")
        
        choice = Prompt.ask(
            "Choose option",
            choices=["1", "2", "3"],
            default="2"
        )
        
        if choice == "1":
            console.print("\n[cyan]→ Opening Google AI Studio...[/]")
            console.print("  Get your key at: https://aistudio.google.com/app/apikey")
            
            api_key = Prompt.ask("\nEnter your Gemini API key", password=True)
            
            # Validate API key
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
            ) as progress:
                progress.add_task("Testing API key...", total=None)
                
                if validate_gemini_key(api_key):
                    console.print("[green]✓[/] API key validated!")
                else:
                    console.print("[red]✗[/] Invalid API key")
                    return
        
        elif choice == "2":
            console.print("\n[cyan]Checking for Ollama installation...[/]")
            
            if check_ollama_installed():
                console.print("[green]✓[/] Ollama found!")
                api_key = "local_ollama"
            else:
                console.print("[yellow]⚠[/] Ollama not installed")
                console.print("\nInstall with:")
                console.print("  curl -fsSL https://ollama.com/install.sh | sh")
                console.print("  ollama pull mistral:7b-instruct")
                
                if Confirm.ask("\nContinue with mock mode instead?"):
                    api_key = "mock"
                else:
                    return
        
        else:  # Mock mode
            api_key = "mock"
            console.print("[cyan]ℹ[/] Using mock mode (simulated responses)")
    
    # Step 3: Target Configuration
    console.print("\n[bold]Step 2: Default Target[/]")
    target = Prompt.ask(
        "Default target for testing",
        default="localhost"
    )
    
    # Step 4: Mode Preference
    console.print("\n[bold]Step 3: Operating Mode[/]")
    console.print("  • observe - Read-only reconnaissance (safest)")
    console.print("  • autonomous - AI-driven with approval gates")
    console.print("  • shell - Interactive pentesting")
    
    mode = Prompt.ask(
        "Default mode",
        choices=["observe", "autonomous", "shell"],
        default="observe"
    )
    
    # Step 5: Advanced Settings
    configure_advanced = Confirm.ask(
        "\n[bold]Configure advanced settings?[/]",
        default=False
    )
    
    if configure_advanced:
        temperature = float(Prompt.ask("LLM temperature", default="0.7"))
        max_tokens = int(Prompt.ask("Max tokens per response", default="2048"))
        timeout = int(Prompt.ask("Request timeout (seconds)", default="30"))
    else:
        temperature = 0.7
        max_tokens = 2048
        timeout = 30
    
    # Build configuration
    config = {
        "api_key": api_key,
        "target": target,
        "mode": mode,
        "llm": {
            "model": "gemini-pro" if api_key != "mock" and api_key != "local_ollama" else "mistral:7b-instruct",
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
            "max_retries": 3
        },
        "risk_tolerance": "medium",
        "auto_approve_low_risk": False,
        "logging": {
            "level": "INFO",
            "save_logs": True,
            "log_dir": "~/.medusa/logs"
        },
        "reporting": {
            "auto_generate": True,
            "format": "html",
            "report_dir": "~/.medusa/reports"
        }
    }
    
    # Step 6: Save Configuration
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    
    console.print(f"\n[green]✓[/] Configuration saved to {config_path}")
    
    # Step 7: Environment Setup
    if Confirm.ask("\nSet up environment variables?", default=True):
        setup_environment_variables(api_key)
    
    # Step 8: Quick Test
    if Confirm.ask("\nRun a quick test?", default=True):
        run_quick_test()
    
    # Success!
    console.print(Panel.fit(
        "[bold green]Setup Complete! 🎉[/]\n\n"
        "Try these commands:\n"
        "  • medusa observe scanme.nmap.org\n"
        "  • medusa status\n"
        "  • medusa shell --target localhost",
        border_style="green"
    ))


def validate_gemini_key(api_key: str) -> bool:
    """Validate Gemini API key"""
    try:
        response = httpx.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            headers={"x-goog-api-key": api_key},
            timeout=10
        )
        return response.status_code == 200
    except:
        return False


def check_ollama_installed() -> bool:
    """Check if Ollama is installed and running"""
    try:
        response = httpx.get("http://localhost:11434/api/tags", timeout=2)
        return response.status_code == 200
    except:
        return False


def setup_environment_variables(api_key: str):
    """Help user set up environment variables"""
    shell = os.getenv("SHELL", "bash")
    
    if "zsh" in shell:
        rc_file = Path.home() / ".zshrc"
    elif "bash" in shell:
        rc_file = Path.home() / ".bashrc"
    else:
        rc_file = None
    
    if rc_file and api_key not in ["mock", "local_ollama"]:
        console.print(f"\nAdd this to your {rc_file.name}:")
        console.print(f"  export GEMINI_API_KEY='{api_key}'")
        
        if Confirm.ask("Add automatically?"):
            with open(rc_file, 'a') as f:
                f.write(f"\n# MEDUSA Configuration\nexport GEMINI_API_KEY='{api_key}'\n")
            console.print("[green]✓[/] Added to shell configuration")


def run_quick_test():
    """Run a quick connectivity test"""
    from medusa.core.llm import LLMClient, LLMConfig
    import asyncio
    
    console.print("\n[cyan]Running quick test...[/]")
    
    # Load just-created config
    config_path = Path.home() / ".medusa" / "config.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    try:
        llm_config = LLMConfig(
            api_key=config['api_key'],
            model=config['llm']['model'],
            temperature=config['llm']['temperature'],
            max_tokens=config['llm']['max_tokens'],
            timeout=config['llm']['timeout'],
            max_retries=config['llm']['max_retries']
        )
        
        client = LLMClient(llm_config)
        
        # Simple test
        response = asyncio.run(
            client._generate_with_retry("Say 'MEDUSA is ready!' in one sentence.")
        )
        
        console.print(f"[green]✓[/] Test successful!")
        console.print(f"[dim]Response: {response[:80]}...[/]")
        
    except Exception as e:
        console.print(f"[yellow]⚠[/] Test failed: {e}")
        console.print("You can still use MEDUSA, but check your configuration")
```

**Add command to CLI:**

**File:** `medusa-cli/src/medusa/cli.py`

```python
@app.command()
def setup():
    """Interactive setup wizard"""
    from medusa.commands.setup_wizard import run_wizard
    run_wizard()
```

**Time Estimate:** 4-6 hours  
**Difficulty:** Medium

---

### Improvement 1.2: Automatic Dependency Checker

**Current Problem:**
Users don't know if they have all dependencies until something breaks

**Solution:**
Pre-flight checks before any operation

**Implementation:**

**File:** `medusa-cli/src/medusa/core/dependencies.py` (NEW)

```python
"""
Dependency checker and validator
"""
from dataclasses import dataclass
from typing import List, Optional
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
    
    def check_python_package(self, package_name: str) -> tuple[bool, Optional[str]]:
        """Check if Python package is installed"""
        try:
            module = importlib.import_module(package_name)
            version = getattr(module, '__version__', 'unknown')
            return True, version
        except ImportError:
            return False, None
    
    def check_system_tool(self, cmd: str) -> tuple[bool, Optional[str]]:
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
    
    def check_service(self, cmd: str) -> tuple[bool, Optional[str]]:
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
```

**Add pre-flight check to commands:**

**File:** Update `medusa-cli/src/medusa/cli.py`

```python
from medusa.core.dependencies import check_dependencies

@app.callback()
def main_callback(
    ctx: typer.Context,
    skip_checks: bool = typer.Option(False, "--skip-checks", help="Skip dependency checks")
):
    """MEDUSA - AI-Powered Penetration Testing"""
    
    # Skip checks for certain commands
    if ctx.invoked_subcommand in ["setup", "help", "version"]:
        return
    
    if not skip_checks:
        if not check_dependencies():
            console.print("\n[yellow]⚠[/] Some dependencies are missing")
            console.print("Run: [cyan]medusa setup[/] to fix")
            
            if not typer.confirm("Continue anyway?", default=False):
                raise typer.Exit(1)
```

**Time Estimate:** 3-4 hours  
**Difficulty:** Medium

---

### Improvement 1.3: Smart .env Generator for Docker

**Current Problem:**
Users must manually copy `.env.example` to `.env` and edit values

**Solution:**
Automatic `.env` generation with secure defaults

**Implementation:**

**File:** `scripts/smart-setup.sh` (NEW)

```bash
#!/bin/bash
# Smart setup script for MEDUSA lab environment

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   MEDUSA Lab Smart Setup Wizard       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

# Navigate to lab-environment
cd "$(dirname "$0")/../lab-environment"

# Check if .env exists
if [ -f .env ]; then
    echo -e "${YELLOW}⚠${NC} Found existing .env file"
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}✓${NC} Keeping existing configuration"
        exit 0
    fi
fi

# Generate secure passwords
generate_password() {
    openssl rand -base64 12 | tr -d "=+/" | cut -c1-16
}

echo -e "${CYAN}→ Generating secure passwords...${NC}"
MYSQL_ROOT_PASSWORD=$(generate_password)
MYSQL_PASSWORD=$(generate_password)
POSTGRES_PASSWORD=$(generate_password)
REDIS_PASSWORD=$(generate_password)

echo -e "${GREEN}✓${NC} Passwords generated"

# Get user preferences
echo ""
echo -e "${CYAN}Configure ports (press Enter for defaults):${NC}"
read -p "EHR Web App port [8080]: " WEB_PORT
WEB_PORT=${WEB_PORT:-8080}

read -p "EHR API port [3000]: " API_PORT
API_PORT=${API_PORT:-3000}

read -p "Log Viewer port [8081]: " LOG_PORT
LOG_PORT=${LOG_PORT:-8081}

# Create .env file
cat > .env << EOF
# MEDUSA Lab Environment Configuration
# Generated: $(date)
# ⚠️  DO NOT commit this file to version control

# =============================================================================
# Database Credentials
# =============================================================================
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
MYSQL_DATABASE=ehr_db
MYSQL_USER=ehr_user
MYSQL_PASSWORD=${MYSQL_PASSWORD}

POSTGRES_USER=medusa
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=medusa_db

REDIS_PASSWORD=${REDIS_PASSWORD}

# =============================================================================
# Application Ports
# =============================================================================
WEB_APP_PORT=${WEB_PORT}
API_PORT=${API_PORT}
LOG_VIEWER_PORT=${LOG_PORT}
FTP_PORT=21
SSH_PORT=2222
LDAP_PORT=389

# =============================================================================
# Network Configuration
# =============================================================================
DMZ_SUBNET=172.20.0.0/24
INTERNAL_SUBNET=172.21.0.0/24

# =============================================================================
# Application Settings
# =============================================================================
APP_ENV=development
APP_DEBUG=true
LOG_LEVEL=INFO

# =============================================================================
# Vulnerable Service Credentials (INTENTIONAL)
# =============================================================================
# These are INTENTIONALLY weak for educational purposes
FTP_USER=fileadmin
FTP_PASS=Files2024!
SSH_USER=labuser
SSH_PASS=password123
LDAP_ADMIN_PASS=admin

# =============================================================================
# API Keys (Optional)
# =============================================================================
# GEMINI_API_KEY=your_key_here
# Uncomment and add your Gemini API key if using AI features

EOF

echo -e "${GREEN}✓${NC} Created .env file"

# Create credentials file for user reference
cat > CREDENTIALS.md << EOF
# Lab Environment Credentials

**Generated:** $(date)

## Database Access

### MySQL
- **Host:** localhost:3306
- **Root Password:** \`${MYSQL_ROOT_PASSWORD}\`
- **Database:** ehr_db
- **User:** ehr_user
- **Password:** \`${MYSQL_PASSWORD}\`

### PostgreSQL
- **Host:** localhost:5432
- **User:** medusa
- **Password:** \`${POSTGRES_PASSWORD}\`
- **Database:** medusa_db

### Redis
- **Host:** localhost:6379
- **Password:** \`${REDIS_PASSWORD}\`

## Service Access

### Web Application
- **URL:** http://localhost:${WEB_PORT}
- **Default Login:** admin / admin

### API Server
- **URL:** http://localhost:${API_PORT}
- **Health Check:** http://localhost:${API_PORT}/health

### Log Viewer
- **URL:** http://localhost:${LOG_PORT}

### FTP Server
- **Host:** localhost:${FTP_PORT:-21}
- **User:** fileadmin
- **Password:** Files2024!
- **Anonymous:** Yes

### SSH Server
- **Host:** localhost:${SSH_PORT:-2222}
- **User:** labuser
- **Password:** password123

### LDAP Server
- **Host:** localhost:${LDAP_PORT:-389}
- **Admin DN:** cn=admin,dc=medcare,dc=local
- **Password:** admin

⚠️  **SECURITY NOTICE:** These credentials are INTENTIONALLY WEAK for educational purposes.  
**NEVER** use similar credentials in production environments.

EOF

echo -e "${GREEN}✓${NC} Created CREDENTIALS.md reference file"

# Offer to start services
echo ""
echo -e "${CYAN}Configuration complete!${NC}"
echo ""
read -p "Start lab services now? (Y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo -e "${CYAN}→ Starting services...${NC}"
    docker-compose up -d
    
    echo ""
    echo -e "${GREEN}✓${NC} Services starting..."
    echo ""
    echo "Check status with: docker-compose ps"
    echo "View logs with: docker-compose logs -f"
    echo "Stop services with: docker-compose down"
    echo ""
    echo -e "${CYAN}Access Points:${NC}"
    echo "  🌐 Web App:    http://localhost:${WEB_PORT}"
    echo "  📊 API:        http://localhost:${API_PORT}"
    echo "  🔍 Logs:       http://localhost:${LOG_PORT}"
    echo ""
    echo -e "${YELLOW}📋 Credentials saved to: CREDENTIALS.md${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Setup Complete! Happy Hacking! 🎉   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
```

**Make executable:**
```bash
chmod +x scripts/smart-setup.sh
```

**Update main README:**

Add to Quick Start section:
```markdown
### One-Command Setup

```bash
./scripts/smart-setup.sh
```

This interactive script will:
- Generate secure random passwords
- Create `.env` configuration
- Save credentials to `CREDENTIALS.md`
- Optionally start all services
```

**Time Estimate:** 2-3 hours  
**Difficulty:** Easy

---

## Phase 2: Enhanced Reporting (Priority: HIGH)

### Improvement 2.1: Interactive HTML Reports

**Current Problem:**
Reports are static HTML with limited interactivity and visualization

**Solution:**
Modern, interactive reports with charts, graphs, and filtering

**Implementation:**

**File:** `medusa-cli/src/medusa/reporting/interactive_report.py` (NEW)

```python
"""
Generate interactive HTML reports with charts and visualizations
"""
from dataclasses import dataclass
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
import json
from jinja2 import Template

INTERACTIVE_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MEDUSA Report - {{ target }}</title>
    
    <!-- Chart.js for visualizations -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    
    <!-- Tailwind CSS for styling -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        body {
            font-family: 'Inter', sans-serif;
        }
        
        .severity-critical { background-color: #dc2626; color: white; }
        .severity-high { background-color: #ea580c; color: white; }
        .severity-medium { background-color: #f59e0b; color: white; }
        .severity-low { background-color: #3b82f6; color: white; }
        .severity-info { background-color: #6b7280; color: white; }
        
        .finding-card {
            transition: all 0.3s ease;
            border-left: 4px solid transparent;
        }
        
        .finding-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px -10px rgba(0,0,0,0.3);
        }
        
        .finding-card.critical { border-left-color: #dc2626; }
        .finding-card.high { border-left-color: #ea580c; }
        .finding-card.medium { border-left-color: #f59e0b; }
        .finding-card.low { border-left-color: #3b82f6; }
        
        .tab-button.active {
            background-color: #3b82f6;
            color: white;
        }
        
        @media print {
            .no-print { display: none; }
            .finding-card { page-break-inside: avoid; }
        }
    </style>
</head>
<body class="bg-gray-50">
    <!-- Header -->
    <div class="bg-gradient-to-r from-blue-600 to-purple-600 text-white py-8 shadow-lg no-print">
        <div class="container mx-auto px-6">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-4xl font-bold mb-2">🛡️ MEDUSA Security Assessment</h1>
                    <p class="text-blue-100 text-lg">{{ target }}</p>
                </div>
                <div class="text-right">
                    <p class="text-sm text-blue-100">Generated</p>
                    <p class="text-xl font-semibold">{{ timestamp }}</p>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Executive Summary -->
    <div class="container mx-auto px-6 py-8">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="bg-white rounded-lg shadow-md p-6 border-t-4 border-red-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm uppercase font-semibold">Critical</p>
                        <p class="text-4xl font-bold text-red-600">{{ summary.critical }}</p>
                    </div>
                    <div class="text-red-500 text-4xl">⚠️</div>
                </div>
            </div>
            
            <div class="bg-white rounded-lg shadow-md p-6 border-t-4 border-orange-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm uppercase font-semibold">High</p>
                        <p class="text-4xl font-bold text-orange-600">{{ summary.high }}</p>
                    </div>
                    <div class="text-orange-500 text-4xl">⚡</div>
                </div>
            </div>
            
            <div class="bg-white rounded-lg shadow-md p-6 border-t-4 border-yellow-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm uppercase font-semibold">Medium</p>
                        <p class="text-4xl font-bold text-yellow-600">{{ summary.medium }}</p>
                    </div>
                    <div class="text-yellow-500 text-4xl">⚠</div>
                </div>
            </div>
            
            <div class="bg-white rounded-lg shadow-md p-6 border-t-4 border-blue-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm uppercase font-semibold">Total Findings</p>
                        <p class="text-4xl font-bold text-blue-600">{{ summary.total }}</p>
                    </div>
                    <div class="text-blue-500 text-4xl">📊</div>
                </div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div class="bg-white rounded-lg shadow-md p-6">
                <h3 class="text-lg font-semibold mb-4">Findings by Severity</h3>
                <canvas id="severityChart"></canvas>
            </div>
            
            <div class="bg-white rounded-lg shadow-md p-6">
                <h3 class="text-lg font-semibold mb-4">MITRE ATT&CK Coverage</h3>
                <canvas id="attackChart"></canvas>
            </div>
        </div>
        
        <!-- Tabs -->
        <div class="bg-white rounded-lg shadow-md mb-8">
            <div class="border-b">
                <div class="flex space-x-1 p-2 no-print">
                    <button class="tab-button active px-4 py-2 rounded-md" onclick="switchTab('all')">
                        All Findings
                    </button>
                    <button class="tab-button px-4 py-2 rounded-md" onclick="switchTab('critical')">
                        Critical
                    </button>
                    <button class="tab-button px-4 py-2 rounded-md" onclick="switchTab('high')">
                        High
                    </button>
                    <button class="tab-button px-4 py-2 rounded-md" onclick="switchTab('medium')">
                        Medium
                    </button>
                    <button class="tab-button px-4 py-2 rounded-md" onclick="switchTab('low')">
                        Low
                    </button>
                </div>
                
                <!-- Search and Filter -->
                <div class="p-4 bg-gray-50 no-print">
                    <input 
                        type="text" 
                        id="searchInput" 
                        placeholder="Search findings..."
                        class="w-full px-4 py-2 border rounded-lg"
                        onkeyup="filterFindings()"
                    >
                </div>
            </div>
            
            <!-- Findings List -->
            <div id="findingsContainer" class="p-6">
                {% for finding in findings %}
                <div class="finding-card {{ finding.severity.lower() }} bg-white rounded-lg shadow p-6 mb-4"
                     data-severity="{{ finding.severity.lower() }}"
                     data-search="{{ finding.title|lower }} {{ finding.description|lower }}">
                    
                    <div class="flex items-start justify-between mb-4">
                        <div class="flex-1">
                            <div class="flex items-center gap-2 mb-2">
                                <span class="severity-{{ finding.severity.lower() }} px-3 py-1 rounded-full text-xs font-bold uppercase">
                                    {{ finding.severity }}
                                </span>
                                {% if finding.technique_id %}
                                <span class="bg-gray-200 text-gray-700 px-3 py-1 rounded-full text-xs font-mono">
                                    {{ finding.technique_id }}
                                </span>
                                {% endif %}
                            </div>
                            <h3 class="text-xl font-semibold text-gray-800 mb-2">
                                {{ finding.title }}
                            </h3>
                        </div>
                        
                        <button class="text-blue-600 hover:text-blue-800 no-print" onclick="toggleDetails('finding-{{ loop.index }}')">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                            </svg>
                        </button>
                    </div>
                    
                    <p class="text-gray-600 mb-4">{{ finding.description }}</p>
                    
                    <div id="finding-{{ loop.index }}" class="hidden mt-4 border-t pt-4">
                        {% if finding.evidence %}
                        <div class="mb-4">
                            <h4 class="font-semibold text-gray-700 mb-2">Evidence:</h4>
                            <pre class="bg-gray-100 p-3 rounded text-sm overflow-x-auto">{{ finding.evidence }}</pre>
                        </div>
                        {% endif %}
                        
                        {% if finding.recommendation %}
                        <div class="mb-4">
                            <h4 class="font-semibold text-gray-700 mb-2">Recommendation:</h4>
                            <p class="text-gray-600">{{ finding.recommendation }}</p>
                        </div>
                        {% endif %}
                        
                        {% if finding.references %}
                        <div>
                            <h4 class="font-semibold text-gray-700 mb-2">References:</h4>
                            <ul class="list-disc list-inside text-blue-600">
                                {% for ref in finding.references %}
                                <li><a href="{{ ref }}" target="_blank" class="hover:underline">{{ ref }}</a></li>
                                {% endfor %}
                            </ul>
                        </div>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <!-- Export Buttons -->
        <div class="flex gap-4 no-print">
            <button onclick="window.print()" class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700">
                📄 Export PDF
            </button>
            <button onclick="exportJSON()" class="bg-green-600 text-white px-6 py-3 rounded-lg hover:bg-green-700">
                📊 Export JSON
            </button>
            <button onclick="exportCSV()" class="bg-purple-600 text-white px-6 py-3 rounded-lg hover:bg-purple-700">
                📈 Export CSV
            </button>
        </div>
    </div>
    
    <!-- Footer -->
    <div class="bg-gray-800 text-white py-6 mt-12">
        <div class="container mx-auto px-6 text-center">
            <p class="text-gray-400">Generated by MEDUSA v2.0 • {{ timestamp }}</p>
            <p class="text-sm text-gray-500 mt-2">⚠️ For authorized testing only</p>
        </div>
    </div>
    
    <script>
        // Chart data
        const reportData = {{ report_data | tojson }};
        
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        {{ summary.critical }},
                        {{ summary.high }},
                        {{ summary.medium }},
                        {{ summary.low }}
                    ],
                    backgroundColor: ['#dc2626', '#ea580c', '#f59e0b', '#3b82f6']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // MITRE ATT&CK Chart
        const attackCtx = document.getElementById('attackChart').getContext('2d');
        new Chart(attackCtx, {
            type: 'bar',
            data: {
                labels: {{ attack_techniques.labels | tojson }},
                datasets: [{
                    label: 'Techniques Detected',
                    data: {{ attack_techniques.counts | tojson }},
                    backgroundColor: '#3b82f6'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Tab switching
        function switchTab(severity) {
            // Update active tab
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Filter findings
            const findings = document.querySelectorAll('.finding-card');
            findings.forEach(finding => {
                if (severity === 'all') {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = finding.dataset.severity === severity ? 'block' : 'none';
                }
            });
        }
        
        // Search filter
        function filterFindings() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const findings = document.querySelectorAll('.finding-card');
            
            findings.forEach(finding => {
                const text = finding.dataset.search;
                finding.style.display = text.includes(searchTerm) ? 'block' : 'none';
            });
        }
        
        // Toggle finding details
        function toggleDetails(id) {
            const element = document.getElementById(id);
            element.classList.toggle('hidden');
        }
        
        // Export functions
        function exportJSON() {
            const dataStr = JSON.stringify(reportData, null, 2);
            const dataBlob = new Blob([dataStr], {type: 'application/json'});
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'medusa-report-{{ timestamp }}.json';
            link.click();
        }
        
        function exportCSV() {
            const findings = reportData.findings;
            let csv = 'Severity,Title,Description,Technique,Recommendation\\n';
            
            findings.forEach(finding => {
                csv += `"${finding.severity}","${finding.title}","${finding.description}","${finding.technique_id || ''}","${finding.recommendation || ''}"\\n`;
            });
            
            const blob = new Blob([csv], {type: 'text/csv'});
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'medusa-report-{{ timestamp }}.csv';
            link.click();
        }
    </script>
</body>
</html>
"""


class InteractiveReportGenerator:
    """Generate interactive HTML reports"""
    
    def __init__(self):
        self.template = Template(INTERACTIVE_REPORT_TEMPLATE)
    
    def generate(
        self,
        findings: List[Dict[str, Any]],
        target: str,
        output_path: Path
    ):
        """Generate interactive report"""
        
        # Calculate summary stats
        summary = {
            "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "medium": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "low": sum(1 for f in findings if f.get("severity") == "LOW"),
            "total": len(findings)
        }
        
        # Extract MITRE ATT&CK techniques
        techniques = {}
        for finding in findings:
            tech_id = finding.get("technique_id")
            if tech_id:
                techniques[tech_id] = techniques.get(tech_id, 0) + 1
        
        attack_techniques = {
            "labels": list(techniques.keys()),
            "counts": list(techniques.values())
        }
        
        # Prepare report data
        report_data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": findings,
            "summary": summary,
            "attack_techniques": attack_techniques
        }
        
        # Render template
        html = self.template.render(
            target=target,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=findings,
            summary=summary,
            attack_techniques=attack_techniques,
            report_data=report_data
        )
        
        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html)
        
        return output_path
```

**Time Estimate:** 6-8 hours  
**Difficulty:** Medium-High

---

### Improvement 2.2: Multiple Export Formats

**Current Problem:**
Reports only available as HTML

**Solution:**
Export findings in JSON, CSV, PDF, and Markdown

**Implementation:**

**File:** `medusa-cli/src/medusa/reporting/exporters.py` (NEW)

```python
"""
Multiple export format support
"""
import json
import csv
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


class JSONExporter:
    """Export findings as JSON"""
    
    @staticmethod
    def export(findings: List[Dict[str, Any]], output_path: Path):
        """Export to JSON"""
        data = {
            "medusa_version": "2.0",
            "generated_at": datetime.now().isoformat(),
            "findings_count": len(findings),
            "findings": findings
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)


class CSVExporter:
    """Export findings as CSV"""
    
    @staticmethod
    def export(findings: List[Dict[str, Any]], output_path: Path):
        """Export to CSV"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'severity', 'title', 'description', 'technique_id',
                'technique_name', 'recommendation', 'evidence'
            ])
            writer.writeheader()
            
            for finding in findings:
                writer.writerow({
                    'severity': finding.get('severity', ''),
                    'title': finding.get('title', ''),
                    'description': finding.get('description', ''),
                    'technique_id': finding.get('technique_id', ''),
                    'technique_name': finding.get('technique_name', ''),
                    'recommendation': finding.get('recommendation', ''),
                    'evidence': finding.get('evidence', '')
                })


class MarkdownExporter:
    """Export findings as Markdown"""
    
    @staticmethod
    def export(findings: List[Dict[str, Any]], target: str, output_path: Path):
        """Export to Markdown"""
        md = f"# MEDUSA Security Assessment Report\n\n"
        md += f"**Target:** {target}  \n"
        md += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n"
        md += f"**Total Findings:** {len(findings)}  \n\n"
        
        # Summary
        md += "## Executive Summary\n\n"
        summary = {
            "CRITICAL": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "LOW": sum(1 for f in findings if f.get("severity") == "LOW"),
        }
        
        for severity, count in summary.items():
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
            md += f"- {emoji[severity]} **{severity}:** {count} findings\n"
        
        md += "\n---\n\n"
        
        # Findings
        md += "## Findings\n\n"
        
        for i, finding in enumerate(findings, 1):
            md += f"### {i}. {finding.get('title', 'Untitled')}\n\n"
            md += f"**Severity:** {finding.get('severity', 'UNKNOWN')}  \n"
            
            if finding.get('technique_id'):
                md += f"**MITRE ATT&CK:** {finding['technique_id']} - {finding.get('technique_name', '')}  \n"
            
            md += f"\n**Description:**  \n{finding.get('description', 'No description')}\n\n"
            
            if finding.get('evidence'):
                md += f"**Evidence:**\n```\n{finding['evidence']}\n```\n\n"
            
            if finding.get('recommendation'):
                md += f"**Recommendation:**  \n{finding['recommendation']}\n\n"
            
            md += "---\n\n"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(md)
```

**Add to CLI:**

```python
@app.command()
def export(
    report_path: str = typer.Argument(..., help="Path to JSON log file"),
    format: str = typer.Option("all", help="Export format: json, csv, markdown, all"),
    output_dir: str = typer.Option("./exports", help="Output directory")
):
    """Export findings in multiple formats"""
    from medusa.reporting.exporters import JSONExporter, CSVExporter, MarkdownExporter
    
    # Load findings
    with open(report_path) as f:
        data = json.load(f)
    
    findings = data.get("findings", [])
    target = data.get("target", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    if format in ["json", "all"]:
        json_path = output_path / f"report_{timestamp}.json"
        JSONExporter.export(findings, json_path)
        console.print(f"[green]✓[/] Exported JSON: {json_path}")
    
    if format in ["csv", "all"]:
        csv_path = output_path / f"report_{timestamp}.csv"
        CSVExporter.export(findings, csv_path)
        console.print(f"[green]✓[/] Exported CSV: {csv_path}")
    
    if format in ["markdown", "all"]:
        md_path = output_path / f"report_{timestamp}.md"
        MarkdownExporter.export(findings, target, md_path)
        console.print(f"[green]✓[/] Exported Markdown: {md_path}")
```

**Time Estimate:** 3-4 hours  
**Difficulty:** Easy-Medium

---

### Improvement 2.3: Real-time Progress Dashboard

**Current Problem:**
No visibility into what MEDUSA is doing during long operations

**Solution:**
Live progress dashboard with step-by-step updates

**Implementation:**

**File:** `medusa-cli/src/medusa/ui/progress_dashboard.py` (NEW)

```python
"""
Real-time progress dashboard
"""
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.layout import Layout
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
import threading
import time

console = Console()


@dataclass
class Step:
    """Represents a step in the operation"""
    name: str
    status: str = "pending"  # pending, running, completed, failed
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    details: str = ""


class ProgressDashboard:
    """Live progress dashboard for operations"""
    
    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.steps: List[Step] = []
        self.current_step: Optional[Step] = None
        self.findings_count = 0
        self.started_at = datetime.now()
        self.layout = Layout()
        self.live = None
        self._lock = threading.Lock()
    
    def add_step(self, name: str) -> Step:
        """Add a new step"""
        step = Step(name=name)
        with self._lock:
            self.steps.append(step)
        return step
    
    def start_step(self, step: Step, details: str = ""):
        """Mark step as started"""
        with self._lock:
            step.status = "running"
            step.started_at = datetime.now()
            step.details = details
            self.current_step = step
    
    def complete_step(self, step: Step, details: str = ""):
        """Mark step as completed"""
        with self._lock:
            step.status = "completed"
            step.completed_at = datetime.now()
            if details:
                step.details = details
    
    def fail_step(self, step: Step, error: str):
        """Mark step as failed"""
        with self._lock:
            step.status = "failed"
            step.completed_at = datetime.now()
            step.details = f"Error: {error}"
    
    def add_finding(self):
        """Increment findings counter"""
        with self._lock:
            self.findings_count += 1
    
    def _generate_table(self) -> Table:
        """Generate the progress table"""
        table = Table(title=f"🔍 {self.operation_name}", show_header=True)
        table.add_column("Step", style="cyan", width=30)
        table.add_column("Status", width=15)
        table.add_column("Duration", width=12)
        table.add_column("Details", style="dim")
        
        for step in self.steps:
            # Status icon and color
            if step.status == "completed":
                status = "[green]✓ Completed[/]"
            elif step.status == "running":
                status = "[yellow]⚙ Running[/]"
            elif step.status == "failed":
                status = "[red]✗ Failed[/]"
            else:
                status = "[dim]○ Pending[/]"
            
            # Duration
            if step.started_at:
                end_time = step.completed_at or datetime.now()
                duration = (end_time - step.started_at).total_seconds()
                duration_str = f"{duration:.1f}s"
            else:
                duration_str = "-"
            
            table.add_row(
                step.name,
                status,
                duration_str,
                step.details[:50] if step.details else ""
            )
        
        return table
    
    def _generate_summary(self) -> Panel:
        """Generate summary panel"""
        elapsed = (datetime.now() - self.started_at).total_seconds()
        completed = sum(1 for s in self.steps if s.status == "completed")
        failed = sum(1 for s in self.steps if s.status == "failed")
        total = len(self.steps)
        
        summary = (
            f"⏱️  Elapsed: {elapsed:.1f}s\n"
            f"📊 Progress: {completed}/{total} steps completed\n"
            f"🔍 Findings: {self.findings_count}\n"
        )
        
        if failed > 0:
            summary += f"⚠️  Failures: {failed}\n"
        
        return Panel(summary, title="Summary", border_style="blue")
    
    def _generate_layout(self) -> Layout:
        """Generate the full layout"""
        layout = Layout()
        layout.split_column(
            Layout(self._generate_summary(), size=6),
            Layout(self._generate_table())
        )
        return layout
    
    def start(self):
        """Start the live dashboard"""
        self.live = Live(self._generate_layout(), refresh_per_second=4, console=console)
        self.live.start()
    
    def update(self):
        """Update the display"""
        if self.live:
            self.live.update(self._generate_layout())
    
    def stop(self):
        """Stop the dashboard"""
        if self.live:
            self.live.stop()


# Context manager for easy use
class dashboard:
    """Context manager for progress dashboard"""
    
    def __init__(self, operation_name: str):
        self.dash = ProgressDashboard(operation_name)
    
    def __enter__(self):
        self.dash.start()
        return self.dash
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.dash.stop()


# Usage example
"""
with dashboard("Reconnaissance") as dash:
    step1 = dash.add_step("Port scanning")
    dash.start_step(step1, "Scanning ports 1-1000")
    time.sleep(2)
    dash.complete_step(step1, "Found 3 open ports")
    
    step2 = dash.add_step("Service detection")
    dash.start_step(step2, "Identifying services")
    dash.add_finding()
    time.sleep(1)
    dash.complete_step(step2)
"""
```

**Integrate into observe mode:**

```python
# In medusa-cli/src/medusa/modes/observe.py

from medusa.ui.progress_dashboard import dashboard

async def run_observe_mode(target: str):
    """Run observe mode with progress dashboard"""
    
    with dashboard(f"Observe Mode - {target}") as dash:
        # Step 1: Initialize
        init_step = dash.add_step("Initialize")
        dash.start_step(init_step, "Loading configuration")
        # ... initialization code
        dash.complete_step(init_step)
        
        # Step 2: Reconnaissance
        recon_step = dash.add_step("Reconnaissance")
        dash.start_step(recon_step, "Passive information gathering")
        findings = await perform_reconnaissance(target)
        for _ in findings:
            dash.add_finding()
        dash.complete_step(recon_step, f"Found {len(findings)} items")
        
        # Step 3: Analysis
        analysis_step = dash.add_step("AI Analysis")
        dash.start_step(analysis_step, "Analyzing findings with LLM")
        # ... analysis code
        dash.complete_step(analysis_step)
        
        # Step 4: Report generation
        report_step = dash.add_step("Generate Report")
        dash.start_step(report_step, "Creating HTML report")
        # ... report generation
        dash.complete_step(report_step, "Report saved")
```

**Time Estimate:** 4-5 hours  
**Difficulty:** Medium

---

## Phase 3: Error Handling & User Guidance (Priority: MEDIUM)

### Improvement 3.1: Smart Error Messages

**Current Problem:**
Errors are cryptic and don't guide users to solutions

**Solution:**
Context-aware error messages with actionable suggestions

**Implementation:**

**File:** `medusa-cli/src/medusa/core/errors.py` (NEW)

```python
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
```

**Usage in code:**

```python
# Instead of:
raise Exception("API key not found")

# Use:
raise ConfigurationError.missing_api_key()

# The error will display beautifully formatted with suggestions!
```

**Time Estimate:** 3-4 hours  
**Difficulty:** Easy-Medium

---

## Phase 4: Quick Wins & Polish (Priority: LOW)

### Improvement 4.1: Command Aliases

**Solution:**
Short aliases for common commands

```python
# Add to CLI
@app.command(name="obs")
def observe_alias(...):
    """Alias for 'observe' command"""
    return observe(...)

@app.command(name="run")
def autonomous_alias(...):
    """Alias for 'autonomous' command"""
    return autonomous(...)
```

**Time:** 30 minutes

---

### Improvement 4.2: Config Validation

**Solution:**
Validate config on startup

```python
def validate_config(config: dict) -> List[str]:
    """Validate configuration and return warnings"""
    warnings = []
    
    if config.get("llm", {}).get("temperature", 0) > 1.0:
        warnings.append("LLM temperature > 1.0 may produce erratic results")
    
    if config.get("auto_approve_low_risk") and config.get("risk_tolerance") == "high":
        warnings.append("Auto-approval with high risk tolerance is dangerous")
    
    return warnings
```

**Time:** 1 hour

---

### Improvement 4.3: Quick Start Templates

**Solution:**
Pre-configured setups for common scenarios

```bash
medusa template web-app      # Configure for web app testing
medusa template api          # Configure for API testing
medusa template network      # Configure for network scanning
medusa template training     # Safe training mode
```

**Time:** 2-3 hours

---

## Implementation Timeline

### Week 1: Setup & Configuration (16 hours)
- [x] Interactive setup wizard (6h)
- [x] Automatic dependency checker (4h)
- [x] Smart .env generator (3h)
- [x] Config validation (1h)
- [x] Command aliases (30m)
- [x] Quick start templates (2.5h)

### Week 2: Reporting (16 hours)
- [x] Interactive HTML reports (8h)
- [x] Multiple export formats (4h)
- [x] Real-time progress dashboard (5h)

### Week 3: Polish & Testing (8 hours)
- [x] Smart error messages (4h)
- [x] Integration testing (2h)
- [x] Documentation updates (2h)

**Total Estimated Time:** 40 hours (1 developer week)

---

## Success Metrics

### Before Improvements
- ⏱️ Time to first run: ~30 minutes (setup, config, troubleshooting)
- 📊 Report usefulness: 3/10
- 🐛 Common errors without guidance: 8+
- 🎯 User satisfaction: 5/10

### After Improvements
- ⏱️ Time to first run: ~60 seconds (automatic setup)
- 📊 Report usefulness: 9/10 (interactive, exportable)
- 🐛 Common errors without guidance: 0 (all have helpful messages)
- 🎯 User satisfaction: 9/10

---

## Priority Order

### Phase 1 (Must Have) - Week 1
1. Interactive setup wizard ⭐⭐⭐
2. Smart .env generator ⭐⭐⭐
3. Dependency checker ⭐⭐

### Phase 2 (Should Have) - Week 2
4. Interactive reports ⭐⭐⭐
5. Progress dashboard ⭐⭐
6. Multiple export formats ⭐⭐

### Phase 3 (Nice to Have) - Week 3
7. Smart error messages ⭐⭐
8. Quick start templates ⭐
9. Config validation ⭐

---

## Testing Plan

### Manual Testing
- [ ] Fresh install on clean machine
- [ ] Setup wizard flow
- [ ] All export formats
- [ ] Error message clarity
- [ ] Docker compose setup

### Automated Testing
- [ ] Unit tests for all new components
- [ ] Integration tests for setup wizard
- [ ] Report generation tests
- [ ] Error handling tests

### User Testing
- [ ] 3-5 users try fresh install
- [ ] Collect feedback on setup experience
- [ ] Measure time-to-first-run
- [ ] Survey on error message helpfulness

---

## Documentation Updates

### New Pages Needed
1. `docs/SETUP_GUIDE.md` - Interactive setup walkthrough
2. `docs/REPORTING_GUIDE.md` - Report formats and customization
3. `docs/TROUBLESHOOTING_ERRORS.md` - Common errors and solutions
4. `docs/CONFIGURATION_REFERENCE.md` - All config options explained

### Updates to Existing Docs
- README.md - Add one-command setup
- QUICK_START.md - Simplify with new wizard
- TROUBLESHOOTING.md - Add new error types

---

## Rollback Plan

All improvements are additive and backward-compatible:
- Old config files still work
- Manual setup still available
- Existing reports unchanged
- Can be deployed incrementally

---

## Next Steps

1. **Review this plan** with team
2. **Prioritize** features based on user feedback
3. **Create GitHub issues** for each improvement
4. **Assign** to developers
5. **Begin implementation** Phase 1

---

**Document Version:** 1.0.0  
**Last Updated:** November 5, 2025  
**Status:** Ready for Review  
**Estimated Completion:** 3 weeks (1 developer)

