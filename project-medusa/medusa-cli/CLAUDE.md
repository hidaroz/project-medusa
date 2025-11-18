# MEDUSA CLI - Claude AI Context Guide

**Quick Context for AI Assistants working with MEDUSA CLI**

## Project Identity

**MEDUSA CLI** = Multi-Environment Detection and Understanding System for Autonomous testing
- **Type**: AI-Powered Autonomous Penetration Testing Command-Line Interface
- **Language**: Python 3.9+
- **License**: MIT / Apache 2.0
- **Purpose**: Educational penetration testing with LLM-powered intelligent decision-making

## Core Concept

MEDUSA is an **attacker agent** that uses AI (Large Language Models) to autonomously perform penetration testing against vulnerable systems (like the MedCare EHR target environment). Think of it as an AI-powered ethical hacker with safety guardrails.

## Entry Points

| File | Purpose | When to Read |
|------|---------|--------------|
| `README.md` | User-facing documentation, setup guide | Understanding overall capabilities |
| `INTEGRATION_GUIDE.md` | LLM integration details | Working with AI/LLM features |
| `CONTRIBUTING.md` | Development guidelines | Contributing to the project |
| `src/medusa/cli.py` | Main CLI entry point | Understanding commands |
| `src/medusa/client.py` | Core client logic | Understanding API interactions |
| `src/medusa/config.py` | Configuration management | Setup and config issues |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    MEDUSA CLI                           │
│  (AI-Powered Autonomous Penetration Testing Agent)     │
└─────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  LLM Brain   │  │ Attack Tools │  │ Approval     │
│              │  │              │  │ Gates        │
│ - Local      │  │ - Nmap       │  │              │
│   (Ollama)   │  │ - SQLMap     │  │ LOW/MEDIUM   │
│ - OpenAI     │  │ - httpx      │  │ HIGH/CRITICAL│
│ - Anthropic  │  │ - Amass      │  │              │
│ - Mock       │  │ - Kerbrute   │  │              │
└──────────────┘  └──────────────┘  └──────────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │    Target Systems              │
        │  (e.g., MedCare EHR, Custom)  │
        └────────────────────────────────┘
```

## Directory Structure

```
medusa-cli/
├── src/medusa/                    # Main source code
│   ├── cli.py                     # Typer-based CLI commands
│   ├── client.py                  # MedusaClient - core logic
│   ├── config.py                  # Configuration management
│   ├── approval.py                # Approval gate system
│   ├── checkpoint.py              # Checkpointing for pause/resume
│   ├── display.py                 # Rich terminal UI
│   ├── reporter.py                # Report generation (HTML, JSON, MD)
│   ├── session.py                 # Session management
│   ├── error_handler.py           # Error handling decorators
│   ├── first_run.py               # First-time setup wizard
│   ├── command_parser.py          # Natural language command parsing
│   ├── completers.py              # Shell auto-completion
│   ├── exporters.py               # Export utilities
│   │
│   ├── core/                      # Core subsystems
│   │   └── llm/                   # LLM Integration
│   │       ├── __init__.py
│   │       ├── client.py          # LLM client abstraction
│   │       ├── config.py          # LLM configuration
│   │       ├── factory.py         # Provider factory
│   │       ├── exceptions.py      # LLM exceptions
│   │       ├── legacy_adapter.py  # Backward compatibility
│   │       └── providers/         # Provider implementations
│   │           ├── base.py        # Base provider interface
│   │           ├── local.py       # Ollama local LLM
│   │           ├── openai.py      # OpenAI GPT integration
│   │           ├── anthropic.py   # Anthropic Claude integration
│   │           └── mock.py        # Mock provider for testing
│   │
│   ├── modes/                     # Operating modes
│   │   ├── autonomous.py          # Full AI-driven attack chain
│   │   ├── interactive.py         # Interactive shell mode
│   │   └── observe.py             # Read-only reconnaissance
│   │
│   ├── tools/                     # Security tool wrappers
│   │   ├── base.py                # Base tool class
│   │   ├── nmap.py                # Nmap wrapper
│   │   ├── amass.py               # Amass subdomain enumeration
│   │   ├── httpx_scanner.py       # httpx web scanner
│   │   ├── kerbrute.py            # Kerberos brute-force
│   │   ├── sql_injection.py       # SQL injection testing
│   │   ├── web_scanner.py         # Web vulnerability scanner
│   │   ├── graph_integration.py   # Neo4j graph integration
│   │   └── parsers/               # Output parsers
│   │
│   ├── world_model/               # Neo4j knowledge graph
│   │   ├── client.py              # Neo4j client
│   │   └── models.py              # Graph data models
│   │
│   ├── api/                       # Graph API server
│   │   └── graph_api.py           # FastAPI graph API
│   │
│   ├── templates/                 # Report templates
│   │   ├── report.md              # Markdown template
│   │   ├── technical_report.html  # HTML technical report
│   │   └── executive_summary.html # Executive summary
│   │
│   └── display/                   # Display utilities
│       └── progress.py            # Progress indicators
│
├── tests/                         # Test suite
├── examples/                      # Usage examples
│   └── reporting_demo.py
├── requirements.txt               # Dependencies
├── requirements-dev.txt           # Dev dependencies
├── setup.py                       # Package setup
├── pyproject.toml                 # Project metadata
├── pytest.ini                     # pytest configuration
├── api_server.py                  # Graph API server entry
├── run_graph_api.py              # Graph API runner
├── test_mistral_llm.py           # LLM tests
└── README.md                      # User documentation
```

## Key Concepts

### 1. Three Operating Modes

| Mode | File | Description | Use Case |
|------|------|-------------|----------|
| **Autonomous** | `modes/autonomous.py` | AI plans and executes full attack chain with approval gates | Complete penetration test |
| **Interactive** | `modes/interactive.py` | Natural language shell for manual control | Step-by-step exploration |
| **Observe** | `modes/observe.py` | Read-only reconnaissance, no exploitation | Initial assessment |

### 2. LLM Integration (Brain of MEDUSA)

**Location**: `src/medusa/core/llm/`

**Providers**:
- **Local (Ollama)** - Default, free, private, unlimited (Mistral-7B-Instruct)
- **OpenAI** - GPT-4, GPT-3.5-turbo (requires API key)
- **Anthropic** - Claude-3 (requires API key)
- **Mock** - Testing mode (no real AI)

**Key Functions**:
```python
# In client.py
await llm_client.get_reconnaissance_recommendation(target, context)
await llm_client.get_enumeration_recommendation(target, findings)
await llm_client.assess_vulnerability_risk(vulnerability, context)
await llm_client.plan_attack_strategy(target, findings, objectives)
await llm_client.get_next_action_recommendation(context)
```

**Configuration** (`~/.medusa/config.yaml`):
```yaml
llm:
  provider: auto          # auto, local, openai, anthropic, mock
  local_model: mistral:7b-instruct
  ollama_url: http://localhost:11434
  temperature: 0.7
  max_tokens: 2048
  timeout: 60
  max_retries: 3
  mock_mode: false
```

### 3. Approval Gates System

**Location**: `src/medusa/approval.py`

**Risk Levels**:
- **LOW**: Port scans, service enumeration (auto-approved)
- **MEDIUM**: Vulnerability scanning, exploitation attempts (prompt user)
- **HIGH**: Data modification, exfiltration (requires approval)
- **CRITICAL**: Destructive actions, persistence (always prompt)

**Purpose**: Prevents accidental damage during autonomous operation

### 4. Security Tools Integration

**Base Class**: `tools/base.py` - All tools inherit from `BaseTool`

**Available Tools**:
- **Nmap** (`tools/nmap.py`) - Port scanning, service detection
- **Amass** (`tools/amass.py`) - Subdomain enumeration
- **httpx** (`tools/httpx_scanner.py`) - HTTP probing
- **Kerbrute** (`tools/kerbrute.py`) - Kerberos user enumeration
- **SQLMap** (via `tools/sql_injection.py`) - SQL injection testing
- **Web Scanner** (`tools/web_scanner.py`) - Custom web vulnerability scanner

**Common Pattern**:
```python
class MyTool(BaseTool):
    @property
    def tool_binary_name(self) -> str:
        return "tool_name"

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        # Sanitize input
        target = self._sanitize_target(target)

        # Build command
        cmd = [self.tool_binary_name, target]

        # Execute with timeout
        stdout, stderr, returncode = await self._run_command(cmd)

        # Parse results
        findings = self.parse_output(stdout, stderr)

        return self._create_result_dict(success=True, findings=findings, ...)
```

### 5. World Model (Knowledge Graph)

**Location**: `src/medusa/world_model/`

**Technology**: Neo4j graph database

**Purpose**: Store and query relationships between:
- Domains, Subdomains, Hosts
- Ports, Services, Webservers
- Users, Credentials
- Vulnerabilities

**Models** (`world_model/models.py`):
- `Domain`, `Subdomain`, `Host`, `Port`
- `WebServer`, `User`, `Credential`, `Vulnerability`

### 6. Checkpoint System

**Location**: `src/medusa/checkpoint.py`

**Purpose**: Save/resume autonomous operations

**Use Case**: Long-running pentests can be paused and resumed later

```python
# In autonomous.py
checkpoint_mgr = CheckpointManager(operation_id)
checkpoint_mgr.save(operation_checkpoint)
checkpoint_data = checkpoint_mgr.load()
```

### 7. Reporting System

**Location**: `src/medusa/reporter.py`

**Formats**:
- **JSON** - Machine-readable logs (`~/.medusa/logs/`)
- **HTML Technical Report** - Dark-themed professional report
- **HTML Executive Summary** - Business-focused summary
- **Markdown** - Integration with documentation systems

**MITRE ATT&CK Mapping**: All techniques mapped to MITRE framework

## Configuration Files

### User Configuration

**Location**: `~/.medusa/config.yaml`

**Structure**:
```yaml
# LLM Configuration
llm:
  provider: local
  local_model: mistral:7b-instruct
  ollama_url: http://localhost:11434
  temperature: 0.7
  max_tokens: 2048

# Target Configuration
target:
  type: docker          # or 'custom'
  url: http://localhost:3001

# Risk Tolerance
risk_tolerance:
  auto_approve_low: true
  auto_approve_medium: false
  auto_approve_high: false
```

## Common Tasks - Quick Reference

### Understanding the CLI

**Start Here**: `src/medusa/cli.py`

**Main Commands**:
```python
@app.command("setup")       # Run setup wizard
@app.command("run")         # Execute penetration test
@app.command("shell")       # Interactive shell mode
@app.command("observe")     # Reconnaissance mode
@app.command("status")      # Show configuration
@app.command("logs")        # View logs
@app.command("reports")     # Manage reports

@llm_app.command("verify")  # Check LLM connectivity
```

### Adding a New LLM Provider

1. Create provider class in `src/medusa/core/llm/providers/`
2. Inherit from `BaseLLMProvider` (`providers/base.py`)
3. Implement required methods:
   - `generate(prompt, context) -> LLMResponse`
   - `health_check() -> bool`
4. Register in `factory.py`
5. Update `config.py` for new provider option

### Adding a New Security Tool

1. Create tool class in `src/medusa/tools/`
2. Inherit from `BaseTool` (`tools/base.py`)
3. Implement:
   - `tool_binary_name` property
   - `execute(target, **kwargs)` method
   - `parse_output(stdout, stderr)` method
4. Use `_sanitize_target()` for input validation
5. Use `_run_command()` for subprocess execution
6. Return standardized dict with `_create_result_dict()`

### Modifying Autonomous Mode Logic

**File**: `src/medusa/modes/autonomous.py`

**Phases**:
1. Reconnaissance (`_run_reconnaissance()`)
2. Enumeration (`_run_enumeration()`)
3. Vulnerability Assessment (`_run_vulnerability_assessment()`)
4. Exploitation (`_run_exploitation()`)
5. Post-Exploitation (`_run_post_exploitation()`)

Each phase:
- Gets LLM recommendations
- Executes approved actions
- Updates world model
- Saves checkpoint
- Generates phase report

### Working with the World Model

```python
from medusa.world_model import Neo4jClient

# Connect
client = Neo4jClient(uri="bolt://localhost:7687")
client.connect()

# Create entities
domain_id = client.create_domain("example.com")
host_id = client.create_host("192.168.1.1", domain_id)
port_id = client.create_port(host_id, 80, "tcp", "http")

# Query relationships
subdomains = client.get_domain_subdomains("example.com")
open_ports = client.get_host_ports("192.168.1.1")

# Close connection
client.close()
```

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **CLI Framework** | Typer | Modern CLI with type hints |
| **Terminal UI** | Rich | Beautiful progress bars, panels, tables |
| **LLM Providers** | Ollama, OpenAI, Anthropic | AI decision-making |
| **Graph DB** | Neo4j | Knowledge graph / World Model |
| **Web Framework** | FastAPI | Graph API server |
| **HTTP Client** | httpx | Async HTTP requests |
| **Config** | PyYAML | Configuration management |
| **Testing** | pytest | Unit and integration tests |
| **Reports** | Jinja2 | HTML template rendering |

## Dependencies

**Core** (`requirements.txt`):
```
typer>=0.9.0          # CLI framework
rich>=13.7.0          # Terminal UI
httpx>=0.27.0         # Async HTTP
pyyaml>=6.0           # Config management
neo4j>=5.14.0         # Graph database
fastapi>=0.104.0      # API server
uvicorn>=0.24.0       # ASGI server
jinja2>=3.1.0         # Template engine
python-multipart      # File uploads
```

**LLM Providers** (optional):
```
google-generativeai   # Gemini (legacy)
openai               # OpenAI GPT
anthropic            # Anthropic Claude
```

**Dev** (`requirements-dev.txt`):
```
pytest>=7.4.0
pytest-cov
pytest-asyncio
black                # Code formatter
mypy                 # Type checker
flake8               # Linter
```

## Testing

### Run All Tests
```bash
cd medusa-cli
pytest tests/ -v
```

### Test LLM Integration
```bash
python test_mistral_llm.py
python test_mistral_reasoning.py
```

### Test with Coverage
```bash
pytest --cov=medusa --cov-report=html tests/
```

### Test Specific Module
```bash
pytest tests/test_client.py -v
pytest tests/test_llm.py -v
```

## Common Debugging Scenarios

### LLM Not Responding

**Check**:
1. Run `medusa llm verify` to check connectivity
2. For Ollama: Ensure `ollama serve` is running
3. For cloud: Verify API key in `~/.medusa/config.yaml`
4. Check logs: `medusa logs --latest`

**Files to investigate**:
- `src/medusa/core/llm/client.py` - LLM client logic
- `src/medusa/core/llm/providers/local.py` - Ollama provider
- `src/medusa/config.py` - Configuration loading

### Tool Execution Failing

**Check**:
1. Tool installed: `which nmap` (or tool name)
2. Permissions: Some tools need sudo
3. Target sanitization: Check for invalid characters

**Files to investigate**:
- `src/medusa/tools/base.py` - Base tool execution
- Specific tool file (e.g., `tools/nmap.py`)
- `src/medusa/error_handler.py` - Error handling

### Approval Gates Not Working

**Files to investigate**:
- `src/medusa/approval.py` - Approval logic
- `src/medusa/config.py` - Risk tolerance settings
- `src/medusa/modes/autonomous.py` - Mode-specific approval

### Reports Not Generating

**Check**:
1. Reports directory exists: `~/.medusa/reports/`
2. Template files present: `src/medusa/templates/`
3. Operation logs exist: `~/.medusa/logs/`

**Files to investigate**:
- `src/medusa/reporter.py` - Report generation
- `src/medusa/templates/` - Report templates

## Important Patterns

### Async/Await Usage

MEDUSA uses async extensively for:
- LLM API calls
- HTTP requests
- Tool execution
- Neo4j queries

**Pattern**:
```python
async def my_function():
    async with httpx.AsyncClient() as client:
        response = await client.get(url)

    result = await llm_client.generate(prompt)
    return result

# Run async function
asyncio.run(my_function())
```

### Error Handling

**Decorator Pattern** (`error_handler.py`):
```python
@error_handler_decorator
async def risky_operation():
    # Automatically handles exceptions
    # Logs errors
    # Shows user-friendly messages
    pass
```

### Display/UI Pattern

**Use Rich Console** (`display.py`):
```python
from medusa.display import display

display.show_success("Operation completed")
display.show_error("Something went wrong")
display.show_warning("Risky action ahead")
display.show_info("Processing...")

# Panels, tables, progress bars
display.panel("Title", "Content", style="cyan")
```

## Security Considerations

### Input Validation

**Always sanitize targets**:
```python
target = self._sanitize_target(user_input)
```

**Prevents**:
- Command injection
- Path traversal
- SQL injection in tool commands

### Approval System

**Enforces ethical boundaries**:
- User must approve HIGH and CRITICAL actions
- Prevents accidental destructive operations
- Maintains audit trail

### API Key Storage

**Location**: `~/.medusa/config.yaml` (permissions: 0600)

**Environment Variables**:
- `CLOUD_API_KEY` - For OpenAI/Anthropic
- `NEO4J_PASSWORD` - For Neo4j
- `GEMINI_API_KEY` - Legacy Gemini support

## Integration Points

### With MedCare EHR (Target)

**Target Services**:
- EHR API: `http://localhost:3000`
- EHR Webapp: `http://localhost:8080`
- MySQL: `localhost:3306`
- LDAP: `localhost:389`
- SSH: `localhost:2222`
- FTP: `localhost:21`

### With Neo4j Graph DB

**Connection**:
```python
uri = "bolt://localhost:7687"
username = "neo4j"
password = "medusa_graph_pass"
```

**Docker**: Auto-detects container environment and uses service name

### With Graph API Server

**Run API**:
```bash
python run_graph_api.py
# or
uvicorn medusa.api.graph_api:app --reload
```

**Endpoints**: `/api/domains`, `/api/hosts`, `/api/vulnerabilities`, etc.

## MITRE ATT&CK Coverage

**Tactics Covered**:
1. Reconnaissance (TA0043)
2. Initial Access (TA0001)
3. Execution (TA0002)
4. Persistence (TA0003)
5. Privilege Escalation (TA0004)
6. Defense Evasion (TA0005)
7. Credential Access (TA0006)
8. Discovery (TA0007)
9. Collection (TA0009)

**Techniques**: 32+ techniques mapped

**Reports**: Include MITRE ATT&CK technique coverage visualization

## Logging

**Locations**:
- **User logs**: `~/.medusa/logs/`
- **Application logs**: Console output via Rich
- **Neo4j logs**: Container logs

**Format**: JSON for operation logs, plain text for debug

**Log Levels**:
```python
import logging
logger = logging.getLogger(__name__)

logger.debug("Detailed info")
logger.info("General info")
logger.warning("Warning message")
logger.error("Error occurred")
logger.critical("Critical failure")
```

## Performance Considerations

**LLM Latency**:
- Local Ollama: 1-5 seconds per decision
- OpenAI GPT-4: 2-10 seconds
- Anthropic Claude: 2-8 seconds

**Optimization**:
- Cache LLM responses (future enhancement)
- Parallel tool execution where possible
- Async operations throughout

## Naming Conventions

**Files**: `snake_case.py`
**Classes**: `PascalCase`
**Functions/Methods**: `snake_case()`
**Constants**: `UPPER_SNAKE_CASE`
**Config Keys**: `lowercase_with_underscores`

## Future Enhancements (Roadmap)

- [ ] Multi-agent coordination (multiple MEDUSA instances)
- [ ] Fine-tuned LLM models for pentesting
- [ ] Real-time web dashboard (separate webapp)
- [ ] Plugin system for custom tools
- [ ] Cloud deployment templates (AWS, Azure, GCP)
- [ ] Response caching for LLM queries
- [ ] Streaming LLM responses
- [ ] Additional LLM providers (Mistral API, Cohere)

## Quick Troubleshooting Checklist

**Setup Issues**:
- [ ] Python 3.9+ installed?
- [ ] Dependencies installed? (`pip install -r requirements.txt`)
- [ ] Configuration exists? (`medusa setup`)
- [ ] Ollama running? (`curl http://localhost:11434`)

**Runtime Issues**:
- [ ] Target accessible? (`curl <target_url>`)
- [ ] Neo4j running? (if using world model)
- [ ] Correct permissions? (some tools need sudo)
- [ ] Logs showing errors? (`medusa logs`)

**LLM Issues**:
- [ ] Provider reachable? (`medusa llm verify`)
- [ ] API key valid? (for cloud providers)
- [ ] Model pulled? (`ollama list` for local)
- [ ] Network connectivity? (for cloud providers)

## External Resources

**Ollama Setup**: https://ollama.com/
**OpenAI API**: https://platform.openai.com/
**Anthropic API**: https://console.anthropic.com/
**Neo4j**: https://neo4j.com/
**MITRE ATT&CK**: https://attack.mitre.org/

## When to Use Which File

| Task | Primary Files |
|------|--------------|
| Add new CLI command | `cli.py` |
| Modify core attack logic | `client.py`, `modes/*.py` |
| Add LLM provider | `core/llm/providers/*.py`, `core/llm/factory.py` |
| Add security tool | `tools/*.py` |
| Modify approval logic | `approval.py` |
| Change config structure | `config.py` |
| Customize reports | `reporter.py`, `templates/*.html` |
| Work with graph DB | `world_model/*.py` |
| Add API endpoint | `api/graph_api.py` |
| Fix display issues | `display.py`, `display/progress.py` |

---

## Summary for AI Assistants

When working with MEDUSA CLI:

1. **Understand the role**: MEDUSA is an AI-powered **attacker agent**, not a target system
2. **LLM is central**: All intelligent decisions flow through `core/llm/`
3. **Safety first**: Approval gates prevent destructive actions
4. **Async everywhere**: Use `async/await` for I/O operations
5. **Rich UI**: Use `display` module for user feedback
6. **Tool pattern**: Follow `BaseTool` for new security tools
7. **Graph knowledge**: Neo4j stores discovered infrastructure
8. **Checkpoints**: Long operations can be paused/resumed
9. **MITRE mapping**: All techniques mapped to ATT&CK framework
10. **Educational purpose**: Built for authorized testing and learning

**Most Critical Files**:
- `cli.py` - CLI entry point
- `client.py` - Core logic
- `modes/autonomous.py` - Main attack loop
- `core/llm/` - AI brain
- `tools/base.py` - Tool integration pattern
- `config.py` - Configuration

**Quick Navigation**:
- Commands: `cli.py`
- AI Logic: `core/llm/`
- Attack Modes: `modes/`
- Security Tools: `tools/`
- Reporting: `reporter.py`, `templates/`
- Configuration: `config.py`
- Knowledge Graph: `world_model/`

---

*Last Updated: 2025-11-16*
*MEDUSA CLI Version: 2.0*
*For detailed API docs, see inline docstrings in source files*
