# MEDUSA Project - AI Agent Context

**Quick Context for AI Agents**

## Project Overview
MEDUSA (Multi-Environment Dynamic Unified Security Assessment) is an LLM-powered penetration testing framework designed for educational and ethical security research.

## Key Characteristics
- **Language**: Python (CLI), JavaScript/React (Web), Python (Backend)
- **License**: Apache 2.0
- **Purpose**: Educational security testing with ethical approval gates
- **Architecture**: Modular CLI + Web UI + Docker lab environment

## Entry Points
1. **Main README**: `/README.md` - Project overview and quick navigation
2. **Getting Started**: `/GETTING_STARTED.md` - Fast setup for new users
3. **Documentation Index**: `/docs/INDEX.md` - Master documentation map
4. **File Index**: `/.ai/FILE_INDEX.json` - Machine-readable navigation

## Primary Components
- **medusa-cli**: `/medusa-cli/` - Python CLI tool (main component)
- **medusa-backend**: `/medusa-backend/` - FastAPI backend service
- **medusa-webapp**: `/medusa-webapp/` - React frontend interface
- **lab-environment**: `/lab-environment/` - Docker-based vulnerable infrastructure

## Common Tasks Quick Reference

### Setup Development Environment
1. Read: `/GETTING_STARTED.md`
2. Run: `/scripts/setup-dev.sh` (if available)
3. Check: `/medusa-cli/README.md` for CLI-specific setup

### Understanding Architecture
1. System Overview: `/docs/01-architecture/system-overview.md`
2. Component Design: `/docs/01-architecture/component-design.md`
3. MITRE Mapping: `/docs/01-architecture/mitre-attack-mapping.md`

### Using the CLI
1. CLI Reference: `/docs/04-usage/cli-reference.md`
2. Interactive Shell: `/docs/04-usage/interactive-shell.md`
3. Examples: `/medusa-cli/examples/` or `/docs/04-usage/examples/`

### Deploying Lab Environment
1. Deployment Guide: `/docs/03-deployment/docker-deployment.md`
2. Docker Compose: `/docker-compose.yml`
3. Lab README: `/lab-environment/README.md`

### Running Tests
1. Testing Guide: `/docs/02-development/testing-guide.md`
2. CLI Tests: `/medusa-cli/tests/`
3. Test Scripts: `/scripts/run-tests.sh` (if available)

### Understanding Security Model
1. Security Policy: `/docs/06-security/security-policy.md`
2. Approval Gates: `/docs/06-security/approval-gates.md`
3. Ethical Guidelines: `/docs/06-security/ethical-guidelines.md`

## Documentation Structure
```
/docs/
├── 00-getting-started/    # Installation, setup, troubleshooting
├── 01-architecture/       # System design, diagrams, MITRE mapping
├── 02-development/        # Dev setup, coding standards, testing
├── 03-deployment/         # Deployment guides, Docker, automation
├── 04-usage/              # User guides, CLI reference, examples
├── 05-api-reference/      # API documentation, OpenAPI specs
├── 06-security/           # Security policies, ethical guidelines
├── 07-research/           # Academic papers, LLM integration research
└── 08-project-management/ # Audits, timelines, feedback, QA
```

## Code Locations
- **Python CLI Source**: `/medusa-cli/src/medusa/`
- **Backend Source**: `/medusa-backend/app/`
- **Frontend Source**: `/medusa-webapp/src/`
- **Lab Services**: `/lab-environment/services/`
- **Training Data**: `/training-data/datasets/`
- **Scripts**: `/scripts/`

## Important Files
- **Main CLI Entry**: `/medusa-cli/src/medusa/cli.py`
- **Backend Main**: `/medusa-backend/app/main.py`
- **Docker Compose**: `/docker-compose.yml`
- **Lab Compose**: `/lab-environment/docker-compose.yml`

## Technology Stack
- **CLI**: Python 3.x, Click, Rich (terminal UI)
- **Backend**: FastAPI, Python 3.x
- **Frontend**: React, Vite
- **LLM**: Ollama integration (local LLM)
- **Infrastructure**: Docker, Docker Compose
- **Testing**: pytest, unittest

## Key Concepts
1. **Approval Gates**: Two-tier security system (user + supervisor approval)
2. **MITRE ATT&CK**: Framework mapped to attack techniques
3. **Training Data**: JSON-formatted datasets for LLM fine-tuning
4. **Interactive Shell**: Advanced CLI mode with checkpoints and tab completion
5. **Lab Environment**: Isolated Docker network with vulnerable services

## Navigation Tips for AI Agents
1. Always check `FILE_INDEX.json` first for structured navigation
2. Use `INDEX.md` for documentation discovery
3. Component READMEs provide local context
4. Numbered doc folders indicate reading order
5. Breadcrumbs in docs show hierarchy

## Recent Changes
- 2025-11: Comprehensive audit completed (77 markdown files, 44 Python files)
- 2025-11: Repository reorganization in progress
- 2025-10: Interactive shell modes merged
- 2025-10: Reporting system added

## Getting Help
- **Documentation Issues**: Check `/docs/INDEX.md`
- **Code Issues**: Check component README files
- **Setup Issues**: Check `/GETTING_STARTED.md`
- **GitHub**: Project issues and feedback at repository

---
*Last Updated: 2025-11-06*
*Version: 2.0 (Reorganization)*
