# MEDUSA - AI-Powered Autonomous Penetration Testing Framework

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)]()
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)]()

⚠️ **SECURITY RESEARCH PROJECT - EDUCATIONAL USE ONLY**

## 🎯 Overview

MEDUSA (Multi-Environment Detection and Understanding System for Autonomous testing) is an AI-powered penetration testing framework that combines local and cloud language models with traditional security testing tools. It provides autonomous security assessment through intelligent decision-making in controlled, authorized test environments.

**Key Features:**
- 🤖 **Multi-Agent AI System** - 6 specialized agents (Recon, Analysis, Planning, Exploitation, Reporting, Orchestrator) work together
- ☁️ **AWS Bedrock Integration** - Enterprise-grade Claude 3.5 with smart model routing (60% cost savings)
- 🧠 **Context Fusion Engine** - Combines Neo4j graph + ChromaDB vector database for intelligent decision-making
- 🛡️ **Approval Gates** - Risk-based approval system prevents unintended actions
- 🎮 **Three Modes** - Observe (read-only), Autonomous (AI-driven), Shell (interactive)
- 🐳 **Comprehensive Lab** - 8 vulnerable Docker services for safe testing
- 📊 **Rich Terminal UI** - Beautiful progress indicators and real-time feedback
- 📝 **Detailed Reporting** - JSON logs and HTML reports with MITRE ATT&CK mapping
- 💰 **Cost Tracking** - Real-time LLM usage and cost monitoring per operation
- 🔄 **Multi-Provider Support** - AWS Bedrock (primary), Local Ollama, OpenAI, Anthropic

## ⚡ Quick Start

### Option 1: Docker Lab (Recommended)

Get the full vulnerable environment running in 3 commands:

```bash
cd lab-environment
cp .env.example .env
docker-compose up -d
```

**Access Services:**
- 🌐 EHR Web Portal: http://localhost:8080
- 📊 API Documentation: http://localhost:3000/api/docs
- 🔍 Log Viewer: http://localhost:8081

See [Docker Quick Start](docs/getting-started/QUICK_START_DOCKER.md) for full guide.

### Option 2: CLI Agent

Install just the MEDUSA AI agent:

```bash
cd medusa-cli
bash ../scripts/install.sh  # Automated setup with PATH configuration
```

After installation:

```bash
medusa setup      # Run setup wizard
medusa --help     # View help
medusa shell      # Start interactive mode
```

### Option 3: API Server (For Web Dashboard)

Start the REST API server to power the web dashboard:

```bash
./start_medusa_api.sh
```

The API will be available at `http://localhost:5001`.

**📚 See [QUICKSTART.md](docs/QUICKSTART.md)** for a complete setup guide with examples.

## 🧠 AI Brain Setup

MEDUSA uses AI for intelligent decision-making during penetration tests. Choose from enterprise cloud or local options:

### Option 1: AWS Bedrock (Recommended for Production) ☁️

**Enterprise-grade, cost-optimized, automatic smart routing.**

```bash
# Configure AWS credentials
aws configure
# Enter your access key, secret key, and region (us-west-2 recommended)

# Set MEDUSA to use Bedrock
export LLM_PROVIDER=bedrock

# Verify setup
medusa llm verify

# Run your first assessment
medusa agent run scanme.nmap.org --type recon_only
```

**Benefits:**
- ✅ **Smart model routing** - Automatically uses Haiku (cheap) or Sonnet (smart) based on task
- ✅ **60% cost savings** - Typical operation: $0.20-0.30 vs $0.60-0.80
- ✅ **Real-time cost tracking** - See exactly what you're spending
- ✅ **No rate limits** - Higher throughput than API providers
- ✅ **Enterprise reliability** - AWS infrastructure with 99.9% uptime

**Typical Costs:**
- Reconnaissance scan: $0.05-0.10
- Vulnerability assessment: $0.15-0.25
- Full security assessment: $0.20-0.30

📚 **[Full AWS Bedrock Setup Guide](docs/00-getting-started/bedrock-setup.md)**

### Option 2: Local LLM (Air-Gapped / Offline) 🔒

**Unlimited usage, zero cost, complete privacy.**

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull AI model
ollama pull mistral:7b-instruct

# MEDUSA will auto-detect and use local LLM
export LLM_PROVIDER=local
medusa agent run scanme.nmap.org --type recon_only
```

**Benefits:**
- ✅ Zero ongoing costs (free forever)
- ✅ Complete data privacy (runs offline)
- ✅ No rate limits or quotas
- ✅ Air-gap compatible

**Requirements:**
- 8GB+ RAM (16GB recommended)
- ~4GB storage for model

📚 **[Full Ollama Setup Guide](docs/00-getting-started/llm-quickstart.md)**

### Option 3: Direct API Providers (Advanced)

**For specific use cases or custom deployments.**

```bash
# OpenAI (GPT-4)
export CLOUD_API_KEY="sk-..."
export LLM_PROVIDER="openai"

# Or Anthropic (Claude API)
export CLOUD_API_KEY="sk-ant-..."
export LLM_PROVIDER="anthropic"
```

⚠️ **Note:** Direct API providers have rate limits and higher costs than Bedrock. Bedrock provides the same models with better pricing and enterprise features.

### Configuration

Set your preferred provider in `~/.medusa/config.yaml`:

```yaml
llm:
  provider: bedrock  # Options: bedrock, local, openai, anthropic, auto

  # AWS Bedrock configuration (recommended)
  aws_region: us-west-2
  smart_model: anthropic.claude-3-5-sonnet-20241022-v2:0  # For planning, reporting
  fast_model: anthropic.claude-3-5-haiku-20241022-v1:0    # For tool execution

  # Local Ollama configuration (fallback)
  model: mistral:7b-instruct
  ollama_url: http://localhost:11434

  temperature: 0.7
  timeout: 60
```

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8GB | 16GB+ |
| Storage | 10GB | 20GB+ |
| GPU | None | NVIDIA/AMD (optional, for speed) |
| Internet | Optional (local) | Yes (for AWS Bedrock) |

**Performance:**
- AWS Bedrock: 2-5s per AI decision (cloud)
- Local with GPU: 5-10s per AI decision
- Local CPU only: 10-30s per AI decision
- All options faster than manual analysis!

## 🏗️ Architecture

### Multi-Agent System

MEDUSA uses a **6-agent architecture** coordinated by an Orchestrator:

```
┌────────────────────────────────────────────────────────────────┐
│                    MEDUSA ORCHESTRATION LAYER                  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Orchestrator Agent (Supervisor)                │  │
│  │         Model: Claude 4.5 Sonnet (Bedrock)               │  │
│  └──────────────┬───────────────────────────────────────────┘  │
│                 │                                              │
│       ┌─────────┼─────────────┬──────────────┐                 │
│       │         │             │              │                 │
│       ▼         ▼             ▼              ▼                 │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐             │
│  │ Recon   │ │ Vuln    │ │ Exploit  │ │ Planning │             │
│  │ Agent   │ │ Analysis│ │ Agent    │ │ Agent    │             │
│  │ (Haiku) │ │ (Haiku) │ │ (Haiku)  │ │ (Sonnet) │             │
│  └────┬────┘ └────┬────┘ └─────┬────┘ └────┬─────┘             │
│       │           │            │           │                   │
│       └───────────┼────────────┼───────────┘                   │
│                   │            │                               │
│                   ▼            ▼                               │
│       ┌────────────────────────────────────┐                   │
│       │    Context Fusion Engine           │                   │
│       │  ┌──────────────┐  ┌─────────────┐ │                   │
│       │  │ Vector Store │  │  Neo4j      │ │                   │
│       │  │  (ChromaDB)  │  │  Graph DB   │ │                   │
│       │  │ • MITRE      │  │ • Hosts     │ │                   │
│       │  │ • CVEs       │  │ • Vulns     │ │                   │
│       │  │ • Tool Docs  │  │ • Ports     │ │                   │
│       │  └──────────────┘  └─────────────┘ │                   │
│       └────────────────────────────────────┘                   │
└────────────────────────────────────────────────────────────────┘
```

**Key Components:**
- **6 Specialized Agents**: Reconnaissance, Vulnerability Analysis, Planning, Exploitation, Reporting, Orchestrator
- **Smart Model Routing**: Automatically uses Claude Haiku (cheap) or Sonnet (smart) based on task complexity
- **Context Fusion**: Combines Neo4j graph (infrastructure state) + ChromaDB vector (MITRE/CVE knowledge)
- **Cost Optimization**: 60-70% cost savings through intelligent model selection

📚 **[Multi-Agent Architecture Guide](docs/01-architecture/multi-agent-evolution-plan.md)**

## 📦 Project Structure

```
project-medusa/
├── MEDUSA AI Agent (Attacker)
│   ├── medusa-cli/          # 🤖 Python AI penetration testing agent
│   └── training-data/       # 📚 LLM training datasets (MITRE ATT&CK)
│
├── MedCare EHR System (Target)
│   └── lab-environment/     # 🐳 Vulnerable infrastructure
│       ├── services/
│       │   ├── ehr-webapp-medcare/  # Vulnerable Next.js web frontend
│       │   ├── ehr-api/             # Vulnerable backend API
│       │   ├── ehr-database/        # MySQL database
│       │   ├── ldap-server/         # LDAP service
│       │   ├── ssh-server/          # SSH server with weak credentials
│       │   ├── ftp-server/          # FTP server
│       │   ├── log-collector/       # Centralized logging
│       │   └── workstation/         # Windows simulation
│       └── docker-compose.yml
│
├── docs/                    # 📖 Documentation
├── scripts/                 # 🛠️ Automation scripts
├── neo4j-schema/            # 🕸️ Graph database schema
└── archive/                 # 📦 Deprecated components
```

### Core Components

| Component | Type | Description | Location | Tech Stack |
|-----------|------|-------------|----------|------------|
| **medusa-cli** | Attacker | AI-powered autonomous agent | `medusa-cli/` | Python 3.9+, Typer, Rich, LLM |
| **training-data** | Attacker | MITRE ATT&CK training datasets | `training-data/` | JSON datasets |
| **ehr-webapp-medcare** | Target | Vulnerable EHR frontend | `lab-environment/services/` | Next.js, React, TypeScript |
| **ehr-api** | Target | Vulnerable backend API | `lab-environment/services/` | Node.js, Express, MySQL |
| **ehr-database** | Target | MySQL with intentional vulnerabilities | `lab-environment/services/` | MySQL 8.0 |
| **lab-environment** | Target | 8 Docker services + orchestration | `lab-environment/` | Docker Compose |
| **neo4j-schema** | Supporting | Graph database for attack mapping | `neo4j-schema/` | Neo4j, Cypher |

## 🎮 Usage Examples

### Multi-Agent Security Assessment

```bash
# Full security assessment with all 6 agents
medusa agent run http://target.com

# Reconnaissance only (fast, safe)
medusa agent run target.com --type recon_only

# Vulnerability scan with analysis
medusa agent run target.com --type vuln_scan

# Check operation status and costs
medusa agent status --verbose

# Generate comprehensive report
medusa agent report --type technical --format html
```

### Classic Single-Agent Modes

```bash
# Observe Mode (Safe, Read-Only)
medusa observe --target localhost --port 8080

# Autonomous Mode (AI-Driven with Approval)
medusa autonomous --target localhost --approve-low

# Interactive Shell Mode
medusa shell --target localhost
```

**Cost Examples:**
- Reconnaissance scan: ~$0.05-0.10
- Vulnerability assessment: ~$0.15-0.25
- Full multi-agent assessment: ~$0.20-0.30

📚 **[Complete Usage Guide](medusa-cli/README.md)**

## 🎯 MITRE ATT&CK Coverage

MEDUSA tests **32+ techniques** across **8 tactics**:

- ✅ Initial Access (3 techniques)
- ✅ Execution (4 techniques)
- ✅ Persistence (3 techniques)
- ✅ Privilege Escalation (4 techniques)
- ✅ Defense Evasion (4 techniques)
- ✅ Credential Access (5 techniques)
- ✅ Discovery (5 techniques)
- ✅ Collection (4 techniques)

See [MITRE ATT&CK Mapping](docs/architecture/MITRE_ATTACK_MAPPING.md) for complete details.

## 🔒 Security & Legal

### ⚠️ Important Disclaimers

**Educational Purpose Only** - This project contains intentional security vulnerabilities for:
- Academic security research
- Authorized penetration testing practice
- Defensive security strategy development
- Cybersecurity education and training

**Prohibited Uses:**
- ❌ Unauthorized system access
- ❌ Malicious activities
- ❌ Real-world attacks without explicit permission
- ❌ Any illegal activities

**Legal Compliance:** Users are responsible for ensuring compliance with all applicable laws including Computer Fraud and Abuse Act (CFAA), HIPAA, GDPR, and local regulations.

See [SECURITY.md](docs/SECURITY.md) for complete security policy and legal information.

## 📚 Documentation

### Essential Reading
- 📖 [Documentation Index](docs/README.md) - Start here for all documentation
- 🏗️ [Architecture](docs/ARCHITECTURE.md) - System design and components
- 🚀 [Deployment Guide](docs/DEPLOYMENT.md) - Installation and configuration
- 🛠️ [Development Guide](docs/DEVELOPMENT.md) - Contributing and development setup
- 🔒 [Security Policy](docs/SECURITY.md) - Critical security information

### Getting Started
- ⚡ [Quick Start (CLI)](docs/getting-started/QUICK_START.md)
- 🐳 [Quick Start (Docker)](docs/getting-started/QUICK_START_DOCKER.md)

### Technical Details
- 🌐 [Network Architecture](docs/architecture/NETWORK_ARCHITECTURE.md)
- 🎯 [MITRE ATT&CK Mapping](docs/architecture/MITRE_ATTACK_MAPPING.md)

### Component Documentation

**MEDUSA AI Agent (Attacker)**:
- [medusa-cli README](medusa-cli/README.md) - AI penetration testing agent
- [training-data README](training-data/README.md) - LLM training datasets

**MedCare EHR System (Target)**:
- [lab-environment README](lab-environment/README.md) - Vulnerable infrastructure setup
- [ehr-webapp-medcare README](lab-environment/services/ehr-webapp-medcare/README.md) - MedCare EHR web frontend
- [MedCare EHR Backend Plan](docs/05-api-reference/medcare-ehr-backend-implementation-plan.md) - EHR API documentation

## 🛠️ Development

### Prerequisites
- Python 3.9+
- Node.js 18+
- Docker Desktop 20.10+
- AWS Account (for Bedrock) OR Ollama (for local LLM)

### Setup Development Environment

```bash
# Clone repository
git clone <repository-url>
cd project-medusa

# Run setup script
./scripts/setup-dev.sh

# Start Docker lab
cd lab-environment && docker-compose up -d

# Install CLI
cd ../medusa-cli && pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

See [Development Guide](docs/DEVELOPMENT.md) for complete setup instructions.

### Running Tests

```bash
# CLI tests
cd medusa-cli
pytest --cov=medusa --cov-report=html

# Lab environment tests
cd lab-environment
docker-compose up -d
./verify.sh
```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Read the Docs** - Review [Development Guide](docs/DEVELOPMENT.md)
2. **Fork Repository** - Create your feature branch
3. **Make Changes** - Follow coding standards
4. **Add Tests** - Ensure test coverage
5. **Update Docs** - Document new features
6. **Submit PR** - Create pull request with clear description

### Contribution Guidelines
- Follow [Conventional Commits](https://www.conventionalcommits.org/)
- Write tests for new features
- Update documentation
- Maintain security best practices

## 📊 Project Status

| Component | Status | Test Coverage | Documentation |
|-----------|--------|---------------|---------------|
| Multi-Agent System | ✅ Stable | 85%+ | ✅ Complete |
| AWS Bedrock Integration | ✅ Production | 90%+ | ✅ Complete |
| Context Fusion Engine | ✅ Stable | 80%+ | ✅ Complete |
| CLI Agent | ✅ Stable | 80%+ | ✅ Complete |
| Lab Environment | ✅ Stable | N/A | ✅ Complete |
| Vector Database (ChromaDB) | ✅ Stable | 75%+ | ✅ Complete |
| Graph Database (Neo4j) | ✅ Stable | 70%+ | ✅ Complete |

## 🎓 Educational Use Cases

MEDUSA is designed for:
- **University Courses** - Cybersecurity curriculum
- **Security Certifications** - CEH, OSCP, GPEN preparation
- **Red Team Training** - Attack simulation practice
- **Blue Team Training** - Detection and response
- **CTF Competitions** - Capture the Flag events
- **Research Projects** - AI in cybersecurity research

## 🏆 Features

### Multi-Agent AI System
- **6 specialized agents** work together: Recon, Analysis, Planning, Exploitation, Reporting, Orchestrator
- **AWS Bedrock integration** with Claude 3.5 Sonnet and Haiku
- **Smart model routing** - Automatically selects optimal model (60% cost savings)
- **Context fusion** - Combines graph + vector databases for intelligent decisions
- **Real-time cost tracking** - Monitor LLM usage and costs per operation

### Approval Gates
- Risk-based approval system (LOW, MEDIUM, HIGH, CRITICAL)
- Configurable auto-approval policies
- Human-in-the-loop for high-risk actions
- Audit trail of all decisions

### Lab Environment
- 8 vulnerable services with realistic scenarios
- Network segmentation (DMZ + Internal)
- Comprehensive logging and monitoring
- Easy reset and cleanup

### Reporting
- HTML reports with visualizations
- JSON structured data
- MITRE ATT&CK technique coverage
- Timeline of activities

## 📈 Roadmap

### Phase 1 (✅ Complete)
- ✅ Docker lab environment
- ✅ CLI with basic operations
- ✅ LLM integration (AWS Bedrock, Ollama)
- ✅ Approval gates system
- ✅ Comprehensive documentation

### Phase 2 (✅ Complete)
- ✅ Multi-agent coordination system
- ✅ AWS Bedrock integration with smart routing
- ✅ Context Fusion Engine (Graph + Vector DB)
- ✅ Real-time cost tracking
- ✅ Enhanced multi-format reporting

### Phase 3 (🔄 In Progress)
- 🔄 Advanced agent orchestration patterns
- 🔄 Custom agent training and fine-tuning
- 🔄 Real-time web dashboard
- 🔄 Additional vector database sources
- 📋 Plugin system for custom tools

### Phase 4 (📋 Planned)
- 📋 Collaborative multi-user operations
- 📋 Cloud deployment templates (AWS, Azure, GCP)
- 📋 Enterprise SSO integration
- 📋 Advanced compliance reporting

## 🙏 Acknowledgments

MEDUSA is inspired by:
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [DVWA](https://github.com/digininja/DVWA)
- [Metasploitable](https://github.com/rapid7/metasploitable3)
- [VulnHub](https://www.vulnhub.com/)

Built with:
- [AWS Bedrock](https://aws.amazon.com/bedrock/) - Enterprise AI (Claude 3.5)
- [ChromaDB](https://www.trychroma.com/) - Vector database
- [Neo4j](https://neo4j.com/) - Graph database
- [Ollama](https://ollama.com/) - Local LLM runtime
- [Typer](https://typer.tiangolo.com/) - CLI framework
- [Rich](https://rich.readthedocs.io/) - Terminal UI
- [FastAPI](https://fastapi.tiangolo.com/) - Backend API
- [Next.js](https://nextjs.org/) - Frontend framework
- [Docker](https://www.docker.com/) - Containerization

## 📄 License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## ⚖️ Legal Disclaimer

**THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

Users are solely responsible for:
- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Any consequences of misuse

The authors and contributors disclaim all liability for misuse of this educational material.

## 📞 Contact & Support

- **Documentation**: [docs/](docs/)
- **Issues**: GitHub Issues
- **Security**: project-medusa-security@[domain]
- **Discussions**: GitHub Discussions

---

**Use Responsibly. Test Ethically. Learn Continuously.**

**Last Updated:** November 15, 2025
**Version:** 2.1 (Multi-Agent + AWS Bedrock)
**Maintained by:** Project MEDUSA Team
