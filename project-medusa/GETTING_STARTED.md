# Getting Started with MEDUSA

**Quick setup guide to get MEDUSA up and running in minutes.**

> **Navigation**: [Home](README.md) → Getting Started | [Full Documentation](docs/INDEX.md)

---

## Welcome to MEDUSA!

This guide will help you set up MEDUSA (Multi-Environment Detection and Understanding System for Autonomous testing) - an AI-powered penetration testing framework for educational use.

### What You'll Learn
1. System requirements and prerequisites
2. Installation options (Docker Lab or CLI only)
3. LLM setup (Local Ollama or Google Gemini)
4. First test run
5. Next steps and learning resources

**Estimated Time**: 15-30 minutes

---

## Prerequisites

### Required Software
- **Python 3.9+** - [Download Python](https://www.python.org/downloads/)
- **Docker Desktop 20.10+** - [Download Docker](https://www.docker.com/products/docker-desktop/)
- **Git** - [Download Git](https://git-scm.com/downloads)

### LLM Provider (Choose One)
- **AWS Bedrock** (recommended for production) - [AWS Account](https://aws.amazon.com/free/)
- **Ollama** (recommended for offline/local) - [Install Ollama](https://ollama.com/download)

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 8GB | 16GB+ |
| **Storage** | 10GB free | 20GB+ free |
| **CPU** | 4 cores | 8+ cores |
| **GPU** | None (optional) | NVIDIA/AMD for faster local LLM |
| **Internet** | Optional (local only) | Required (for AWS Bedrock) |

---

## Installation Options

Choose your preferred setup path:

### Option A: Full Lab Environment (Recommended for Learning)
**Best for**: Students, researchers, comprehensive testing
- ✅ Complete vulnerable infrastructure
- ✅ 8 pre-configured Docker services
- ✅ Realistic healthcare scenario
- ✅ Safe, isolated environment

[Jump to Lab Setup](#option-a-full-lab-setup)

### Option B: CLI Only (Lightweight)
**Best for**: Quick tests, external targets, minimal setup
- ✅ Faster installation
- ✅ Less disk space required
- ✅ Test external authorized targets
- ✅ Portable setup

[Jump to CLI Setup](#option-b-cli-only-setup)

---

## Option A: Full Lab Setup

### Step 1: Clone Repository

```bash
# Clone the repository
git clone https://github.com/your-org/project-medusa.git
cd project-medusa
```

### Step 2: Set Up Lab Environment

```bash
# Navigate to lab environment
cd lab-environment

# Copy environment template
cp .env.example .env

# Start all services (this may take 5-10 minutes on first run)
docker-compose up -d

# Verify all services are running
docker-compose ps
```

**Expected Output**: All services should show "Up" status.

### Step 3: Verify Lab Services

Access these URLs to confirm services are running:

- 🌐 **EHR Web Portal**: http://localhost:8080
- 📊 **API Documentation**: http://localhost:3000/api/docs
- 🔍 **Log Viewer**: http://localhost:8081

### Step 4: Install MEDUSA CLI

```bash
# Return to project root
cd ..

# Navigate to CLI directory
cd medusa-cli

# Install in development mode
pip install -e .

# Verify installation
medusa --version
```

### Step 5: Configure LLM Provider

MEDUSA supports multiple LLM providers. Choose based on your needs:

#### Option A: AWS Bedrock (Recommended for Production) ☁️

**Best for:** Production use, enterprise deployments, cost-optimized operations

```bash
# 1. Install and configure AWS CLI
pip install awscli
aws configure
# Enter: Access Key ID, Secret Access Key, Region (us-west-2 recommended)

# 2. Request model access (one-time setup)
# Go to AWS Console → Bedrock → Model access
# Enable: Claude 3.5 Sonnet and Claude 3.5 Haiku

# 3. Set MEDUSA to use Bedrock
export LLM_PROVIDER=bedrock

# 4. Verify connection
medusa llm verify
```

**Cost Information:**
- Reconnaissance scan: ~$0.05-0.10
- Vulnerability assessment: ~$0.15-0.25
- Full security assessment: ~$0.20-0.30
- Smart routing saves 60% vs using only Sonnet

📚 **[Complete Bedrock Setup Guide](docs/00-getting-started/bedrock-setup.md)**

#### Option B: Local LLM with Ollama (Recommended for Offline) 🔒

**Best for:** Air-gapped environments, learning, unlimited testing

```bash
# Install Ollama (if not already installed)
curl -fsSL https://ollama.com/install.sh | sh

# Pull the AI model (mistral 7B)
ollama pull mistral:7b-instruct

# Verify Ollama is running
curl http://localhost:11434/api/tags
```

**Benefits**:
- ✅ Zero ongoing costs (free forever)
- ✅ Complete privacy (runs offline)
- ✅ No rate limits or quotas
- ✅ Air-gap compatible
- ✅ No cloud account needed

📚 **[Complete Ollama Setup Guide](docs/00-getting-started/llm-quickstart.md)**

#### Option C: Direct API Providers (Advanced)

**For specific use cases only**

```bash
# OpenAI
export CLOUD_API_KEY="sk-..."
export LLM_PROVIDER="openai"

# Anthropic
export CLOUD_API_KEY="sk-ant-..."
export LLM_PROVIDER="anthropic"
```

⚠️ **Note**: Direct API providers have higher costs and rate limits. AWS Bedrock provides better pricing for the same models.

### Step 6: Configure MEDUSA

Create configuration file:

```bash
# Create config directory
mkdir -p ~/.medusa

# Create config file
cat > ~/.medusa/config.yaml << 'EOF'
llm:
  # Primary provider (bedrock, local, openai, anthropic, auto)
  provider: bedrock

  # AWS Bedrock configuration
  aws_region: us-west-2
  smart_model: anthropic.claude-3-5-sonnet-20241022-v2:0  # For planning
  fast_model: anthropic.claude-3-5-haiku-20241022-v1:0    # For execution

  # Local Ollama fallback
  model: mistral:7b-instruct
  ollama_url: http://localhost:11434

  temperature: 0.7
  timeout: 60

approval:
  auto_approve_low: false
  auto_approve_medium: false
  require_supervisor: true

logging:
  level: INFO
  format: rich
  output_dir: ~/.medusa/logs
EOF
```

**For local-only setup**, change `provider: bedrock` to `provider: local`

### Step 7: Index Knowledge Bases (Multi-Agent Mode)

**Required for multi-agent operations** - Skip if using single-agent mode only

```bash
cd medusa-cli

# Index MITRE ATT&CK framework (~5 minutes)
python scripts/index_mitre_attack.py

# Index security tool documentation (~2 minutes)
python scripts/index_tool_docs.py

# Index CVE database (~3 minutes)
python scripts/index_cves.py

# Verify indexing
python -c "from medusa.context.vector_store import VectorStore; vs = VectorStore(); print(vs.get_stats())"
```

**Expected output**: Should show 200+ MITRE techniques, 100+ CVEs, and tool docs indexed.

### Step 8: First Test Run

```bash
# Multi-agent assessment (uses all 6 agents)
medusa agent run scanme.nmap.org --type recon_only

# OR single-agent observe mode (safe, read-only)
medusa observe --target scanme.nmap.org

# Expected: MEDUSA performs reconnaissance and provides AI analysis
```

**Success!** If you see AI-generated analysis and recommendations, MEDUSA is working correctly.

---

## Option B: CLI Only Setup

### Step 1: Clone and Install

```bash
# Clone repository
git clone https://github.com/your-org/project-medusa.git
cd project-medusa/medusa-cli

# Install CLI
pip install -e .

# Verify installation
medusa --version
```

### Step 2: Configure LLM

Follow [Step 5 from Lab Setup](#step-5-configure-llm) to set up either Ollama or Gemini.

### Step 3: Create Configuration

```bash
# Create config directory
mkdir -p ~/.medusa

# Create minimal config
cat > ~/.medusa/config.yaml << 'EOF'
llm:
  provider: auto
  model: mistral:7b-instruct
  temperature: 0.7
  timeout: 60

logging:
  level: INFO
  format: rich
EOF
```

### Step 4: Index Knowledge Bases (Optional for Multi-Agent)

If you want to use multi-agent features:

```bash
cd medusa-cli
python scripts/index_mitre_attack.py
python scripts/index_tool_docs.py
python scripts/index_cves.py
```

### Step 5: Test with External Target

```bash
# Multi-agent mode
medusa agent run scanme.nmap.org --type recon_only

# OR single-agent observe mode
medusa observe --target scanme.nmap.org

# Expected: MEDUSA performs reconnaissance and provides AI analysis
```

---

## Understanding MEDUSA Modes

MEDUSA supports two operational paradigms:

### Multi-Agent Mode (Recommended) 🤖

**6 specialized agents work together** - Modern, production-ready

```bash
# Full assessment with all agents
medusa agent run http://target.com

# Reconnaissance only
medusa agent run target.com --type recon_only

# Vulnerability scan
medusa agent run target.com --type vuln_scan

# Check status and costs
medusa agent status --verbose

# Generate report
medusa agent report --type technical
```

**Features**:
- ✅ Specialized agents (Recon, Analysis, Planning, Exploitation, Reporting, Orchestrator)
- ✅ Smart model routing (60% cost savings with Bedrock)
- ✅ Context fusion (graph + vector databases)
- ✅ Real-time cost tracking
- ✅ Comprehensive multi-format reports

**Use Cases**:
- Production security assessments
- Comprehensive vulnerability analysis
- Cost-optimized operations
- Enterprise deployments

### Single-Agent Classic Modes 💻

**Legacy modes** - Simple, quick operations

#### 1. Observe Mode (Read-Only) 🔍
```bash
medusa observe --target localhost --port 8080
```
Safe for learning - No actions executed

#### 2. Autonomous Mode (AI-Driven) 🤖
```bash
medusa autonomous --target localhost --approve-low
```
AI makes decisions with approval gates

#### 3. Shell Mode (Interactive) 💻
```bash
medusa shell --target localhost
```
Interactive command execution with AI

**Use Cases**:
- Quick reconnaissance
- Learning MEDUSA basics
- Simple manual testing

---

## Your First Security Test

Let's run a complete multi-agent assessment:

### Step 1: Reconnaissance (Multi-Agent Mode)

```bash
# Run multi-agent reconnaissance
medusa agent run scanme.nmap.org --type recon_only
```

**What happens**:
1. Orchestrator agent coordinates the operation
2. Recon agent performs discovery and enumeration
3. Vulnerability Analysis agent correlates with CVE database
4. Planning agent suggests next steps
5. Reporting agent generates comprehensive report

**Expected duration**: 2-5 minutes
**Expected cost (Bedrock)**: $0.05-0.10

### Step 2: Review Real-Time Status

```bash
# Check operation status
medusa agent status

# View detailed metrics
medusa agent status --verbose
```

**What to look for**:
- Agent task completion status
- Token usage and costs
- Findings discovered
- Execution time per agent

### Step 3: Full Assessment (Optional)

```bash
# Complete security assessment on lab environment
medusa agent run http://localhost:8080 --type full_assessment
```

**Note**: This includes exploitation simulation. Only use on authorized targets!

**Expected duration**: 5-15 minutes
**Expected cost (Bedrock)**: $0.20-0.30

### Step 4: Generate Reports

```bash
# Executive summary (for management)
medusa agent report --type executive --output exec-summary.md

# Technical report (for security team)
medusa agent report --type technical --format html --output assessment.html

# Remediation plan (for DevOps)
medusa agent report --type remediation --output fixes.md
```

### Step 5: Review Costs (Bedrock Only)

```bash
# View cost breakdown
medusa agent status --verbose | grep -A 10 "Cost"

# Expected output:
# Total Cost: $0.23
# - Orchestrator: $0.05
# - Recon Agent: $0.03
# - Vuln Analysis: $0.04
# - Planning Agent: $0.08
# - Reporting: $0.03
```

---

## Troubleshooting

### Common Issues

#### "medusa: command not found"
```bash
# Ensure Python's bin directory is in PATH
export PATH="$HOME/.local/bin:$PATH"

# Or reinstall with system-wide access
sudo pip install -e .
```

#### "Ollama connection failed"
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama service
systemctl start ollama  # Linux
# or
brew services start ollama  # macOS
```

#### "Docker services won't start"
```bash
# Check Docker is running
docker ps

# View service logs
cd lab-environment
docker-compose logs -f

# Reset and restart
docker-compose down
docker-compose up -d --force-recreate
```

#### "Vector database empty" or "No MITRE techniques found"
```bash
# Run indexing scripts
cd medusa-cli
python scripts/index_mitre_attack.py
python scripts/index_tool_docs.py
python scripts/index_cves.py

# Verify
python -c "from medusa.context.vector_store import VectorStore; vs = VectorStore(); print(vs.get_stats())"
```

#### "AWS Bedrock connection failed"
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check model access (AWS Console → Bedrock → Model access)
# Ensure Claude 3.5 Sonnet and Haiku are enabled

# Test connection
medusa llm verify
```

### Getting Help

- **Documentation**: [docs/INDEX.md](docs/INDEX.md)
- **Troubleshooting Guide**: [docs/00-getting-started/troubleshooting.md](docs/00-getting-started/troubleshooting.md)
- **CLI Help**: `medusa --help`
- **Component Docs**:
  - [CLI Documentation](medusa-cli/README.md)
  - [Lab Documentation](lab-environment/README.md)

---

## Next Steps

### Learn More
1. **[CLI Reference](docs/04-usage/cli-reference.md)** - Complete CLI command documentation
2. **[Architecture Overview](docs/01-architecture/system-overview.md)** - Understand MEDUSA's design
3. **[Interactive Shell Guide](docs/04-usage/interactive-shell.md)** - Advanced CLI features
4. **[MITRE ATT&CK Mapping](docs/01-architecture/mitre-attack-mapping.md)** - Security framework coverage

### Advanced Topics
- **[LLM Fine-Tuning](docs/OLLAMA_FINE_TUNING.md)** - Customize AI behavior
- **[Development Guide](docs/02-development/development-setup.md)** - Contribute to MEDUSA
- **[Deployment Guide](docs/03-deployment/deployment-guide.md)** - Production deployment
- **[Security Policy](docs/06-security/security-policy.md)** - Ethical usage guidelines

### Practice Scenarios

1. **Web Application Testing**
   ```bash
   medusa autonomous --target localhost:8080 --mode web-app
   ```

2. **Network Reconnaissance**
   ```bash
   medusa observe --target localhost --scan-network
   ```

3. **API Security Testing**
   ```bash
   medusa autonomous --target localhost:3000 --mode api
   ```

---

## Best Practices

### ⚠️ Security and Ethics

**Always Remember**:
- ✅ Only test authorized systems (your lab or explicitly permitted targets)
- ✅ Review approval gates before granting permissions
- ✅ Keep detailed logs for accountability
- ✅ Follow responsible disclosure for real vulnerabilities

**Never**:
- ❌ Test production systems without written authorization
- ❌ Bypass approval gates for convenience
- ❌ Use MEDUSA for malicious purposes
- ❌ Share credentials or sensitive data discovered during tests

See [Security Policy](docs/06-security/security-policy.md) for complete guidelines.

### Performance Tips

1. **Use Local LLM for Heavy Testing**
   - No rate limits
   - Consistent performance
   - Privacy-preserving

2. **Start with Observe Mode**
   - Understand scope before acting
   - Review AI suggestions
   - Build confidence gradually

3. **Monitor Resource Usage**
   ```bash
   # Check Docker resource usage
   docker stats

   # Check Ollama memory usage
   ps aux | grep ollama
   ```

---

## Quick Reference Card

### Essential Commands

```bash
# Observe (safe, no actions)
medusa observe --target <host>

# Autonomous with approval
medusa autonomous --target <host> --approve-low

# Interactive shell
medusa shell --target <host>

# View help
medusa --help

# Check configuration
medusa config --show

# View logs
medusa logs --tail

# Generate report
medusa report --output html
```

### Configuration Locations

- **Config file**: `~/.medusa/config.yaml`
- **Logs**: `~/.medusa/logs/`
- **Reports**: `~/.medusa/reports/`
- **Lab environment**: `lab-environment/`

### Service URLs (Lab)

- EHR Portal: http://localhost:8080
- API Docs: http://localhost:3000/api/docs
- Log Viewer: http://localhost:8081

---

## Support and Community

### Documentation
- **Main Index**: [docs/INDEX.md](docs/INDEX.md)
- **AI Agent Context**: [.ai/CONTEXT.md](.ai/CONTEXT.md)
- **Quick Reference**: [.ai/QUICK_REFERENCE.md](.ai/QUICK_REFERENCE.md)

### Issues and Feedback
- Report bugs via GitHub Issues
- Suggest features via GitHub Discussions
- Security issues: project-medusa-security@[domain]

### Contributing
Interested in contributing? See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## License and Legal

**License**: Apache 2.0 - See [LICENSE](LICENSE)

**Legal Disclaimer**: MEDUSA is for educational and authorized testing only. Users are solely responsible for:
- Obtaining proper authorization before testing
- Complying with all applicable laws (CFAA, GDPR, HIPAA, etc.)
- Any consequences of misuse

See [LICENSE](LICENSE) for complete terms.

---

**Congratulations!** You're now ready to use MEDUSA for security research and education.

**Remember**: Use responsibly. Test ethically. Learn continuously.

---

**Last Updated**: 2025-11-15
**Version**: 2.1 (Multi-Agent + AWS Bedrock)
**Maintained by**: Project MEDUSA Team

**Questions?** Check the [Documentation Index](docs/INDEX.md) or open a GitHub Issue.

---

## Quick Command Reference

### Multi-Agent Operations
```bash
medusa agent run <target>                    # Full assessment
medusa agent run <target> --type recon_only  # Reconnaissance
medusa agent status                          # Check status
medusa agent report --type technical         # Generate report
medusa llm verify                            # Test LLM connection
```

### Single-Agent Operations
```bash
medusa observe <target>                      # Read-only mode
medusa autonomous <target>                   # AI-driven mode
medusa shell                                 # Interactive shell
```

### Knowledge Base Management
```bash
python scripts/index_mitre_attack.py         # Index MITRE ATT&CK
python scripts/index_tool_docs.py            # Index tool docs
python scripts/index_cves.py                 # Index CVEs
```
