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

### Optional but Recommended
- **Ollama** (for local LLM) - [Install Ollama](https://ollama.com/download)
- **Google Gemini API Key** (alternative to Ollama) - [Get API Key](https://ai.google.dev/)

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 8GB | 16GB+ |
| **Storage** | 10GB free | 20GB+ free |
| **CPU** | 4 cores | 8+ cores |
| **GPU** | None (optional) | NVIDIA/AMD for faster LLM |
| **Internet** | Not required | For Gemini API only |

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

### Step 5: Configure LLM

Choose between Local LLM (recommended) or Google Gemini:

#### Option 1: Local LLM with Ollama (Recommended)

```bash
# Install Ollama (if not already installed)
curl -fsSL https://ollama.com/install.sh | sh

# Pull the AI model (mistral 7B)
ollama pull mistral:7b-instruct

# Verify Ollama is running
curl http://localhost:11434/api/tags
```

**Benefits**:
- ✅ Unlimited usage, no rate limits
- ✅ Complete privacy (runs offline)
- ✅ Zero ongoing costs
- ✅ Predictable performance

#### Option 2: Google Gemini API

```bash
# Set your API key as environment variable
export GEMINI_API_KEY="your-api-key-here"

# Or add to your shell profile (~/.bashrc, ~/.zshrc)
echo 'export GEMINI_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

**Note**: Free tier limited to ~3 scans/day (15 requests/minute)

**Get API Key**: https://ai.google.dev/gemini-api/docs/quickstart

### Step 6: Configure MEDUSA

Create configuration file:

```bash
# Create config directory
mkdir -p ~/.medusa

# Create config file
cat > ~/.medusa/config.yaml << 'EOF'
llm:
  provider: auto  # "local", "gemini", "mock", or "auto"
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

### Step 7: First Test Run

```bash
# Test with observe mode (safe, read-only)
medusa observe --target localhost --port 8080

# Expected: MEDUSA scans the EHR portal and suggests reconnaissance actions
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

### Step 4: Test with External Target

```bash
# Test with scanme.nmap.org (authorized test target)
medusa observe --target scanme.nmap.org

# Expected: MEDUSA performs reconnaissance and provides AI analysis
```

---

## Understanding MEDUSA Modes

MEDUSA has three operating modes:

### 1. Observe Mode (Read-Only) 🔍
**Safe for learning** - No actions executed, only analysis

```bash
medusa observe --target localhost --port 8080
```

**Use Cases**:
- Learning how MEDUSA thinks
- Understanding AI decision-making
- Safe exploration of capabilities

### 2. Autonomous Mode (AI-Driven) 🤖
**AI makes decisions** with approval gates for risky actions

```bash
medusa autonomous --target localhost --approve-low
```

**Use Cases**:
- Automated penetration testing
- Time-saving for repetitive tasks
- Supervised security assessments

### 3. Shell Mode (Interactive) 💻
**Interactive command execution** with AI suggestions

```bash
medusa shell --target localhost
```

**Use Cases**:
- Manual testing with AI assistance
- Learning command syntax
- Exploratory testing

---

## Your First Security Test

Let's run a complete test workflow:

### Step 1: Reconnaissance (Observe Mode)

```bash
# Discover what services are running
medusa observe --target localhost --port 8080
```

**What to look for**:
- Discovered services and ports
- Identified technologies
- AI-suggested next steps

### Step 2: Review Findings

```bash
# View the generated report
cat ~/.medusa/logs/latest-scan.json
```

### Step 3: Autonomous Testing (Optional)

```bash
# Let AI perform low-risk tests automatically
medusa autonomous --target localhost --approve-low --approve-medium
```

**Note**: This will execute actual tests. Only use on authorized targets!

### Step 4: Review Results

```bash
# Check HTML report
open ~/.medusa/reports/latest-report.html

# View MITRE ATT&CK coverage
medusa report --show-coverage
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

#### "Gemini API rate limit exceeded"
```bash
# Switch to local LLM
medusa observe --target localhost --provider local

# Or configure auto-fallback
# Edit ~/.medusa/config.yaml:
# llm:
#   provider: auto  # Will auto-switch to local if Gemini fails
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

**Last Updated**: 2025-11-06
**Version**: 2.0
**Maintained by**: Project MEDUSA Team

**Questions?** Check the [Documentation Index](docs/INDEX.md) or open a GitHub Issue.
