# Development Setup Guide

Complete guide for setting up a MEDUSA development environment.

## Prerequisites

### Required Software

- **Python 3.9+** (Python 3.11+ recommended)
- **Docker** and **Docker Compose** (for target environment and optional services)
- **Git** (for version control)

### Optional but Recommended

- **Ollama** (for local LLM inference) - [Download](https://ollama.com/)
- **AWS CLI** (for Bedrock integration) - Only if using AWS Bedrock
- **Neo4j Desktop** (for world model development) - Only for graph database work

## Environment Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/project-medusa.git
cd project-medusa
```

### 2. Set Up Python Virtual Environment

**Using venv:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

**Using conda (alternative):**
```bash
conda create -n medusa python=3.11
conda activate medusa
```

### 3. Install Dependencies

**Core dependencies:**
```bash
cd medusa-cli
pip install -r requirements.txt
```

**Development dependencies:**
```bash
pip install -r requirements-dev.txt
```

**Optional cloud provider dependencies:**
```bash
# OpenAI support
pip install openai

# Anthropic Claude support
pip install anthropic
```

### 4. Install MEDUSA in Development Mode

```bash
# From medusa-cli directory
pip install -e .
```

This allows you to edit code and see changes immediately without reinstalling.

## LLM Provider Setup

### Option 1: Local LLM (Ollama - Recommended for Development)

**Install Ollama:**
```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh
```

**Pull the model:**
```bash
ollama pull mistral:7b-instruct
```

**Start Ollama server:**
```bash
ollama serve
```

**Verify connectivity:**
```bash
curl http://localhost:11434/api/tags
```

### Option 2: AWS Bedrock

**Configure AWS credentials:**
```bash
aws configure
# Enter your Access Key ID, Secret Access Key, and region
```

**Verify access:**
```bash
aws bedrock list-foundation-models --region us-west-2
```

### Option 3: OpenAI/Anthropic

**Set API key:**
```bash
export CLOUD_API_KEY="your-api-key-here"
```

## MEDUSA Configuration

### Run First-Time Setup

```bash
medusa setup
```

This wizard will:
- Create `~/.medusa/` directory structure
- Generate initial configuration file
- Test LLM connectivity
- Configure target environment

### Manual Configuration

Edit `~/.medusa/config.yaml`:

```yaml
# LLM Configuration
llm:
  provider: local  # or 'bedrock', 'openai', 'anthropic', 'mock'
  local_model: mistral:7b-instruct
  ollama_url: http://localhost:11434
  temperature: 0.7
  max_tokens: 2048
  timeout: 60
  max_retries: 3

# Target Configuration
target:
  type: docker  # or 'custom'
  url: http://localhost:3001

# Risk Tolerance
risk_tolerance:
  auto_approve_low: true
  auto_approve_medium: false
  auto_approve_high: false
  auto_approve_critical: false

# Logging
logging:
  level: INFO
  log_dir: ~/.medusa/logs
```

## Target Environment Setup

### Start the MedCare EHR Target (Docker)

```bash
# From project root
cd medcare-ehr
docker-compose up -d
```

**Verify target is running:**
```bash
curl http://localhost:3001/health
```

### Alternative: Custom Target

If testing against a custom target, update the configuration:

```yaml
target:
  type: custom
  url: http://your-target-url:port
```

## Verify Installation

### Test MEDUSA CLI

```bash
# Check version
medusa --version

# Check status
medusa status

# Verify LLM connectivity
medusa llm verify
```

### Run Basic Test

```bash
# Start a simple reconnaissance scan
medusa observe --target http://localhost:3001
```

## Running Tests

### Unit and Integration Tests

```bash
# From medusa-cli directory
pytest tests/ -v
```

### Test with Coverage

```bash
pytest --cov=medusa --cov-report=html tests/
# View coverage report at htmlcov/index.html
```

### Test Specific Modules

```bash
# Test LLM integration
pytest tests/test_llm.py -v

# Test tool wrappers
pytest tests/test_tools.py -v

# Test CLI commands
pytest tests/test_cli.py -v
```

### LLM Reasoning Tests

```bash
# Test local LLM
python test_mistral_llm.py

# Test LLM reasoning capabilities
python test_mistral_reasoning.py
```

## Common Development Issues

### Issue: ImportError for medusa modules

**Symptom:**
```
ModuleNotFoundError: No module named 'medusa'
```

**Solution:**
```bash
# Ensure you installed in development mode
cd medusa-cli
pip install -e .
```

### Issue: Ollama Connection Refused

**Symptom:**
```
LLM Not Connected - Connection refused to http://localhost:11434
```

**Solution:**
```bash
# Start Ollama server
ollama serve

# Verify it's running
curl http://localhost:11434/api/tags
```

### Issue: ChromaDB/sentence-transformers Installation Failures

**Symptom:**
```
ERROR: Failed building wheel for sentence-transformers
```

**Solution:**
```bash
# Install system dependencies first (Ubuntu/Debian)
sudo apt-get install build-essential python3-dev

# Install system dependencies (macOS)
brew install cmake

# Retry installation
pip install sentence-transformers
```

### Issue: Docker Target Not Accessible

**Symptom:**
```
Target unreachable: http://localhost:3001
```

**Solution:**
```bash
# Check if containers are running
docker ps | grep medcare

# Restart containers
cd medcare-ehr
docker-compose down
docker-compose up -d

# Check logs
docker-compose logs -f
```

### Issue: Permission Errors with ~/.medusa Directory

**Symptom:**
```
PermissionError: [Errno 13] Permission denied: '~/.medusa/config.yaml'
```

**Solution:**
```bash
# Fix permissions
chmod -R u+w ~/.medusa/

# Or remove and recreate
rm -rf ~/.medusa/
medusa setup
```

### Issue: AWS Bedrock Access Denied

**Symptom:**
```
botocore.exceptions.ClientError: An error occurred (AccessDeniedException)
```

**Solution:**
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Ensure proper IAM permissions for Bedrock
# Required actions:
# - bedrock:InvokeModel
# - bedrock:ListFoundationModels
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

Edit code in `medusa-cli/src/medusa/`

### 3. Test Changes

```bash
# Run tests
pytest tests/ -v

# Test manually
medusa <your-command>
```

### 4. Code Quality Checks

```bash
# Format code
black src/medusa/

# Lint code
flake8 src/medusa/

# Type checking
mypy src/medusa/
```

### 5. Commit and Push

```bash
git add .
git commit -m "feat: your feature description"
git push origin feature/your-feature-name
```

## Development Tools

### Code Formatting

```bash
# Format all Python files
black src/medusa/

# Check formatting without making changes
black --check src/medusa/
```

### Linting

```bash
# Run flake8
flake8 src/medusa/

# With configuration
flake8 --max-line-length=100 --exclude=venv src/medusa/
```

### Type Checking

```bash
# Run mypy
mypy src/medusa/

# Ignore specific errors
mypy --ignore-missing-imports src/medusa/
```

## Debugging Tips

### Enable Debug Logging

Edit `~/.medusa/config.yaml`:
```yaml
logging:
  level: DEBUG
```

Or set environment variable:
```bash
export MEDUSA_LOG_LEVEL=DEBUG
medusa run --target http://localhost:3001
```

### View Recent Logs

```bash
# View latest operation logs
medusa logs --latest

# View specific log file
tail -f ~/.medusa/logs/operation_20240115_143022.log
```

### Interactive Python Debugging

Add breakpoints in code:
```python
import pdb; pdb.set_trace()
```

Run MEDUSA commands and hit the breakpoint to inspect variables.

### Test Individual Components

```python
# Test LLM client directly
from medusa.core.llm import LLMConfig, create_llm_client
import asyncio

async def test_llm():
    config = LLMConfig(provider="local", local_model="mistral:7b-instruct")
    client = create_llm_client(config)
    response = await client.generate("Test prompt")
    print(response)
    await client.close()

asyncio.run(test_llm())
```

## Next Steps

- Read [Technical Reference](technical-reference.md) for architecture details
- Check [AI Agents Guide](ai-agents-guide.md) for multi-agent system development
- Review [CLI Quickstart](../00-getting-started/cli-quickstart.md) for usage examples
- See [Deployment Guide](../03-deployment/deployment-guide.md) for production setup

## Getting Help

- **GitHub Issues**: [Project Issues](https://github.com/yourusername/project-medusa/issues)
- **Documentation**: Check other files in `docs/`
- **Troubleshooting**: See [Troubleshooting Guide](../00-getting-started/troubleshooting.md)
