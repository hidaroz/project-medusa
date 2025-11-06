# MEDUSA Automation & Deployment Guide

## 🎯 Overview

This guide covers all automation scripts created for the MEDUSA project, enabling one-command deployment and streamlined development workflows.

## 📁 Created Files

### Lab Environment Scripts (`lab-environment/`)
- **`setup.sh`** - Complete lab deployment automation
- **`verify.sh`** - Comprehensive service verification
- **`healthcheck.py`** - Python-based health monitoring with JSON output

### Development Scripts (`scripts/`)
- **`setup-dev.sh`** - Python development environment setup
- **`run-tests.sh`** - Test execution with coverage reporting
- **`build-docker.sh`** - Docker lab build automation
- **`clean.sh`** - Cleanup script with multiple levels

### Configuration Files
- **`env.example`** - Environment configuration template
- **`docker-compose.override.yml`** - Development-specific Docker overrides

---

## 🚀 Quick Start

### 1. Initial Setup

```bash
# Clone the repository (if not already done)
cd project-medusa

# Set up development environment
./scripts/setup-dev.sh

# Configure API keys
cp env.example .env
# Edit .env and add your GOOGLE_API_KEY
```

### 2. Deploy Docker Lab

```bash
# One-command deployment
cd lab-environment
./setup.sh

# The script will:
# - Check prerequisites (Docker, Docker Compose)
# - Build all 8 service images
# - Create networks (DMZ + Internal)
# - Start all services
# - Run health checks
# - Display access information
```

### 3. Verify Deployment

```bash
# Run verification script
cd lab-environment
./verify.sh

# Or use Python health checker
python3 healthcheck.py

# For JSON output (useful for automation)
python3 healthcheck.py --format json
```

---

## 📚 Detailed Script Documentation

### Lab Environment Scripts

#### `setup.sh` - Complete Lab Setup

**Purpose:** One-command deployment of the entire vulnerable lab environment.

**Usage:**
```bash
cd lab-environment
./setup.sh
```

**What it does:**
1. ✅ Checks prerequisites (Docker, Docker Compose, curl)
2. 🏗️ Creates necessary directories
3. ⚙️ Generates `.env` file if missing
4. 🐳 Builds all Docker images
5. 🌐 Creates Docker networks
6. 🗄️ Initializes databases
7. 🚀 Starts all 8 services
8. ⏱️ Waits for services to be healthy
9. ✅ Runs basic verification
10. 📋 Displays access information

**Time:** ~5-10 minutes on first run

---

#### `verify.sh` - Service Verification

**Purpose:** Comprehensive testing of all services for accessibility and health.

**Usage:**
```bash
./verify.sh [OPTIONS]

Options:
  --json       Output results in JSON format
  --verbose    Show detailed test information
  --help       Show help message
```

**Examples:**
```bash
# Standard verification
./verify.sh

# Verbose output
./verify.sh --verbose

# JSON output for automation
./verify.sh --json > status.json
```

**Tests performed:**
- ✅ Docker environment check
- ✅ Container status (all 8 services)
- ✅ Web service endpoints (HTTP checks)
- ✅ Network service ports (SSH, FTP, LDAP, etc.)
- ✅ Database connectivity and data
- ✅ Docker networks
- ✅ Volume data
- ✅ Vulnerability test points

**Exit codes:**
- `0` - All tests passed
- `1` - Some tests failed

---

#### `healthcheck.py` - Python Health Monitor

**Purpose:** Python-based health monitoring with structured output.

**Usage:**
```bash
python3 healthcheck.py [OPTIONS]

Options:
  --format [text|json]  Output format
  --quiet               Suppress progress messages
```

**Examples:**
```bash
# Standard health check
python3 healthcheck.py

# JSON output
python3 healthcheck.py --format json

# Quiet JSON (for scripts)
python3 healthcheck.py --format json --quiet
```

**Features:**
- 🔍 Checks all 8 services
- 🐳 Docker container status
- 🌐 HTTP endpoint testing
- 🔌 Port connectivity tests
- 🗄️ Database health checks
- 📊 JSON output for automation
- 🎨 Colored terminal output

**JSON Output Structure:**
```json
{
  "timestamp": "2024-10-31T10:30:00Z",
  "services": {
    "ehr_webapp": {
      "name": "EHR Web Portal",
      "status": "healthy",
      "checks": { ... }
    },
    ...
  },
  "summary": {
    "total": 8,
    "healthy": 8,
    "unhealthy": 0,
    "degraded": 0
  }
}
```

---

### Development Scripts

#### `setup-dev.sh` - Development Environment Setup

**Purpose:** One-command setup for Python development environment.

**Usage:**
```bash
./scripts/setup-dev.sh
```

**What it does:**
1. ✅ Checks prerequisites (Python 3.8+, pip, git)
2. 🐍 Creates Python virtual environment
3. 📦 Installs dependencies from `requirements.txt`
4. 🔧 Installs medusa-cli in editable mode
5. 🛠️ Installs dev tools (pytest, black, flake8, mypy)
6. ⚙️ Creates `.env` file from template
7. 🪝 Sets up pre-commit hooks
8. 📝 Creates helper scripts
9. 🧪 Runs initial tests

**Time:** ~3-5 minutes

**After running:**
```bash
# Activate virtual environment
cd medusa-cli
source venv/bin/activate

# Or use helper script
source activate.sh
```

---

#### `run-tests.sh` - Test Execution

**Purpose:** Run pytest test suite with coverage reporting.

**Usage:**
```bash
./scripts/run-tests.sh [OPTIONS] [TEST_PATH]

Options:
  --no-cov        Disable coverage reporting
  --no-html       Disable HTML coverage report
  --verbose, -v   Verbose test output
  --help          Show help message
```

**Examples:**
```bash
# Run all tests with coverage
./scripts/run-tests.sh

# Run with verbose output
./scripts/run-tests.sh --verbose

# Run specific test file
./scripts/run-tests.sh tests/unit/test_config.py

# Run without coverage
./scripts/run-tests.sh --no-cov
```

**Features:**
- 🧪 Runs pytest test suite
- 📊 Coverage reporting
- 📈 HTML coverage report
- 🎨 Colored output
- 🚀 Auto-opens HTML report (macOS)

---

#### `build-docker.sh` - Docker Build Automation

**Purpose:** Build and start Docker lab environment.

**Usage:**
```bash
./scripts/build-docker.sh [OPTIONS]

Options:
  --no-cache       Build images without using cache
  --foreground     Run in foreground (show logs)
  --skip-verify    Skip verification after startup
  --help           Show help message
```

**Examples:**
```bash
# Standard build and start
./scripts/build-docker.sh

# Build without cache
./scripts/build-docker.sh --no-cache

# Run in foreground (see logs)
./scripts/build-docker.sh --foreground
```

**What it does:**
1. ✅ Checks Docker prerequisites
2. 🏗️ Builds all Docker images
3. 🚀 Starts services
4. ⏱️ Waits for health
5. ✅ Runs verification
6. 📋 Displays access info

---

#### `clean.sh` - Cleanup Script

**Purpose:** Clean up Docker services, Python cache, and temporary files.

**Usage:**
```bash
./scripts/clean.sh [OPTIONS]

Options:
  --deep     Deep clean (removes volumes and images)
  --all      Complete clean (everything including venv)
  --venv     Remove Python virtual environment
  --help     Show help message
```

**Cleanup Levels:**

**Normal** (default):
```bash
./scripts/clean.sh
```
- Stops Docker containers
- Removes containers
- Cleans Python cache
- Removes temporary files

**Deep** (`--deep`):
```bash
./scripts/clean.sh --deep
```
- All normal cleanup
- **Removes Docker volumes (data loss!)**
- Removes Docker images

**Complete** (`--all`):
```bash
./scripts/clean.sh --all
```
- All deep cleanup
- **Removes virtual environment**
- Removes build artifacts
- Prunes Docker system

⚠️ **Warning:** Deep and complete cleanups are destructive!

---

## 🔧 Configuration

### Environment Variables (`env.example`)

**Required:**
```bash
GOOGLE_API_KEY=your_gemini_api_key_here
```

**Common Settings:**
```bash
LLM_MODEL=gemini-pro
LLM_TEMPERATURE=0.7
LOG_LEVEL=INFO
MEDUSA_HOME=~/.medusa
```

**Docker Lab:**
```bash
MYSQL_ROOT_PASSWORD=admin123
MYSQL_DATABASE=healthcare_db
EHR_WEB_PORT=8080
```

**Security:**
```bash
REQUIRE_APPROVAL=true
MAX_AUTO_RISK=MEDIUM
AUDIT_LOGGING=true
```

### Docker Compose Override (`docker-compose.override.yml`)

**Purpose:** Development-specific configurations.

**Features:**
- 📝 Source code mounting for live editing
- 🐛 Debug ports exposed
- 📊 Verbose logging
- 🔄 Hot-reload capabilities
- 💻 Development tools included

**Usage:** Automatically applied when running `docker-compose`

**To disable:**
```bash
docker-compose -f docker-compose.yml up -d
```

---

## 🎓 Common Workflows

### Daily Development

```bash
# 1. Activate environment
cd medusa-cli
source venv/bin/activate

# 2. Make changes to code

# 3. Run tests
cd ..
./scripts/run-tests.sh

# 4. Format code
cd medusa-cli
black src/

# 5. Commit (pre-commit hooks run automatically)
git add .
git commit -m "feat: add new feature"
```

### Lab Testing

```bash
# Start lab
cd lab-environment
./setup.sh

# Run MEDUSA agent
cd ../medusa-cli
source venv/bin/activate
medusa autonomous --target 172.20.0.2

# View logs
docker-compose logs -f ehr-webapp

# Stop lab
docker-compose down
```

### Complete Reset

```bash
# Clean everything
./scripts/clean.sh --all

# Rebuild from scratch
./scripts/setup-dev.sh
./scripts/build-docker.sh
```

---

## 📊 Service Access Information

### Web Interfaces
- **EHR Portal:** http://localhost:8080
- **EHR API:** http://localhost:3000
- **Log Viewer:** http://localhost:8081

### Default Credentials
- **Web Login:** admin / admin123
- **SSH:** admin / admin2024 (port 2222)
- **MySQL:** root / admin123 (port 3306)
- **FTP:** fileadmin / Files2024! (port 21)
- **LDAP:** cn=admin,dc=medcare,dc=local / admin123

### Connection Commands
```bash
# SSH
ssh admin@localhost -p 2222

# MySQL
mysql -h localhost -P 3306 -u root -padmin123

# FTP
ftp localhost 21
```

---

## 🐛 Troubleshooting

### Docker Issues

**Problem:** Docker daemon not running
```bash
# macOS
open -a Docker

# Linux
sudo systemctl start docker
```

**Problem:** Port already in use
```bash
# Find what's using the port
lsof -i :8080

# Stop conflicting service or change port in docker-compose.yml
```

**Problem:** Services not starting
```bash
# Check logs
docker-compose logs

# Rebuild without cache
./scripts/build-docker.sh --no-cache
```

### Python Issues

**Problem:** Virtual environment not found
```bash
# Recreate it
./scripts/setup-dev.sh
```

**Problem:** Import errors
```bash
# Reinstall in editable mode
cd medusa-cli
source venv/bin/activate
pip install -e .
```

**Problem:** Tests failing
```bash
# Check test output
./scripts/run-tests.sh --verbose

# Verify fixtures
ls -la medusa-cli/tests/fixtures/
```

### Network Issues

**Problem:** Services can't reach each other
```bash
# Check networks
docker network ls
docker network inspect medusa-internal

# Restart services
docker-compose restart
```

---

## 📝 Script Maintenance

All scripts follow these conventions:
- ✅ Error handling (`set -euo pipefail`)
- 🎨 Colored output for readability
- 📊 Progress indicators
- 🔍 Prerequisite checking
- 📋 Help documentation (`--help`)
- ✅ Exit codes (0 = success, 1 = failure)

**To modify scripts:**
1. Edit the script file
2. Test thoroughly
3. Update this documentation
4. Commit changes with descriptive message

---

## 🔒 Security Notes

⚠️ **Important:**
- Lab environment contains **INTENTIONAL vulnerabilities**
- **DO NOT** expose to the internet
- Use only in isolated networks
- Review `.env` before committing (API keys!)
- Keep `env.example` updated, not `.env`

---

## 📚 Additional Resources

- **Project README:** `README.md`
- **Architecture Guide:** `medusa-cli/ARCHITECTURE.md`
- **Quick Start:** `medusa-cli/QUICKSTART.md`
- **Lab Documentation:** `lab-environment/docs/`
- **Testing Guide:** `.cursor/rules/cursor-rules-testing.mdc`

---

## 🆘 Getting Help

**Script-specific help:**
```bash
./script-name.sh --help
```

**Check service status:**
```bash
cd lab-environment
./verify.sh --verbose
```

**View logs:**
```bash
docker-compose logs -f [service-name]
```

---

**Last Updated:** October 31, 2025  
**Version:** 1.0  
**Maintainer:** MEDUSA Project Team

