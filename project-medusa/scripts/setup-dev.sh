#!/bin/bash
set -euo pipefail

# ============================================================================
# MEDUSA Development Environment Setup Script
# ============================================================================
# Purpose: One-command setup for Python development environment
# Usage: ./setup-dev.sh
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLI_DIR="$PROJECT_ROOT/medusa-cli"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}${BOLD}==>${NC} ${BOLD}$1${NC}"
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║           MEDUSA Development Environment Setup               ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ============================================================================
# Prerequisite Checks
# ============================================================================

check_prerequisites() {
    log_step "Checking prerequisites"
    
    local missing_tools=0
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        log_info "Install from: https://www.python.org/downloads/"
        ((missing_tools++))
    else
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        log_success "Python 3 installed (version $PYTHON_VERSION)"
        
        # Check Python version is >= 3.8
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
            log_error "Python 3.8+ required, found $PYTHON_VERSION"
            ((missing_tools++))
        fi
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is not installed"
        ((missing_tools++))
    else
        log_success "pip3 installed"
    fi
    
    # Check git
    if ! command -v git &> /dev/null; then
        log_warning "git not found - pre-commit hooks will be skipped"
    else
        log_success "git installed"
    fi
    
    if [ $missing_tools -gt 0 ]; then
        log_error "Missing $missing_tools required tool(s). Please install them first."
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# ============================================================================
# Virtual Environment Setup
# ============================================================================

setup_venv() {
    log_step "Setting up Python virtual environment"
    
    cd "$CLI_DIR"
    
    # Remove old venv if it exists and user confirms
    if [ -d "venv" ]; then
        log_warning "Virtual environment already exists"
        read -p "Remove and recreate? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Removing old virtual environment..."
            rm -rf venv
        else
            log_info "Using existing virtual environment"
            return 0
        fi
    fi
    
    # Create virtual environment
    log_info "Creating virtual environment..."
    if python3 -m venv venv; then
        log_success "Virtual environment created"
    else
        log_error "Failed to create virtual environment"
        exit 1
    fi
    
    # Activate virtual environment
    log_info "Activating virtual environment..."
    source venv/bin/activate
    
    # Upgrade pip
    log_info "Upgrading pip..."
    pip install --upgrade pip setuptools wheel &>/dev/null
    log_success "pip upgraded"
}

# ============================================================================
# Install Dependencies
# ============================================================================

install_dependencies() {
    log_step "Installing Python dependencies"
    
    cd "$CLI_DIR"
    source venv/bin/activate
    
    # Install from requirements.txt
    if [ -f "requirements.txt" ]; then
        log_info "Installing from requirements.txt..."
        if pip install -r requirements.txt; then
            log_success "Dependencies installed from requirements.txt"
        else
            log_error "Failed to install dependencies"
            exit 1
        fi
    else
        log_warning "requirements.txt not found"
    fi
    
    # Install package in development mode
    if [ -f "setup.py" ] || [ -f "pyproject.toml" ]; then
        log_info "Installing medusa-cli in editable mode..."
        if pip install -e .; then
            log_success "medusa-cli installed in development mode"
        else
            log_error "Failed to install medusa-cli"
            exit 1
        fi
    fi
    
    # Install development dependencies
    log_info "Installing development dependencies..."
    pip install pytest pytest-cov pytest-asyncio black flake8 mypy pre-commit &>/dev/null || true
    log_success "Development dependencies installed"
}

# ============================================================================
# Environment Configuration
# ============================================================================

setup_env_file() {
    log_step "Setting up environment configuration"
    
    cd "$PROJECT_ROOT"
    
    # Check if .env already exists
    if [ -f ".env" ]; then
        log_success ".env file already exists"
        return 0
    fi
    
    # Check if .env.example exists
    if [ -f ".env.example" ]; then
        log_info "Creating .env from .env.example..."
        cp .env.example .env
        log_success ".env file created"
        log_warning "Please edit .env and add your API keys"
    else
        log_info "Creating default .env file..."
        cat > .env << 'EOF'
# MEDUSA Configuration
# Generated by setup-dev.sh

# Google Gemini API (required for LLM functionality)
GOOGLE_API_KEY=your_gemini_api_key_here

# LLM Configuration
LLM_MODEL=gemini-pro
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=2048

# Application Settings
LOG_LEVEL=INFO
MEDUSA_HOME=~/.medusa

# Docker Lab (for internal use)
MYSQL_ROOT_PASSWORD=admin123
MYSQL_DATABASE=healthcare_db
MYSQL_USER=ehrapp
MYSQL_PASSWORD=Welcome123!

# Lab Network
DMZ_SUBNET=172.20.0.0/24
INTERNAL_SUBNET=172.21.0.0/24
EOF
        log_success ".env file created"
        log_warning "⚠️  Please edit .env and add your GOOGLE_API_KEY"
    fi
}

# ============================================================================
# Pre-commit Hooks
# ============================================================================

setup_pre_commit_hooks() {
    log_step "Setting up pre-commit hooks"
    
    cd "$CLI_DIR"
    source venv/bin/activate
    
    if ! command -v git &> /dev/null; then
        log_warning "git not found - skipping pre-commit hooks"
        return 0
    fi
    
    if ! git rev-parse --git-dir &> /dev/null; then
        log_warning "Not a git repository - skipping pre-commit hooks"
        return 0
    fi
    
    # Create .pre-commit-config.yaml if it doesn't exist
    if [ ! -f ".pre-commit-config.yaml" ]; then
        log_info "Creating .pre-commit-config.yaml..."
        cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-json
      - id: check-toml
      - id: mixed-line-ending

  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/pycqa/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
        args: ['--max-line-length=100', '--extend-ignore=E203,W503']
EOF
        log_success ".pre-commit-config.yaml created"
    fi
    
    # Install pre-commit hooks
    log_info "Installing pre-commit hooks..."
    if pre-commit install &>/dev/null; then
        log_success "Pre-commit hooks installed"
    else
        log_warning "Failed to install pre-commit hooks"
    fi
}

# ============================================================================
# Run Initial Tests
# ============================================================================

run_initial_tests() {
    log_step "Running initial tests"
    
    cd "$CLI_DIR"
    source venv/bin/activate
    
    # Check if pytest is available
    if ! command -v pytest &> /dev/null; then
        log_warning "pytest not found - skipping tests"
        return 0
    fi
    
    # Check if tests directory exists
    if [ ! -d "tests" ]; then
        log_warning "tests directory not found - skipping tests"
        return 0
    fi
    
    log_info "Running test suite..."
    if pytest tests/ -v --tb=short 2>&1 | tail -20; then
        log_success "All tests passed!"
    else
        log_warning "Some tests failed - review output above"
        log_info "This is normal during development"
    fi
}

# ============================================================================
# Create Helper Scripts
# ============================================================================

create_helper_scripts() {
    log_step "Creating helper scripts"
    
    cd "$CLI_DIR"
    
    # Create activate script
    cat > activate.sh << 'EOF'
#!/bin/bash
# Quick activation script for MEDUSA development environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/venv/bin/activate"
echo "✓ MEDUSA development environment activated"
echo "Run 'deactivate' to exit"
EOF
    chmod +x activate.sh
    log_success "Created activate.sh helper script"
}

# ============================================================================
# Display Instructions
# ============================================================================

display_instructions() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}║          🎯 Development Environment Ready! 🎯                 ║${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}Virtual Environment:${NC}"
    echo -e "  Location: ${BOLD}$CLI_DIR/venv${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}Activation:${NC}"
    echo -e "  ${BOLD}source $CLI_DIR/venv/bin/activate${NC}"
    echo -e "  ${BOLD}# OR${NC}"
    echo -e "  ${BOLD}cd medusa-cli && source activate.sh${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}Quick Commands:${NC}"
    echo -e "  ${BOLD}Run tests:${NC}        cd medusa-cli && pytest"
    echo -e "  ${BOLD}Run with coverage:${NC} cd medusa-cli && pytest --cov=medusa"
    echo -e "  ${BOLD}Format code:${NC}      cd medusa-cli && black src/"
    echo -e "  ${BOLD}Lint code:${NC}        cd medusa-cli && flake8 src/"
    echo -e "  ${BOLD}Type check:${NC}       cd medusa-cli && mypy src/"
    echo ""
    echo -e "${CYAN}${BOLD}Development Workflow:${NC}"
    echo -e "  1. Activate virtual environment"
    echo -e "  2. Make your changes in ${BOLD}medusa-cli/src/${NC}"
    echo -e "  3. Run tests: ${BOLD}pytest${NC}"
    echo -e "  4. Format code: ${BOLD}black src/${NC}"
    echo -e "  5. Commit changes (pre-commit hooks will run)"
    echo ""
    echo -e "${CYAN}${BOLD}API Configuration:${NC}"
    if grep -q "your_gemini_api_key_here" "$PROJECT_ROOT/.env" 2>/dev/null; then
        echo -e "  ${RED}⚠️  Action Required:${NC}"
        echo -e "  Edit ${BOLD}$PROJECT_ROOT/.env${NC}"
        echo -e "  Add your Google Gemini API key to ${BOLD}GOOGLE_API_KEY${NC}"
    else
        echo -e "  ${GREEN}✓ API key configured${NC}"
    fi
    echo ""
    echo -e "${CYAN}${BOLD}Useful Scripts:${NC}"
    echo -e "  ${BOLD}./scripts/run-tests.sh${NC}      - Run test suite"
    echo -e "  ${BOLD}./scripts/build-docker.sh${NC}   - Build Docker lab"
    echo -e "  ${BOLD}./scripts/clean.sh${NC}          - Clean up environment"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "  1. Activate virtual environment"
    echo -e "  2. Configure API key in .env"
    echo -e "  3. Run tests to verify setup"
    echo -e "  4. Start coding!"
    echo ""
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    print_banner
    
    check_prerequisites
    setup_venv
    install_dependencies
    setup_env_file
    setup_pre_commit_hooks
    create_helper_scripts
    run_initial_tests
    
    display_instructions
    
    log_success "Development environment setup complete!"
    exit 0
}

main "$@"

