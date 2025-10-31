#!/bin/bash
set -euo pipefail

# ============================================================================
# MEDUSA Test Runner Script
# ============================================================================
# Purpose: Run pytest test suite with coverage reporting
# Usage: ./run-tests.sh [OPTIONS]
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

# Options
COVERAGE=true
HTML_REPORT=true
VERBOSE=false
TEST_PATH=""

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

log_step() {
    echo -e "\n${CYAN}${BOLD}==>${NC} ${BOLD}$1${NC}"
}

show_help() {
    echo "MEDUSA Test Runner"
    echo ""
    echo "Usage: $0 [OPTIONS] [TEST_PATH]"
    echo ""
    echo "Options:"
    echo "  --no-cov        Disable coverage reporting"
    echo "  --no-html       Disable HTML coverage report"
    echo "  --verbose, -v   Verbose test output"
    echo "  --help, -h      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              # Run all tests with coverage"
    echo "  $0 --verbose                    # Run with verbose output"
    echo "  $0 --no-cov                     # Run without coverage"
    echo "  $0 tests/unit/                  # Run only unit tests"
    echo "  $0 tests/unit/test_config.py    # Run specific test file"
    echo ""
}

# ============================================================================
# Argument Parsing
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-cov)
                COVERAGE=false
                shift
                ;;
            --no-html)
                HTML_REPORT=false
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                TEST_PATH="$1"
                shift
                ;;
        esac
    done
}

# ============================================================================
# Environment Check
# ============================================================================

check_environment() {
    log_step "Checking environment"
    
    # Check if in CLI directory
    cd "$CLI_DIR"
    
    # Check for virtual environment
    if [ ! -d "venv" ]; then
        log_error "Virtual environment not found"
        log_info "Run: ./scripts/setup-dev.sh"
        exit 1
    fi
    
    # Activate virtual environment
    log_info "Activating virtual environment..."
    source venv/bin/activate
    
    # Check pytest is installed
    if ! command -v pytest &> /dev/null; then
        log_error "pytest not found in virtual environment"
        log_info "Install with: pip install pytest pytest-cov"
        exit 1
    fi
    
    log_success "Environment ready"
}

# ============================================================================
# Run Tests
# ============================================================================

run_tests() {
    log_step "Running test suite"
    
    cd "$CLI_DIR"
    source venv/bin/activate
    
    # Build pytest command
    local pytest_args=()
    
    # Add test path (default to tests/)
    if [ -n "$TEST_PATH" ]; then
        pytest_args+=("$TEST_PATH")
    else
        pytest_args+=("tests/")
    fi
    
    # Add verbosity
    if [ "$VERBOSE" = true ]; then
        pytest_args+=("-vv")
    else
        pytest_args+=("-v")
    fi
    
    # Add coverage if enabled
    if [ "$COVERAGE" = true ]; then
        pytest_args+=("--cov=medusa")
        pytest_args+=("--cov-report=term-missing")
        
        if [ "$HTML_REPORT" = true ]; then
            pytest_args+=("--cov-report=html")
        fi
    fi
    
    # Add other useful options
    pytest_args+=("--tb=short")              # Shorter traceback
    pytest_args+=("--strict-markers")        # Strict marker checking
    pytest_args+=("--color=yes")             # Colored output
    
    # Display command being run
    log_info "Command: pytest ${pytest_args[*]}"
    echo ""
    
    # Run pytest
    if pytest "${pytest_args[@]}"; then
        log_success "All tests passed!"
        return 0
    else
        log_error "Some tests failed"
        return 1
    fi
}

# ============================================================================
# Display Results
# ============================================================================

display_results() {
    local exit_code=$1
    
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}${BOLD}✓ Test Suite Passed${NC}"
    else
        echo -e "${RED}${BOLD}✗ Test Suite Failed${NC}"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Show coverage report location
    if [ "$COVERAGE" = true ] && [ "$HTML_REPORT" = true ]; then
        if [ -d "$CLI_DIR/htmlcov" ]; then
            echo -e "${CYAN}${BOLD}Coverage Report:${NC}"
            echo -e "  ${BOLD}$CLI_DIR/htmlcov/index.html${NC}"
            echo ""
            
            # Try to open in browser (macOS)
            if [[ "$OSTYPE" == "darwin"* ]]; then
                log_info "Opening coverage report in browser..."
                open "$CLI_DIR/htmlcov/index.html" 2>/dev/null || true
            fi
        fi
    fi
    
    # Show summary
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}All tests passed successfully!${NC}"
        echo -e "Continue with confidence. 🚀"
    else
        echo -e "${YELLOW}Some tests failed. Review the output above.${NC}"
        echo ""
        echo -e "${YELLOW}Troubleshooting tips:${NC}"
        echo -e "  • Check test output for specific failures"
        echo -e "  • Run individual test files: ${BOLD}pytest tests/unit/test_file.py${NC}"
        echo -e "  • Run with more verbosity: ${BOLD}$0 --verbose${NC}"
        echo -e "  • Check test fixtures in ${BOLD}tests/fixtures/${NC}"
    fi
    
    echo ""
}

# ============================================================================
# Cleanup
# ============================================================================

cleanup() {
    # Clean up pytest cache if tests failed
    if [ -d "$CLI_DIR/.pytest_cache" ]; then
        # We keep the cache for faster subsequent runs
        :
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    parse_arguments "$@"
    
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║                    MEDUSA Test Runner                        ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_environment
    
    # Run tests and capture exit code
    set +e
    run_tests
    TEST_EXIT_CODE=$?
    set -e
    
    display_results $TEST_EXIT_CODE
    
    cleanup
    
    exit $TEST_EXIT_CODE
}

main "$@"

