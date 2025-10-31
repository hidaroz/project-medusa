#!/bin/bash
set -euo pipefail

# ============================================================================
# MEDUSA Cleanup Script
# ============================================================================
# Purpose: Clean up Docker services, Python cache, and temporary files
# Usage: ./clean.sh [--deep] [--all]
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LAB_DIR="$PROJECT_ROOT/lab-environment"
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
DEEP_CLEAN=false
CLEAN_ALL=false
REMOVE_VENV=false

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

show_help() {
    echo "MEDUSA Cleanup Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --deep           Deep clean (removes volumes and images)"
    echo "  --all            Complete clean (everything including venv)"
    echo "  --venv           Remove Python virtual environment"
    echo "  --help, -h       Show this help message"
    echo ""
    echo "Cleanup levels:"
    echo "  Normal:          Stop containers, clean cache"
    echo "  Deep (--deep):   + Remove volumes and images"
    echo "  All (--all):     + Remove venv, all build artifacts"
    echo ""
    echo "Examples:"
    echo "  $0               # Normal cleanup"
    echo "  $0 --deep        # Deep cleanup (removes data)"
    echo "  $0 --all         # Complete cleanup"
    echo ""
}

confirm_action() {
    local message="$1"
    echo -e "${YELLOW}${BOLD}WARNING:${NC} $message"
    read -p "Are you sure? (type 'yes' to confirm): " -r
    echo
    if [[ ! $REPLY == "yes" ]]; then
        log_info "Cleanup cancelled"
        exit 0
    fi
}

# ============================================================================
# Argument Parsing
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --deep)
                DEEP_CLEAN=true
                shift
                ;;
            --all)
                CLEAN_ALL=true
                DEEP_CLEAN=true
                REMOVE_VENV=true
                shift
                ;;
            --venv)
                REMOVE_VENV=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# Docker Cleanup
# ============================================================================

cleanup_docker() {
    log_step "Cleaning up Docker services"
    
    cd "$LAB_DIR"
    
    # Check if docker-compose file exists
    if [ ! -f "docker-compose.yml" ]; then
        log_warning "docker-compose.yml not found - skipping Docker cleanup"
        return 0
    fi
    
    # Stop services
    log_info "Stopping Docker services..."
    if docker-compose ps -q | grep -q .; then
        docker-compose stop
        log_success "Services stopped"
    else
        log_info "No services running"
    fi
    
    # Remove containers
    log_info "Removing containers..."
    docker-compose down --remove-orphans
    log_success "Containers removed"
    
    # Deep clean: remove volumes and images
    if [ "$DEEP_CLEAN" = true ]; then
        log_info "Performing deep clean..."
        
        # Remove volumes
        log_info "Removing volumes (this will delete all data)..."
        docker-compose down -v
        log_success "Volumes removed"
        
        # Remove images
        log_info "Removing Docker images..."
        local images=$(docker images --filter "reference=lab-environment*" -q)
        if [ -n "$images" ]; then
            docker rmi $images 2>/dev/null || true
            log_success "Images removed"
        else
            log_info "No images to remove"
        fi
    fi
}

# ============================================================================
# Python Cache Cleanup
# ============================================================================

cleanup_python_cache() {
    log_step "Cleaning Python cache files"
    
    cd "$PROJECT_ROOT"
    
    # Remove __pycache__ directories
    log_info "Removing __pycache__ directories..."
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    log_success "__pycache__ cleaned"
    
    # Remove .pyc files
    log_info "Removing .pyc files..."
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    log_success ".pyc files removed"
    
    # Remove .pyo files
    find . -type f -name "*.pyo" -delete 2>/dev/null || true
    
    # Clean pytest cache
    if [ -d "$CLI_DIR/.pytest_cache" ]; then
        log_info "Removing pytest cache..."
        rm -rf "$CLI_DIR/.pytest_cache"
        log_success "pytest cache removed"
    fi
    
    # Clean coverage files
    if [ -d "$CLI_DIR/htmlcov" ]; then
        log_info "Removing coverage reports..."
        rm -rf "$CLI_DIR/htmlcov"
        rm -f "$CLI_DIR/.coverage"
        log_success "Coverage files removed"
    fi
    
    # Clean egg-info
    if [ -d "$CLI_DIR/src/medusa_pentest.egg-info" ]; then
        log_info "Removing egg-info..."
        rm -rf "$CLI_DIR/src/medusa_pentest.egg-info"
        log_success "egg-info removed"
    fi
}

# ============================================================================
# Virtual Environment Cleanup
# ============================================================================

cleanup_venv() {
    if [ "$REMOVE_VENV" = false ]; then
        return 0
    fi
    
    log_step "Removing virtual environment"
    
    if [ -d "$CLI_DIR/venv" ]; then
        log_info "Removing virtual environment..."
        rm -rf "$CLI_DIR/venv"
        log_success "Virtual environment removed"
    else
        log_info "No virtual environment found"
    fi
}

# ============================================================================
# Temporary Files Cleanup
# ============================================================================

cleanup_temp_files() {
    log_step "Cleaning temporary files"
    
    cd "$PROJECT_ROOT"
    
    # Remove log files
    if [ -d "$LAB_DIR/analysis" ]; then
        log_info "Cleaning analysis directory..."
        rm -f "$LAB_DIR/analysis"/*.log 2>/dev/null || true
    fi
    
    # Remove DS_Store files (macOS)
    log_info "Removing .DS_Store files..."
    find . -name ".DS_Store" -delete 2>/dev/null || true
    
    # Remove backup files
    log_info "Removing backup files..."
    find . -name "*~" -delete 2>/dev/null || true
    find . -name "*.bak" -delete 2>/dev/null || true
    
    log_success "Temporary files cleaned"
}

# ============================================================================
# Build Artifacts Cleanup
# ============================================================================

cleanup_build_artifacts() {
    if [ "$CLEAN_ALL" = false ]; then
        return 0
    fi
    
    log_step "Cleaning build artifacts"
    
    # Remove dist directories
    if [ -d "$CLI_DIR/dist" ]; then
        log_info "Removing dist directory..."
        rm -rf "$CLI_DIR/dist"
    fi
    
    # Remove build directories
    if [ -d "$CLI_DIR/build" ]; then
        log_info "Removing build directory..."
        rm -rf "$CLI_DIR/build"
    fi
    
    # Remove node_modules (if present)
    if [ -d "$PROJECT_ROOT/medusa-webapp/node_modules" ]; then
        log_info "Removing node_modules..."
        rm -rf "$PROJECT_ROOT/medusa-webapp/node_modules"
    fi
    
    log_success "Build artifacts cleaned"
}

# ============================================================================
# Docker System Cleanup
# ============================================================================

cleanup_docker_system() {
    if [ "$CLEAN_ALL" = false ]; then
        return 0
    fi
    
    log_step "Cleaning Docker system"
    
    log_info "Removing unused Docker resources..."
    docker system prune -f 2>&1 | head -5
    log_success "Docker system cleaned"
}

# ============================================================================
# Display Summary
# ============================================================================

display_summary() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}║                 ✓ Cleanup Complete                           ║${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}${BOLD}What was cleaned:${NC}"
    echo -e "  ${GREEN}✓${NC} Docker containers stopped and removed"
    echo -e "  ${GREEN}✓${NC} Python cache files removed"
    echo -e "  ${GREEN}✓${NC} Temporary files removed"
    
    if [ "$DEEP_CLEAN" = true ]; then
        echo -e "  ${GREEN}✓${NC} Docker volumes removed"
        echo -e "  ${GREEN}✓${NC} Docker images removed"
    fi
    
    if [ "$REMOVE_VENV" = true ]; then
        echo -e "  ${GREEN}✓${NC} Virtual environment removed"
    fi
    
    if [ "$CLEAN_ALL" = true ]; then
        echo -e "  ${GREEN}✓${NC} Build artifacts removed"
        echo -e "  ${GREEN}✓${NC} Docker system pruned"
    fi
    
    echo ""
    echo -e "${CYAN}${BOLD}To rebuild:${NC}"
    
    if [ "$REMOVE_VENV" = true ]; then
        echo -e "  1. Run: ${BOLD}./scripts/setup-dev.sh${NC}"
    fi
    
    echo -e "  2. Run: ${BOLD}./scripts/build-docker.sh${NC}"
    echo ""
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    parse_arguments "$@"
    
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║                    MEDUSA Cleanup Script                     ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Show cleanup level
    if [ "$CLEAN_ALL" = true ]; then
        log_warning "Cleanup level: COMPLETE (all data will be removed)"
        confirm_action "This will remove EVERYTHING including virtual environment and volumes."
    elif [ "$DEEP_CLEAN" = true ]; then
        log_warning "Cleanup level: DEEP (volumes and images will be removed)"
        confirm_action "This will remove all Docker volumes and stored data."
    else
        log_info "Cleanup level: NORMAL (containers and cache only)"
    fi
    
    # Run cleanup tasks
    cleanup_docker
    cleanup_python_cache
    cleanup_venv
    cleanup_temp_files
    cleanup_build_artifacts
    cleanup_docker_system
    
    display_summary
    
    log_success "Cleanup completed successfully!"
    exit 0
}

main "$@"

