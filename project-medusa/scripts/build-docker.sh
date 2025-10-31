#!/bin/bash
set -euo pipefail

# ============================================================================
# MEDUSA Docker Lab Build Script
# ============================================================================
# Purpose: Build and start Docker lab environment
# Usage: ./build-docker.sh [--no-cache] [--detach]
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LAB_DIR="$PROJECT_ROOT/lab-environment"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Options
NO_CACHE=false
DETACHED=true
SKIP_VERIFY=false

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
    echo "MEDUSA Docker Lab Build Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-cache       Build images without using cache"
    echo "  --foreground     Run in foreground (show logs)"
    echo "  --skip-verify    Skip verification after startup"
    echo "  --help, -h       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Build and start lab"
    echo "  $0 --no-cache         # Build without cache"
    echo "  $0 --foreground       # Run in foreground"
    echo ""
}

# ============================================================================
# Argument Parsing
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-cache)
                NO_CACHE=true
                shift
                ;;
            --foreground)
                DETACHED=false
                shift
                ;;
            --skip-verify)
                SKIP_VERIFY=true
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
# Prerequisite Checks
# ============================================================================

check_prerequisites() {
    log_step "Checking prerequisites"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found"
        log_info "Install from: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Check Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        log_info "Start Docker Desktop or run: sudo systemctl start docker"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose not found"
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# ============================================================================
# Build Images
# ============================================================================

build_images() {
    log_step "Building Docker images"
    
    cd "$LAB_DIR"
    
    local build_args=()
    
    if [ "$NO_CACHE" = true ]; then
        build_args+=("--no-cache")
        log_info "Building without cache (this will take longer)..."
    else
        log_info "Building images (using cache where possible)..."
    fi
    
    # Add progress flag
    build_args+=("--progress=plain")
    
    # Build
    if docker-compose build "${build_args[@]}"; then
        log_success "All images built successfully"
    else
        log_error "Image build failed"
        exit 1
    fi
}

# ============================================================================
# Start Services
# ============================================================================

start_services() {
    log_step "Starting Docker services"
    
    cd "$LAB_DIR"
    
    if [ "$DETACHED" = true ]; then
        log_info "Starting services in detached mode..."
        
        if docker-compose up -d; then
            log_success "Services started"
        else
            log_error "Failed to start services"
            exit 1
        fi
    else
        log_info "Starting services in foreground..."
        log_info "Press Ctrl+C to stop"
        echo ""
        
        docker-compose up
        exit 0
    fi
}

# ============================================================================
# Wait for Services
# ============================================================================

wait_for_services() {
    log_step "Waiting for services to be ready"
    
    cd "$LAB_DIR"
    
    local max_wait=60
    local elapsed=0
    
    log_info "This may take 30-60 seconds..."
    
    while [ $elapsed -lt $max_wait ]; do
        local running=$(docker-compose ps | grep -c "Up" || true)
        local total=$(docker-compose ps -q | wc -l | tr -d ' ')
        
        printf "\r  %d/%d services running... [%ds]" "$running" "$total" "$elapsed"
        
        if [ "$running" -eq "$total" ] && [ "$total" -gt 0 ]; then
            echo ""
            log_success "All services are running"
            return 0
        fi
        
        sleep 5
        elapsed=$((elapsed + 5))
    done
    
    echo ""
    log_warning "Services did not start within ${max_wait}s"
    log_info "Check status with: docker-compose ps"
}

# ============================================================================
# Verify Services
# ============================================================================

verify_services() {
    if [ "$SKIP_VERIFY" = true ]; then
        log_info "Skipping verification (--skip-verify)"
        return 0
    fi
    
    log_step "Verifying services"
    
    cd "$LAB_DIR"
    
    if [ -f "verify.sh" ]; then
        log_info "Running verification script..."
        echo ""
        
        if ./verify.sh; then
            log_success "Verification passed"
        else
            log_warning "Verification had issues - check output above"
        fi
    else
        log_warning "verify.sh not found - skipping detailed verification"
        
        # Basic container check
        log_info "Running basic container check..."
        docker-compose ps
    fi
}

# ============================================================================
# Display Access Info
# ============================================================================

display_access_info() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}║           🎯 MEDUSA Lab is Running! 🎯                        ║${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}Web Interfaces:${NC}"
    echo -e "  ${BOLD}EHR Portal:${NC}     http://localhost:8080"
    echo -e "  ${BOLD}EHR API:${NC}        http://localhost:3000"
    echo -e "  ${BOLD}Log Viewer:${NC}     http://localhost:8081"
    echo ""
    echo -e "${CYAN}${BOLD}Default Credentials:${NC}"
    echo -e "  ${BOLD}Web:${NC}            admin / admin123"
    echo -e "  ${BOLD}SSH:${NC}            admin / admin2024"
    echo -e "  ${BOLD}MySQL:${NC}          root / admin123"
    echo -e "  ${BOLD}FTP:${NC}            fileadmin / Files2024!"
    echo ""
    echo -e "${CYAN}${BOLD}Quick Commands:${NC}"
    echo -e "  ${BOLD}View logs:${NC}      docker-compose -f $LAB_DIR/docker-compose.yml logs -f"
    echo -e "  ${BOLD}Stop lab:${NC}       docker-compose -f $LAB_DIR/docker-compose.yml down"
    echo -e "  ${BOLD}Restart:${NC}        docker-compose -f $LAB_DIR/docker-compose.yml restart"
    echo -e "  ${BOLD}Status:${NC}         docker-compose -f $LAB_DIR/docker-compose.yml ps"
    echo ""
    echo -e "${RED}${BOLD}⚠️  SECURITY WARNING ⚠️${NC}"
    echo -e "${RED}This lab contains INTENTIONAL vulnerabilities!${NC}"
    echo -e "${RED}Use only in isolated environments.${NC}"
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
    echo "║                MEDUSA Docker Lab Builder                     ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_prerequisites
    build_images
    start_services
    
    if [ "$DETACHED" = true ]; then
        wait_for_services
        verify_services
        display_access_info
    fi
    
    log_success "Docker lab is ready!"
    exit 0
}

main "$@"

