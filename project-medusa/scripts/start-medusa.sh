#!/bin/bash
# ============================================================================
# MEDUSA Startup Script
# ============================================================================
# Starts all MEDUSA services with proper validation and health checks
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Header
echo -e "${BLUE}"
echo "============================================================================"
echo "  MEDUSA - AI-Powered Penetration Testing Platform"
echo "  Startup Script"
echo "============================================================================"
echo -e "${NC}"

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        log_info "Install Docker from: https://docs.docker.com/get-docker/"
        exit 1
    fi
    log_success "Docker: $(docker --version)"
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed"
        log_info "Install Docker Compose from: https://docs.docker.com/compose/install/"
        exit 1
    fi
    log_success "Docker Compose: Available"
    
    # Check if Docker daemon is running
    if ! docker ps &> /dev/null; then
        log_error "Docker daemon is not running"
        log_info "Start Docker and try again"
        exit 1
    fi
    log_success "Docker daemon: Running"
    
    log_success "All prerequisites met"
}

# Check environment file
check_environment() {
    log_info "Checking environment configuration..."
    
    if [ ! -f "$PROJECT_ROOT/.env" ]; then
        log_warning ".env file not found"
        
        if [ -f "$PROJECT_ROOT/.env.example" ]; then
            log_info "Creating .env from .env.example"
            cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
            log_warning "Please edit .env file and add your GEMINI_API_KEY"
            log_info "Edit: $PROJECT_ROOT/.env"
            exit 1
        else
            log_error "Neither .env nor .env.example found"
            exit 1
        fi
    fi
    
    # Check for Gemini API key
    if ! grep -q "GEMINI_API_KEY=.*[a-zA-Z0-9]" "$PROJECT_ROOT/.env"; then
        log_warning "GEMINI_API_KEY not set in .env"
        log_info "Get your API key from: https://makersuite.google.com/app/apikey"
        log_info "Add it to: $PROJECT_ROOT/.env"
        exit 1
    fi
    
    log_success "Environment configured"
}

# Build images
build_images() {
    log_info "Building Docker images..."
    
    cd "$PROJECT_ROOT"
    
    if docker-compose build --parallel; then
        log_success "Images built successfully"
    else
        log_error "Failed to build images"
        exit 1
    fi
}

# Start services
start_services() {
    log_info "Starting services..."
    
    cd "$PROJECT_ROOT"
    
    if docker-compose up -d; then
        log_success "Services started"
    else
        log_error "Failed to start services"
        exit 1
    fi
}

# Wait for health checks
wait_for_health() {
    log_info "Waiting for services to become healthy..."
    
    local max_attempts=60
    local attempt=0
    local all_healthy=false
    
    while [ $attempt -lt $max_attempts ]; do
        # Check backend health
        if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
            backend_status="${GREEN}✓${NC}"
        else
            backend_status="${RED}✗${NC}"
        fi
        
        # Check frontend health
        if curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
            frontend_status="${GREEN}✓${NC}"
        else
            frontend_status="${RED}✗${NC}"
        fi
        
        # Check EHR webapp
        if curl -sf http://localhost:8080 > /dev/null 2>&1; then
            ehr_status="${GREEN}✓${NC}"
        else
            ehr_status="${RED}✗${NC}"
        fi
        
        echo -ne "\r${BLUE}[INFO]${NC} Backend: $backend_status | Frontend: $frontend_status | Lab: $ehr_status | Attempt: $((attempt+1))/$max_attempts"
        
        # Check if all healthy
        if curl -sf http://localhost:8000/health > /dev/null 2>&1 && \
           curl -sf http://localhost:3000/api/health > /dev/null 2>&1 && \
           curl -sf http://localhost:8080 > /dev/null 2>&1; then
            all_healthy=true
            break
        fi
        
        sleep 2
        ((attempt++))
    done
    
    echo "" # New line after progress
    
    if [ "$all_healthy" = true ]; then
        log_success "All services are healthy"
        return 0
    else
        log_warning "Some services failed to become healthy"
        log_info "Check logs with: docker-compose logs -f"
        return 1
    fi
}

# Display status
display_status() {
    echo ""
    log_info "Service Status:"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # MEDUSA Services
    echo -e "${BLUE}MEDUSA Platform:${NC}"
    echo -e "  Frontend:  ${GREEN}http://localhost:3000${NC}"
    echo -e "  Backend:   ${GREEN}http://localhost:8000${NC}"
    echo -e "  API Docs:  ${GREEN}http://localhost:8000/docs${NC}"
    echo ""
    
    # Lab Services
    echo -e "${BLUE}Lab Environment:${NC}"
    echo -e "  EHR Portal: ${GREEN}http://localhost:8080${NC}"
    echo -e "  EHR API:    ${GREEN}http://localhost:3001${NC}"
    echo -e "  Logs:       ${GREEN}http://localhost:8081${NC}"
    echo -e "  SSH:        ${YELLOW}ssh admin@localhost -p 2222${NC} (password: admin2024)"
    echo -e "  MySQL:      ${YELLOW}mysql -h localhost -P 3306 -u ehrapp -pWelcome123!${NC}"
    echo -e "  FTP:        ${YELLOW}ftp://localhost:21${NC} (user: fileadmin, pass: Files2024!)"
    
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Quick start
    log_info "Quick Start:"
    echo -e "  1. Open ${GREEN}http://localhost:3000${NC} in your browser"
    echo -e "  2. Create a new session"
    echo -e "  3. Start a scan against the lab environment"
    echo ""
    
    # Management commands
    log_info "Management Commands:"
    echo -e "  View logs:    ${YELLOW}docker-compose logs -f${NC}"
    echo -e "  Stop:         ${YELLOW}docker-compose stop${NC}"
    echo -e "  Restart:      ${YELLOW}docker-compose restart${NC}"
    echo -e "  Stop & Clean: ${YELLOW}docker-compose down${NC}"
    echo -e "  Full Reset:   ${YELLOW}docker-compose down -v${NC}"
    echo ""
}

# Main execution
main() {
    check_prerequisites
    check_environment
    build_images
    start_services
    
    if wait_for_health; then
        log_success "✨ MEDUSA is ready!"
        display_status
    else
        log_warning "⚠️  MEDUSA started but some services need attention"
        display_status
        log_info "Check logs for details: docker-compose logs -f"
    fi
}

# Run main function
main "$@"

