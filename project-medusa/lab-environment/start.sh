#!/bin/bash
set -euo pipefail

# ============================================================================
# MEDUSA Lab - Quick Start Script
# ============================================================================
# Purpose: Quick one-command lab startup with minimal output
# Usage: ./start.sh [--rebuild] [--quiet]
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# Options
REBUILD=false
QUIET=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --rebuild)
            REBUILD=true
            shift
            ;;
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --help|-h)
            echo "MEDUSA Lab - Quick Start"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --rebuild    Rebuild Docker images from scratch"
            echo "  --quiet      Minimal output"
            echo "  --help       Show this help"
            echo ""
            exit 0
            ;;
    esac
done

log() {
    if [ "$QUIET" = false ]; then
        echo -e "${GREEN}▶${NC} $1"
    fi
}

# Change to lab directory
cd "$SCRIPT_DIR"

# Check Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running${NC}"
    echo "Please start Docker Desktop or run: sudo systemctl start docker"
    exit 1
fi

log "🚀 Starting MEDUSA Lab Environment..."

# Stop existing containers
if [ "$QUIET" = false ]; then
    docker-compose down
else
    docker-compose down > /dev/null 2>&1
fi

# Build and start
if [ "$REBUILD" = true ]; then
    log "🔨 Rebuilding Docker images (this may take 5-10 minutes)..."
    if [ "$QUIET" = false ]; then
        docker-compose up -d --build
    else
        docker-compose up -d --build > /dev/null 2>&1
    fi
else
    log "📦 Starting containers..."
    if [ "$QUIET" = false ]; then
        docker-compose up -d
    else
        docker-compose up -d > /dev/null 2>&1
    fi
fi

# Wait for services
log "⏳ Waiting for services to be ready..."
sleep 15

# Quick health check
log "🔍 Performing health checks..."

FAILED=0

# Check web app
if curl -s http://localhost:8080 > /dev/null 2>&1; then
    [ "$QUIET" = false ] && echo -e "  ${GREEN}✅${NC} EHR Web Portal (http://localhost:8080)"
else
    [ "$QUIET" = false ] && echo -e "  ${RED}❌${NC} EHR Web Portal - Not responding"
    ((FAILED++))
fi

# Check API
if curl -s http://localhost:3001 > /dev/null 2>&1; then
    [ "$QUIET" = false ] && echo -e "  ${GREEN}✅${NC} EHR API (http://localhost:3001)"
else
    [ "$QUIET" = false ] && echo -e "  ${YELLOW}⚠${NC}  EHR API - May need more time"
fi

# Check database
if docker-compose exec -T ehr-database mysqladmin ping -h localhost -u root -padmin123 &>/dev/null; then
    [ "$QUIET" = false ] && echo -e "  ${GREEN}✅${NC} MySQL Database (port 3306)"
else
    [ "$QUIET" = false ] && echo -e "  ${YELLOW}⚠${NC}  MySQL Database - May need more time"
fi

echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ Lab environment is ready!${NC}"
    echo ""
    echo -e "${CYAN}Quick Access:${NC}"
    echo "  Web:  http://localhost:8080"
    echo "  API:  http://localhost:3001"
    echo "  SSH:  ssh admin@localhost -p 2222 (password: admin2024)"
    echo ""
    echo -e "${CYAN}Commands:${NC}"
    echo "  Full verification: ./verify.sh"
    echo "  View logs:         docker-compose logs -f"
    echo "  Stop lab:          docker-compose down"
    echo ""
    echo -e "${RED}⚠️  CONTAINS INTENTIONAL VULNERABILITIES - DO NOT EXPOSE TO INTERNET${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some services need more time to initialize${NC}"
    echo "Run './verify.sh' in 30 seconds to check status"
    exit 0
fi
