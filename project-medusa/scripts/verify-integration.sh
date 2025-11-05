#!/bin/bash

# ============================================================================
# MEDUSA Integration Verification Script
# ============================================================================
# This script verifies that all components are properly integrated:
# 1. Workstation container is stable (not looping)
# 2. Frontend can connect to EHR API
# 3. Database is accessible and populated
# 4. All services are healthy
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to check if a service is running
check_container() {
    local container_name=$1
    local status=$(docker inspect -f '{{.State.Status}}' "$container_name" 2>/dev/null || echo "not found")

    if [ "$status" = "running" ]; then
        log_success "Container $container_name is running"
        return 0
    elif [ "$status" = "restarting" ]; then
        log_error "Container $container_name is RESTARTING (loop detected!)"
        return 1
    elif [ "$status" = "not found" ]; then
        log_warning "Container $container_name not found"
        return 1
    else
        log_warning "Container $container_name status: $status"
        return 1
    fi
}

# Function to check HTTP endpoint
check_endpoint() {
    local url=$1
    local name=$2
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

    if [ "$response" = "200" ]; then
        log_success "$name is healthy (HTTP $response)"
        return 0
    else
        log_error "$name is not responding (HTTP $response)"
        return 1
    fi
}

# Function to check port
check_port() {
    local host=$1
    local port=$2
    local name=$3

    if nc -z -w 2 "$host" "$port" 2>/dev/null; then
        log_success "$name is listening on port $port"
        return 0
    else
        log_error "$name is NOT listening on port $port"
        return 1
    fi
}

echo ""
echo "======================================================================"
echo "  MEDUSA Integration Verification"
echo "======================================================================"
echo ""

# Check if Docker is running
log_info "Checking Docker..."
if docker ps >/dev/null 2>&1; then
    log_success "Docker is running"
else
    log_error "Docker is not running. Please start Docker first."
    exit 1
fi

echo ""
log_info "Checking MEDUSA containers..."
echo ""

# Check core MEDUSA services
check_container "medusa_frontend" || true
check_container "medusa_backend" || true
check_container "medusa_postgres" || true
check_container "medusa_redis" || true

echo ""
log_info "Checking EHR lab environment containers..."
echo ""

# Check EHR services
check_container "medusa_ehr_web" || true
check_container "medusa_ehr_api" || true
check_container "medusa_ehr_db" || true

echo ""
log_info "Checking vulnerable services..."
echo ""

# Check vulnerable services
check_container "medusa_workstation" || WORKSTATION_FAILED=1
check_container "medusa_ssh_server" || true
check_container "medusa_ftp_server" || true
check_container "medusa_ldap" || true

echo ""
log_info "Checking service health endpoints..."
echo ""

# Give services a moment to be ready
sleep 2

# Check health endpoints
check_endpoint "http://localhost:8000/health" "MEDUSA Backend" || true
check_endpoint "http://localhost:3001/health" "EHR API" || true
check_endpoint "http://localhost:3000/api/health" "MEDUSA Frontend" || true

echo ""
log_info "Checking service ports..."
echo ""

# Check ports
check_port "localhost" "3000" "Frontend (Next.js)" || true
check_port "localhost" "8000" "Backend (FastAPI)" || true
check_port "localhost" "3001" "EHR API (Node.js)" || true
check_port "localhost" "3306" "MySQL Database" || true
check_port "localhost" "445" "Workstation SMB" || true
check_port "localhost" "5900" "Workstation VNC" || true

echo ""
log_info "Testing database connectivity..."
echo ""

# Test MySQL connection
if docker exec medusa_ehr_db mysql -u ehrapp -pWelcome123! -e "USE healthcare_db; SELECT COUNT(*) as patient_count FROM patients;" 2>/dev/null | grep -q "patient_count"; then
    PATIENT_COUNT=$(docker exec medusa_ehr_db mysql -u ehrapp -pWelcome123! -N -e "USE healthcare_db; SELECT COUNT(*) FROM patients;" 2>/dev/null)
    log_success "MySQL database accessible - Found $PATIENT_COUNT patients"
else
    log_error "MySQL database connection failed"
fi

echo ""
log_info "Testing API endpoints..."
echo ""

# Test EHR API endpoints
if curl -s http://localhost:3001/api/patients | grep -q "count"; then
    log_success "EHR API /api/patients endpoint working"
else
    log_error "EHR API /api/patients endpoint failed"
fi

if curl -s http://localhost:3001/api/users | grep -q "users"; then
    log_success "EHR API /api/users endpoint working"
else
    log_error "EHR API /api/users endpoint failed"
fi

echo ""
log_info "Checking workstation stability (5 second test)..."
echo ""

# Check if workstation is stable (not restarting)
WORKSTATION_STATUS_BEFORE=$(docker inspect -f '{{.RestartCount}}' medusa_workstation 2>/dev/null || echo "0")
sleep 5
WORKSTATION_STATUS_AFTER=$(docker inspect -f '{{.RestartCount}}' medusa_workstation 2>/dev/null || echo "0")

if [ "$WORKSTATION_STATUS_BEFORE" = "$WORKSTATION_STATUS_AFTER" ]; then
    log_success "Workstation container is STABLE (no restarts in 5 seconds)"
else
    log_error "Workstation container RESTARTED during test (loop detected!)"
    log_info "Showing last 20 lines of workstation logs:"
    docker logs --tail 20 medusa_workstation
fi

echo ""
echo "======================================================================"
echo "  Verification Complete"
echo "======================================================================"
echo ""

log_info "Summary of services:"
echo ""
echo "  Frontend:         http://localhost:3000"
echo "  MEDUSA Backend:   http://localhost:8000"
echo "  EHR API:          http://localhost:3001"
echo "  EHR Web Portal:   http://localhost:8080"
echo "  API Docs:         http://localhost:8000/docs"
echo ""

log_info "Database credentials:"
echo ""
echo "  MySQL:"
echo "    Host: localhost:3306"
echo "    User: ehrapp"
echo "    Pass: Welcome123!"
echo "    DB:   healthcare_db"
echo ""

log_info "Test vulnerabilities:"
echo ""
echo "  SQL Injection:    curl 'http://localhost:3001/api/patients/1%20OR%201=1'"
echo "  User Enumeration: curl http://localhost:3001/api/users"
echo "  Admin Endpoint:   curl http://localhost:3001/api/admin/config"
echo ""

if [ -n "$WORKSTATION_FAILED" ]; then
    log_warning "Workstation container needs attention. Check logs with:"
    echo "  docker logs medusa_workstation"
    echo ""
fi

log_success "Integration verification complete!"
echo ""
