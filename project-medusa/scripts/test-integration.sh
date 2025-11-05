#!/bin/bash
# ============================================================================
# MEDUSA Integration Test Script
# ============================================================================
# Tests all services and their integration
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Logging
log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}  ✓${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "${RED}  ✗${NC} $1"
    ((FAILED++))
}

log_warn() {
    echo -e "${YELLOW}  ⚠${NC} $1"
    ((WARNINGS++))
}

# Header
echo -e "${BLUE}"
echo "============================================================================"
echo "  MEDUSA Integration Tests"
echo "============================================================================"
echo -e "${NC}"

# Test 1: Docker Services Running
log_test "Checking Docker services..."
if docker ps | grep -q "medusa_backend"; then
    log_pass "Backend container running"
else
    log_fail "Backend container not running"
fi

if docker ps | grep -q "medusa_frontend"; then
    log_pass "Frontend container running"
else
    log_fail "Frontend container not running"
fi

if docker ps | grep -q "medusa_postgres"; then
    log_pass "PostgreSQL container running"
else
    log_fail "PostgreSQL container not running"
fi

if docker ps | grep -q "medusa_redis"; then
    log_pass "Redis container running"
else
    log_fail "Redis container not running"
fi

# Test 2: Health Endpoints
log_test "Testing health endpoints..."

if curl -sf http://localhost:8000/health | grep -q "healthy"; then
    log_pass "Backend health check passed"
else
    log_fail "Backend health check failed"
fi

if curl -sf http://localhost:3000/api/health | grep -q "ok"; then
    log_pass "Frontend health check passed"
else
    log_fail "Frontend health check failed"
fi

# Test 3: API Endpoints
log_test "Testing API endpoints..."

# Backend API health details
if curl -sf http://localhost:8000/api/health | grep -q "status"; then
    log_pass "Backend API health endpoint accessible"
else
    log_fail "Backend API health endpoint failed"
fi

# Session creation
if response=$(curl -sf -X POST http://localhost:8000/api/sessions -H "Content-Type: application/json" -d '{"target":"test","mode":"observe"}'); then
    if echo "$response" | grep -q "session_id"; then
        log_pass "Session creation endpoint works"
    else
        log_fail "Session creation returned unexpected response"
    fi
else
    log_fail "Session creation endpoint failed"
fi

# Test 4: Database Connectivity
log_test "Testing database connectivity..."

if docker-compose exec -T medusa-postgres pg_isready -U medusa &> /dev/null; then
    log_pass "PostgreSQL is accepting connections"
else
    log_fail "PostgreSQL connection failed"
fi

# Test 5: Redis Connectivity
log_test "Testing Redis connectivity..."

if docker-compose exec -T medusa-redis redis-cli ping | grep -q "PONG"; then
    log_pass "Redis is responding"
else
    log_fail "Redis connection failed"
fi

# Test 6: Network Connectivity
log_test "Testing network connectivity..."

# Check backend can reach postgres
if docker-compose exec -T medusa-backend ping -c 1 medusa-postgres &> /dev/null; then
    log_pass "Backend can reach PostgreSQL"
else
    log_warn "Backend cannot ping PostgreSQL (may be normal)"
fi

# Check backend can reach lab services
if docker-compose exec -T medusa-backend ping -c 1 ehr-database &> /dev/null; then
    log_pass "Backend can reach lab environment"
else
    log_warn "Backend cannot reach lab environment"
fi

# Test 7: Lab Services
log_test "Testing lab environment services..."

services=("ehr-webapp:8080" "ehr-api:3001" "ssh-server:2222" "ehr-database:3306")
for service in "${services[@]}"; do
    IFS=':' read -r name port <<< "$service"
    if nc -zv localhost "$port" 2>&1 | grep -q "succeeded\|Connected"; then
        log_pass "$name accessible on port $port"
    else
        log_fail "$name not accessible on port $port"
    fi
done

# Test 8: Docker Networks
log_test "Testing Docker networks..."

networks=("medusa-dmz" "healthcare-dmz" "healthcare-internal")
for network in "${networks[@]}"; do
    if docker network ls | grep -q "$network"; then
        log_pass "Network $network exists"
    else
        log_fail "Network $network not found"
    fi
done

# Test 9: Volume Persistence
log_test "Testing volume persistence..."

if docker volume ls | grep -q "medusa-postgres-data"; then
    log_pass "PostgreSQL data volume exists"
else
    log_fail "PostgreSQL data volume not found"
fi

if docker volume ls | grep -q "medusa-redis-data"; then
    log_pass "Redis data volume exists"
else
    log_fail "Redis data volume not found"
fi

# Test 10: Frontend Access
log_test "Testing frontend accessibility..."

if curl -sf http://localhost:3000 | grep -q "<!DOCTYPE html>"; then
    log_pass "Frontend serves HTML"
else
    log_fail "Frontend not serving content"
fi

# Test 11: WebSocket (basic connectivity)
log_test "Testing WebSocket endpoint..."

# Just check if the endpoint exists (actual WebSocket test would require wscat or similar)
if curl -sf -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:8000/ws/test-session 2>&1 | grep -q "400\|426\|Upgrade"; then
    log_pass "WebSocket endpoint exists"
else
    log_warn "WebSocket endpoint test inconclusive"
fi

# Test 12: Docker Socket Access
log_test "Testing Docker socket access..."

if docker-compose exec -T medusa-backend docker ps &> /dev/null; then
    log_pass "Backend has Docker socket access"
else
    log_warn "Backend cannot access Docker socket (required for container management)"
fi

# Summary
echo ""
echo -e "${BLUE}============================================================================${NC}"
echo -e "${GREEN}Passed:${NC}   $PASSED"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo -e "${RED}Failed:${NC}   $FAILED"
echo -e "${BLUE}============================================================================${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✨ All critical tests passed!${NC}"
    exit 0
elif [ $FAILED -le 2 ]; then
    echo -e "${YELLOW}⚠️  Some tests failed, but system may still be functional${NC}"
    exit 0
else
    echo -e "${RED}❌ Multiple tests failed - system needs attention${NC}"
    exit 1
fi

