#!/bin/bash

# MEDUSA Demo Setup Verification Script
# Run this before your demo to ensure everything is ready

set -e

echo "🔴 MEDUSA Demo Setup Verification"
echo "===================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check functions
check_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    FAILED=1
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

FAILED=0

# 1. Check Docker
echo "1. Checking Docker..."
if command -v docker &> /dev/null; then
    check_pass "Docker is installed"
    if docker ps &> /dev/null; then
        check_pass "Docker daemon is running"
    else
        check_fail "Docker daemon is not running"
    fi
else
    check_fail "Docker is not installed"
fi

# 2. Check Docker Compose
echo ""
echo "2. Checking Docker Compose..."
if command -v docker-compose &> /dev/null; then
    check_pass "Docker Compose is installed"
else
    check_fail "Docker Compose is not installed"
fi

# 3. Check Lab Environment
echo ""
echo "3. Checking Lab Environment..."
cd "$(dirname "$0")/../lab-environment" || exit 1

if [ -f "docker-compose.yml" ]; then
    check_pass "docker-compose.yml found"
    
    # Check if services are running
    if docker-compose ps | grep -q "Up"; then
        RUNNING_SERVICES=$(docker-compose ps | grep -c "Up" || true)
        check_pass "Lab services are running ($RUNNING_SERVICES services)"
        
        # Check specific services
        echo "   Checking individual services..."
        SERVICES=("medusa_ehr_web:8080" "medusa_ehr_api:3001" "medusa_ehr_db:3306" "medusa_ssh_server:2222")
        for service in "${SERVICES[@]}"; do
            IFS=':' read -r name port <<< "$service"
            if docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
                check_pass "   $name is running"
            else
                check_warn "   $name is not running"
            fi
        done
    else
        check_warn "Lab services are not running"
        echo "   Run: docker-compose up -d"
    fi
else
    check_fail "docker-compose.yml not found"
fi

# 4. Check Service Accessibility
echo ""
echo "4. Checking Service Accessibility..."

check_service() {
    local name=$1
    local url=$2
    if curl -s -f -o /dev/null --max-time 5 "$url" 2>/dev/null; then
        check_pass "$name is accessible ($url)"
    else
        check_warn "$name is not accessible ($url)"
    fi
}

check_service "EHR Web Portal" "http://localhost:8080"
check_service "EHR API" "http://localhost:3001/api/health"
check_service "Log Viewer" "http://localhost:8081"

# 5. Check MEDUSA Installation
echo ""
echo "5. Checking MEDUSA Installation..."
cd "$(dirname "$0")/.." || exit 1

if command -v medusa &> /dev/null; then
    check_pass "MEDUSA CLI is installed"
    
    # Check MEDUSA status
    if medusa status &> /dev/null; then
        check_pass "MEDUSA is configured"
    else
        check_warn "MEDUSA is not configured (run: medusa setup)"
    fi
else
    check_fail "MEDUSA CLI is not installed"
    echo "   Install with: cd medusa-cli && pip install -e ."
fi

# 6. Check Required Tools
echo ""
echo "6. Checking Required Tools..."

check_tool() {
    if command -v "$1" &> /dev/null; then
        check_pass "$1 is installed"
    else
        check_warn "$1 is not installed (optional but recommended)"
    fi
}

check_tool "nmap"
check_tool "mysql"
check_tool "curl"
check_tool "ssh"

# 7. Check Network Ports
echo ""
echo "7. Checking Network Ports..."

check_port() {
    local port=$1
    local service=$2
    if nc -z localhost "$port" 2>/dev/null || timeout 1 bash -c "echo > /dev/tcp/localhost/$port" 2>/dev/null; then
        check_pass "Port $port ($service) is open"
    else
        check_warn "Port $port ($service) is not accessible"
    fi
}

check_port "8080" "EHR Web Portal"
check_port "3001" "EHR API"
check_port "3306" "MySQL Database"
check_port "2222" "SSH Server"
check_port "21" "FTP Server"
check_port "389" "LDAP Server"
check_port "8081" "Log Viewer"

# 8. Check Database Access
echo ""
echo "8. Checking Database Access..."
if command -v mysql &> /dev/null; then
    if mysql -h localhost -P 3306 -u root -padmin123 -e "SHOW DATABASES;" &> /dev/null <<< "admin123"; then
        check_pass "Database is accessible"
    else
        check_warn "Database access test failed (may need manual verification)"
    fi
else
    check_warn "MySQL client not installed (database check skipped)"
fi

# 9. Check Disk Space
echo ""
echo "9. Checking Disk Space..."
AVAILABLE_SPACE=$(df -h . | awk 'NR==2 {print $4}' | sed 's/[^0-9]//')
if [ "$AVAILABLE_SPACE" -gt 5 ]; then
    check_pass "Sufficient disk space available"
else
    check_warn "Low disk space (< 5GB available)"
fi

# 10. Check Memory
echo ""
echo "10. Checking System Resources..."
TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
if [ "$TOTAL_MEM" -ge 8 ]; then
    check_pass "Sufficient RAM ($TOTAL_MEM GB)"
else
    check_warn "Low RAM ($TOTAL_MEM GB) - 8GB+ recommended"
fi

# Summary
echo ""
echo "===================================="
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All critical checks passed!${NC}"
    echo ""
    echo "You're ready for the demo!"
    echo ""
    echo "Next steps:"
    echo "  1. Review DEMO_SCRIPT.md"
    echo "  2. Review DEMO_QUICK_REFERENCE.md"
    echo "  3. Start demo with: medusa observe --target http://localhost:3001"
else
    echo -e "${RED}✗ Some checks failed${NC}"
    echo ""
    echo "Please fix the issues above before running the demo."
    exit 1
fi

echo ""
echo "Good luck with your demo! 🚀"

