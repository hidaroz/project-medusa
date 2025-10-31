#!/bin/bash
# MEDUSA Lab Verification Script
# Tests if all services are up and responding

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   MEDUSA Lab - Service Verification               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

FAILED=0

# Function to check HTTP service
check_http() {
    local name=$1
    local url=$2
    local expected_code=$3
    
    echo -n "Checking $name... "
    
    if command -v curl &> /dev/null; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" = "$expected_code" ]; then
            echo -e "${GREEN}✓ OK${NC} (HTTP $HTTP_CODE)"
        else
            echo -e "${RED}✗ FAILED${NC} (HTTP $HTTP_CODE, expected $expected_code)"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "${YELLOW}⚠ SKIPPED${NC} (curl not installed)"
    fi
}

# Function to check port
check_port() {
    local name=$1
    local host=$2
    local port=$3
    
    echo -n "Checking $name... "
    
    if command -v nc &> /dev/null; then
        if nc -z -w2 "$host" "$port" 2>/dev/null; then
            echo -e "${GREEN}✓ OK${NC} (port $port open)"
        else
            echo -e "${RED}✗ FAILED${NC} (port $port closed)"
            FAILED=$((FAILED + 1))
        fi
    elif command -v telnet &> /dev/null; then
        if timeout 2 telnet "$host" "$port" 2>/dev/null | grep -q "Connected"; then
            echo -e "${GREEN}✓ OK${NC} (port $port open)"
        else
            echo -e "${RED}✗ FAILED${NC} (port $port closed)"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "${YELLOW}⚠ SKIPPED${NC} (nc/telnet not installed)"
    fi
}

# Function to check Docker container
check_container() {
    local name=$1
    local container=$2
    
    echo -n "Checking $name container... "
    
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        STATUS=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null)
        if [ "$STATUS" = "running" ]; then
            echo -e "${GREEN}✓ OK${NC} (running)"
        else
            echo -e "${RED}✗ FAILED${NC} (status: $STATUS)"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "${RED}✗ FAILED${NC} (container not found)"
        FAILED=$((FAILED + 1))
    fi
}

echo "═══════════════════════════════════════════════════"
echo "Container Status"
echo "═══════════════════════════════════════════════════"

check_container "EHR Web Portal" "medusa_ehr_web"
check_container "EHR Database" "medusa_ehr_db"
check_container "EHR API" "medusa_ehr_api"
check_container "SSH Server" "medusa_ssh_server"
check_container "FTP Server" "medusa_ftp_server"
check_container "LDAP Server" "medusa_ldap"
check_container "Log Collector" "medusa_logs"
check_container "Workstation" "medusa_workstation"

echo ""
echo "═══════════════════════════════════════════════════"
echo "HTTP Services"
echo "═══════════════════════════════════════════════════"

check_http "EHR Web Portal" "http://localhost:8080" "200"
check_http "EHR API Health" "http://localhost:3000/health" "200"
check_http "Log Viewer" "http://localhost:8081" "200"

echo ""
echo "═══════════════════════════════════════════════════"
echo "Network Services"
echo "═══════════════════════════════════════════════════"

check_port "MySQL" "localhost" "3306"
check_port "SSH" "localhost" "2222"
check_port "FTP" "localhost" "21"
check_port "LDAP" "localhost" "389"
check_port "SMB" "localhost" "445"

echo ""
echo "═══════════════════════════════════════════════════"
echo "Network Connectivity"
echo "═══════════════════════════════════════════════════"

# Check if networks exist
echo -n "Checking DMZ network... "
if docker network inspect medusa-dmz &>/dev/null; then
    echo -e "${GREEN}✓ OK${NC}"
else
    echo -e "${RED}✗ FAILED${NC}"
    FAILED=$((FAILED + 1))
fi

echo -n "Checking Internal network... "
if docker network inspect medusa-internal &>/dev/null; then
    echo -e "${GREEN}✓ OK${NC}"
else
    echo -e "${RED}✗ FAILED${NC}"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "Database Connectivity"
echo "═══════════════════════════════════════════════════"

echo -n "Checking database connection... "
if docker exec medusa_ehr_db mysqladmin ping -h localhost -u root -padmin123 &>/dev/null; then
    echo -e "${GREEN}✓ OK${NC}"
else
    echo -e "${RED}✗ FAILED${NC}"
    FAILED=$((FAILED + 1))
fi

echo -n "Checking healthcare_db exists... "
if docker exec medusa_ehr_db mysql -u root -padmin123 -e "USE healthcare_db" &>/dev/null; then
    echo -e "${GREEN}✓ OK${NC}"
else
    echo -e "${RED}✗ FAILED${NC}"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "═══════════════════════════════════════════════════"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed! Lab is ready for testing.${NC}"
    echo ""
    echo "Access Points:"
    echo "  • EHR Portal: http://localhost:8080"
    echo "  • API: http://localhost:3000"
    echo "  • Logs: http://localhost:8081"
    echo ""
    exit 0
else
    echo -e "${RED}✗ $FAILED check(s) failed. Please review the output above.${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  • Check container logs: docker-compose logs [service-name]"
    echo "  • Restart services: docker-compose restart"
    echo "  • Complete reset: docker-compose down -v && docker-compose up -d"
    echo ""
    exit 1
fi

