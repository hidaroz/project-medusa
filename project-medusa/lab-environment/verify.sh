#!/bin/bash
set -euo pipefail

# ============================================================================
# MEDUSA Lab - Service Verification Script
# ============================================================================
# Purpose: Comprehensive testing of all services for accessibility and health
# Usage: ./verify.sh [--json] [--verbose]
# ============================================================================

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Output options
JSON_OUTPUT=false
VERBOSE=false

# Test results
declare -A test_results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_success() {
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "${GREEN}[✓]${NC} $1"
    fi
}

log_error() {
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "${RED}[✗]${NC} $1" >&2
    fi
}

log_warning() {
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "${YELLOW}[!]${NC} $1"
    fi
}

log_verbose() {
    if [ "$VERBOSE" = true ] && [ "$JSON_OUTPUT" = false ]; then
        echo -e "${CYAN}  └─${NC} $1"
    fi
}

# ============================================================================
# Test Functions
# ============================================================================

run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected="$3"
    
    ((TOTAL_TESTS++))
    
    if [ "$VERBOSE" = true ]; then
        log_verbose "Running: $test_command"
    fi
    
    if eval "$test_command" &>/dev/null; then
        if [ "$expected" = "pass" ]; then
            log_success "$test_name"
            test_results["$test_name"]="PASS"
            ((PASSED_TESTS++))
            return 0
        else
            log_error "$test_name (expected to fail but passed)"
            test_results["$test_name"]="FAIL"
            ((FAILED_TESTS++))
            return 1
        fi
    else
        if [ "$expected" = "fail" ]; then
            log_success "$test_name (expected failure)"
            test_results["$test_name"]="PASS"
            ((PASSED_TESTS++))
            return 0
        else
            log_error "$test_name"
            test_results["$test_name"]="FAIL"
            ((FAILED_TESTS++))
            return 1
        fi
    fi
}

# ============================================================================
# Service Tests
# ============================================================================

test_docker_running() {
    log_info "Checking Docker environment..."
    
    run_test "Docker daemon running" \
        "docker info" \
        "pass"
    
    run_test "Docker Compose available" \
        "docker-compose --version" \
        "pass"
}

test_containers_running() {
    log_info "Checking container status..."
    
    run_test "EHR Web container running" \
        "docker ps --filter name=medusa_ehr_web --filter status=running --quiet | grep -q ." \
        "pass"
    
    run_test "EHR Database container running" \
        "docker ps --filter name=medusa_ehr_db --filter status=running --quiet | grep -q ." \
        "pass"
    
    run_test "EHR API container running" \
        "docker ps --filter name=medusa_ehr_api --filter status=running --quiet | grep -q ." \
        "pass"
    
    run_test "SSH Server container running" \
        "docker ps --filter name=medusa_ssh_server --filter status=running --quiet | grep -q ." \
        "pass"
    
    run_test "FTP Server container running" \
        "docker ps --filter name=medusa_ftp_server --filter status=running --quiet | grep -q ." \
        "pass"
    
    run_test "LDAP Server container running" \
        "docker ps --filter name=medusa_ldap --filter status=running --quiet | grep -q ." \
        "pass"
    
    run_test "Log Collector container running" \
        "docker ps --filter name=medusa_logs --filter status=running --quiet | grep -q ." \
        "pass"
    
    run_test "Workstation container running" \
        "docker ps --filter name=medusa_workstation --filter status=running --quiet | grep -q ." \
        "pass"
}

test_web_services() {
    log_info "Testing web service endpoints..."
    
    # EHR Web Portal
    if http_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 2>/dev/null); then
        if [[ "$http_code" =~ ^(200|302|301)$ ]]; then
            log_success "EHR Web Portal responding (HTTP $http_code)"
            test_results["EHR Web Portal HTTP"]="PASS"
            ((TOTAL_TESTS++))
            ((PASSED_TESTS++))
        else
            log_error "EHR Web Portal returned HTTP $http_code"
            test_results["EHR Web Portal HTTP"]="FAIL"
            ((TOTAL_TESTS++))
            ((FAILED_TESTS++))
        fi
    else
        log_error "EHR Web Portal not responding"
        test_results["EHR Web Portal HTTP"]="FAIL"
        ((TOTAL_TESTS++))
        ((FAILED_TESTS++))
    fi
    
    # EHR API
    if http_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 2>/dev/null); then
        if [[ "$http_code" =~ ^(200|404)$ ]]; then
            log_success "EHR API responding (HTTP $http_code)"
            test_results["EHR API HTTP"]="PASS"
            ((TOTAL_TESTS++))
            ((PASSED_TESTS++))
        else
            log_error "EHR API returned HTTP $http_code"
            test_results["EHR API HTTP"]="FAIL"
            ((TOTAL_TESTS++))
            ((FAILED_TESTS++))
        fi
    else
        log_error "EHR API not responding"
        test_results["EHR API HTTP"]="FAIL"
        ((TOTAL_TESTS++))
        ((FAILED_TESTS++))
    fi
    
    # Log Collector
    if http_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8081 2>/dev/null); then
        if [[ "$http_code" =~ ^(200|404)$ ]]; then
            log_success "Log Collector responding (HTTP $http_code)"
            test_results["Log Collector HTTP"]="PASS"
            ((TOTAL_TESTS++))
            ((PASSED_TESTS++))
        else
            log_error "Log Collector returned HTTP $http_code"
            test_results["Log Collector HTTP"]="FAIL"
            ((TOTAL_TESTS++))
            ((FAILED_TESTS++))
        fi
    else
        log_error "Log Collector not responding"
        test_results["Log Collector HTTP"]="FAIL"
        ((TOTAL_TESTS++))
        ((FAILED_TESTS++))
    fi
}

test_network_services() {
    log_info "Testing network service ports..."
    
    # Helper function for port testing
    test_port() {
        local service_name="$1"
        local port="$2"
        
        ((TOTAL_TESTS++))
        
        # Try multiple methods to test port
        if command -v nc &>/dev/null; then
            if nc -z -w 2 localhost "$port" 2>/dev/null; then
                log_success "$service_name listening on port $port"
                test_results["$service_name Port"]="PASS"
                ((PASSED_TESTS++))
                return 0
            fi
        fi
        
        # Fallback to /dev/tcp
        if timeout 2 bash -c "echo > /dev/tcp/localhost/$port" 2>/dev/null; then
            log_success "$service_name listening on port $port"
            test_results["$service_name Port"]="PASS"
            ((PASSED_TESTS++))
            return 0
        fi
        
        log_error "$service_name not listening on port $port"
        test_results["$service_name Port"]="FAIL"
        ((FAILED_TESTS++))
        return 1
    }
    
    test_port "SSH Server" 2222
    test_port "FTP Server" 21
    test_port "LDAP Server" 389
    test_port "MySQL Database" 3306
    test_port "SMB (Workstation)" 445
}

test_database() {
    log_info "Testing database connectivity..."
    
    ((TOTAL_TESTS++))
    
    # Change to script directory for docker-compose
    cd "$SCRIPT_DIR"
    
    # Test MySQL ping
    if docker-compose exec -T ehr-database mysqladmin ping -h localhost -u root -padmin123 &>/dev/null; then
        log_success "MySQL Database responding"
        test_results["MySQL Ping"]="PASS"
        ((PASSED_TESTS++))
    else
        log_error "MySQL Database not responding"
        test_results["MySQL Ping"]="FAIL"
        ((FAILED_TESTS++))
    fi
    
    # Test database exists
    ((TOTAL_TESTS++))
    if docker-compose exec -T ehr-database mysql -u root -padmin123 -e "SHOW DATABASES;" 2>/dev/null | grep -q "healthcare_db"; then
        log_success "Healthcare database exists"
        test_results["Database Exists"]="PASS"
        ((PASSED_TESTS++))
    else
        log_error "Healthcare database not found"
        test_results["Database Exists"]="FAIL"
        ((FAILED_TESTS++))
    fi
    
    # Test table count
    ((TOTAL_TESTS++))
    if table_count=$(docker-compose exec -T ehr-database mysql -u root -padmin123 -D healthcare_db -e "SHOW TABLES;" 2>/dev/null | wc -l); then
        if [ "$table_count" -gt 1 ]; then
            log_success "Database tables initialized ($((table_count - 1)) tables)"
            test_results["Database Tables"]="PASS"
            ((PASSED_TESTS++))
            log_verbose "Found $((table_count - 1)) tables in healthcare_db"
        else
            log_warning "Database has no tables"
            test_results["Database Tables"]="FAIL"
            ((FAILED_TESTS++))
        fi
    else
        log_error "Could not query database tables"
        test_results["Database Tables"]="FAIL"
        ((FAILED_TESTS++))
    fi
}

test_networks() {
    log_info "Testing Docker networks..."
    
    run_test "DMZ network exists" \
        "docker network ls | grep -q 'healthcare-dmz\|medusa-dmz'" \
        "pass"
    
    run_test "Internal network exists" \
        "docker network ls | grep -q 'healthcare-internal\|medusa-internal'" \
        "pass"
    
    # Test network connectivity between services
    ((TOTAL_TESTS++))
    cd "$SCRIPT_DIR"
    if docker-compose exec -T ehr-webapp ping -c 1 ehr-database &>/dev/null; then
        log_success "Web app can reach database (internal network)"
        test_results["Internal Network Connectivity"]="PASS"
        ((PASSED_TESTS++))
    else
        log_error "Web app cannot reach database"
        test_results["Internal Network Connectivity"]="FAIL"
        ((FAILED_TESTS++))
    fi
}

test_volumes() {
    log_info "Testing Docker volumes..."
    
    run_test "Database volume exists" \
        "docker volume ls | grep -q 'db-data'" \
        "pass"
    
    run_test "Log volumes exist" \
        "docker volume ls | grep -q 'logs'" \
        "pass"
    
    # Check volume sizes (should have data)
    ((TOTAL_TESTS++))
    cd "$SCRIPT_DIR"
    if db_size=$(docker-compose exec -T ehr-database du -sh /var/lib/mysql 2>/dev/null | cut -f1); then
        log_success "Database volume has data ($db_size)"
        test_results["Database Volume Data"]="PASS"
        ((PASSED_TESTS++))
        log_verbose "Database size: $db_size"
    else
        log_warning "Could not check database volume size"
        test_results["Database Volume Data"]="FAIL"
        ((FAILED_TESTS++))
    fi
}

test_vulnerabilities() {
    log_info "Testing intentional vulnerabilities (sanity checks)..."
    
    # Test SQL injection point exists
    ((TOTAL_TESTS++))
    if curl -s "http://localhost:8080/search.php?query=test" 2>/dev/null | grep -q "search\|patient\|query"; then
        log_success "Search endpoint accessible (SQLi test point)"
        test_results["SQLi Endpoint"]="PASS"
        ((PASSED_TESTS++))
    else
        log_warning "Search endpoint not responding as expected"
        test_results["SQLi Endpoint"]="FAIL"
        ((FAILED_TESTS++))
    fi
    
    # Test weak credentials work
    ((TOTAL_TESTS++))
    cd "$SCRIPT_DIR"
    if docker-compose exec -T ehr-database mysql -u root -padmin123 -e "SELECT 1" &>/dev/null; then
        log_success "Weak database credentials work (as intended)"
        test_results["Weak DB Credentials"]="PASS"
        ((PASSED_TESTS++))
    else
        log_error "Database credentials test failed"
        test_results["Weak DB Credentials"]="FAIL"
        ((FAILED_TESTS++))
    fi
}

# ============================================================================
# Report Generation
# ============================================================================

generate_report() {
    if [ "$JSON_OUTPUT" = true ]; then
        generate_json_report
    else
        generate_text_report
    fi
}

generate_text_report() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              MEDUSA Lab Verification Report                  ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Calculate success rate
    if [ $TOTAL_TESTS -gt 0 ]; then
        SUCCESS_RATE=$(awk "BEGIN {printf \"%.1f\", ($PASSED_TESTS/$TOTAL_TESTS)*100}")
    else
        SUCCESS_RATE="0.0"
    fi
    
    echo -e "${BOLD}Test Summary:${NC}"
    echo -e "  Total Tests:   $TOTAL_TESTS"
    echo -e "  ${GREEN}Passed:        $PASSED_TESTS${NC}"
    echo -e "  ${RED}Failed:        $FAILED_TESTS${NC}"
    echo -e "  Success Rate:  $SUCCESS_RATE%"
    echo ""
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}${BOLD}✓ All tests passed! Lab is fully operational.${NC}"
        echo ""
        echo -e "${CYAN}The lab is ready for penetration testing.${NC}"
        return 0
    else
        echo -e "${YELLOW}${BOLD}⚠ Some tests failed. Review the output above.${NC}"
        echo ""
        echo -e "${YELLOW}Troubleshooting tips:${NC}"
        echo -e "  1. Ensure all containers are running: ${BOLD}docker-compose ps${NC}"
        echo -e "  2. Check logs: ${BOLD}docker-compose logs${NC}"
        echo -e "  3. Restart services: ${BOLD}docker-compose restart${NC}"
        echo -e "  4. Full reset: ${BOLD}docker-compose down -v && ./setup.sh${NC}"
        return 1
    fi
}

generate_json_report() {
    echo "{"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    echo "  \"summary\": {"
    echo "    \"total_tests\": $TOTAL_TESTS,"
    echo "    \"passed\": $PASSED_TESTS,"
    echo "    \"failed\": $FAILED_TESTS,"
    echo "    \"success_rate\": $(awk "BEGIN {printf \"%.2f\", ($PASSED_TESTS/$TOTAL_TESTS)*100}")"
    echo "  },"
    echo "  \"tests\": {"
    
    local first=true
    for test_name in "${!test_results[@]}"; do
        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi
        echo -n "    \"$test_name\": \"${test_results[$test_name]}\""
    done
    
    echo ""
    echo "  },"
    echo "  \"status\": \"$([ $FAILED_TESTS -eq 0 ] && echo "healthy" || echo "degraded")\""
    echo "}"
}

# ============================================================================
# Argument Parsing
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --json)
                JSON_OUTPUT=true
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
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    echo "MEDUSA Lab Verification Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --json       Output results in JSON format"
    echo "  --verbose    Show detailed test information"
    echo "  --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run verification with standard output"
    echo "  $0 --verbose          # Run with detailed output"
    echo "  $0 --json             # Output JSON for automation"
    echo ""
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    parse_arguments "$@"
    
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "${CYAN}${BOLD}MEDUSA Lab - Service Verification${NC}"
        echo -e "${CYAN}Starting comprehensive health checks...${NC}"
        echo ""
    fi
    
    # Change to script directory
    cd "$SCRIPT_DIR"
    
    # Run all tests
    test_docker_running
    test_containers_running
    test_web_services
    test_network_services
    test_database
    test_networks
    test_volumes
    test_vulnerabilities
    
    # Generate report
    generate_report
    
    # Exit with appropriate code
    if [ $FAILED_TESTS -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"

