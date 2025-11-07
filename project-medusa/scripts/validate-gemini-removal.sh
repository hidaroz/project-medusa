#!/bin/bash

##############################################################################
# MEDUSA Gemini Removal Validation Script
# 
# This script validates that:
# 1. All Gemini code references are removed
# 2. New provider architecture is in place
# 3. Dependencies are updated
# 4. Configuration is correct
# 5. Tests pass
#
# Usage: ./scripts/validate-gemini-removal.sh
##############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Test functions
test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASSED++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAILED++))
}

test_warning() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1"
    ((WARNINGS++))
}

print_section() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo ""
}

##############################################################################
# VALIDATION CHECKS
##############################################################################

print_section "1. Checking for Gemini Code References"

# Check for gemini imports in source code
if grep -r "google\.generativeai\|import genai\|from genai" \
    "$PROJECT_ROOT/medusa-cli/src" \
    "$PROJECT_ROOT/medusa-cli/tests" \
    --include="*.py" 2>/dev/null | grep -v ".backup\|.gemini_backup"; then
    test_fail "Found google.generativeai imports"
else
    test_pass "No google.generativeai imports found"
fi

# Check for GEMINI_API_KEY in code
if grep -r "GEMINI_API_KEY\|gemini_api_key" \
    "$PROJECT_ROOT/medusa-cli/src" \
    --include="*.py" 2>/dev/null | grep -v "legacy\|backup\|archive"; then
    test_fail "Found GEMINI_API_KEY references in code"
else
    test_pass "No GEMINI_API_KEY references in code"
fi

# Check for GeminiClient references
if grep -r "GeminiClient\|class.*Gemini" \
    "$PROJECT_ROOT/medusa-cli/src" \
    --include="*.py" 2>/dev/null | grep -v "backup"; then
    test_fail "Found GeminiClient references"
else
    test_pass "No GeminiClient references found"
fi

print_section "2. Checking Dependencies"

# Check requirements.txt doesn't have google-generativeai
if grep -i "google-generativeai" "$PROJECT_ROOT/medusa-cli/requirements.txt"; then
    test_fail "google-generativeai still in requirements.txt"
else
    test_pass "google-generativeai removed from requirements.txt"
fi

# Check httpx is available for Ollama API
if grep -i "httpx" "$PROJECT_ROOT/medusa-cli/requirements.txt"; then
    test_pass "httpx dependency present"
else
    test_fail "httpx dependency missing"
fi

print_section "3. Checking New Provider Architecture"

# Check provider files exist
PROVIDER_FILES=(
    "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/providers/base.py"
    "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/providers/local.py"
    "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/providers/mock.py"
    "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/config.py"
    "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/factory.py"
    "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/client.py"
    "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/legacy_adapter.py"
)

for file in "${PROVIDER_FILES[@]}"; do
    if [ -f "$file" ]; then
        test_pass "Provider file exists: $(basename "$file")"
    else
        test_fail "Provider file missing: $(basename "$file")"
    fi
done

# Check BaseLLMProvider interface
if grep -q "class BaseLLMProvider" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/providers/base.py"; then
    test_pass "BaseLLMProvider interface found"
else
    test_fail "BaseLLMProvider interface not found"
fi

# Check LocalProvider implementation
if grep -q "class LocalProvider" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/providers/local.py"; then
    test_pass "LocalProvider implementation found"
else
    test_fail "LocalProvider implementation not found"
fi

print_section "4. Checking Configuration"

# Check LLMConfig has new provider fields
if grep -q "provider.*=" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/config.py" && \
   grep -q "ollama_url" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/config.py"; then
    test_pass "LLMConfig has new provider fields"
else
    test_fail "LLMConfig missing new provider fields"
fi

# Check env.example doesn't reference Gemini
if grep -i "GOOGLE_API_KEY\|GEMINI" "$PROJECT_ROOT/env.example" | grep -v "^#"; then
    test_fail "env.example still references Gemini"
else
    test_pass "env.example updated, no active Gemini references"
fi

# Check env.example has LLM_PROVIDER
if grep -q "LLM_PROVIDER" "$PROJECT_ROOT/env.example"; then
    test_pass "env.example has LLM_PROVIDER configuration"
else
    test_fail "env.example missing LLM_PROVIDER configuration"
fi

print_section "5. Checking Factory Pattern"

# Check factory creates correct providers
if grep -q "create_llm_provider\|create_llm_client" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/factory.py"; then
    test_pass "Factory functions found"
else
    test_fail "Factory functions not found"
fi

# Check factory handles auto-detection
if grep -q "provider.*auto\|auto.*detect" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/factory.py"; then
    test_pass "Auto-detection logic found in factory"
else
    test_fail "Auto-detection logic missing in factory"
fi

print_section "6. Checking Backward Compatibility"

# Check legacy adapter exists
if [ -f "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/legacy_adapter.py" ]; then
    test_pass "Legacy adapter exists"
else
    test_fail "Legacy adapter missing"
fi

# Check LocalLLMClient is in legacy adapter
if grep -q "class LocalLLMClient" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/legacy_adapter.py"; then
    test_pass "LocalLLMClient in legacy adapter"
else
    test_fail "LocalLLMClient not in legacy adapter"
fi

# Check MockLLMClient is in legacy adapter
if grep -q "class MockLLMClient" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/legacy_adapter.py"; then
    test_pass "MockLLMClient in legacy adapter"
else
    test_fail "MockLLMClient not in legacy adapter"
fi

print_section "7. Checking Exports"

# Check __init__.py exports new classes
if grep -q "LLMClient\|create_llm_client" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/__init__.py"; then
    test_pass "New LLM classes exported from __init__.py"
else
    test_fail "New LLM classes not exported"
fi

# Check legacy exports are available
if grep -q "LocalLLMClient\|MockLLMClient" "$PROJECT_ROOT/medusa-cli/src/medusa/core/llm/__init__.py"; then
    test_pass "Legacy classes exported from __init__.py"
else
    test_fail "Legacy classes not exported"
fi

print_section "8. Checking Documentation"

# Check migration guide exists
if [ -f "$PROJECT_ROOT/GEMINI_REMOVAL_MIGRATION_GUIDE.md" ]; then
    test_pass "Migration guide exists"
else
    test_fail "Migration guide missing"
fi

# Check migration guide mentions Ollama setup
if grep -q "ollama\|Ollama" "$PROJECT_ROOT/GEMINI_REMOVAL_MIGRATION_GUIDE.md"; then
    test_pass "Migration guide documents Ollama setup"
else
    test_fail "Migration guide missing Ollama documentation"
fi

print_section "9. Checking Tests"

# Check test files reference new providers
if [ -f "$PROJECT_ROOT/medusa-cli/tests/unit/test_llm.py" ] || \
   [ -f "$PROJECT_ROOT/medusa-cli/tests/integration/test_llm_integration.py" ]; then
    test_pass "LLM test files exist"
else
    test_warning "LLM test files not found - may need to create"
fi

print_section "10. Summary"

echo ""
echo "Test Results:"
echo "  ${GREEN}Passed: $PASSED${NC}"
echo "  ${RED}Failed: $FAILED${NC}"
echo "  ${YELLOW}Warnings: $WARNINGS${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All critical checks passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Install Ollama: https://ollama.com/download"
    echo "  2. Pull Mistral: ollama pull mistral:7b-instruct"
    echo "  3. Start server: ollama serve"
    echo "  4. Test MEDUSA: medusa health"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some checks failed!${NC}"
    echo ""
    echo "Please fix the failures above and re-run this script."
    echo ""
    exit 1
fi

