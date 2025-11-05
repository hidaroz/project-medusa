# MEDUSA Fix Plan - Comprehensive Repair Strategy

**Date:** November 4, 2025
**Version:** 1.0.0
**Status:** Ready for Implementation
**Estimated Total Time:** 6-9 hours

---

## Overview

This document provides a detailed, step-by-step plan to fix all issues identified in the manual testing report. The plan is organized by priority and includes specific code changes, testing procedures, and validation steps.

---

## Executive Summary

### Issues to Fix
1. **🔴 CRITICAL:** LLM Response Parsing Bug (Issue #2)
2. **🟡 HIGH:** Missing Dependency - prompt_toolkit (Issue #1)
3. **🟠 MEDIUM:** FTP Server Unhealthy (Issue #3)

### Success Criteria
- ✅ All modes (observe, autonomous, shell) work with LLM
- ✅ No missing dependencies
- ✅ All Docker services healthy
- ✅ Integration tests pass
- ✅ Documentation updated

---

## Phase 1: Critical Fixes (Priority 1)

### Fix 1.1: LLM Response Parsing Bug
**Issue:** Issue #2 - LLM crashes with multi-part response error
**Time Estimate:** 1-2 hours
**Difficulty:** Medium

#### Step 1: Backup Current Code
```bash
cd medusa-cli/src/medusa/core
cp llm.py llm.py.backup
```

#### Step 2: Update LLM Response Handler

**File:** `medusa-cli/src/medusa/core/llm.py`
**Lines to modify:** 74-106 (the `_generate_with_retry` method)

**Current problematic code (lines 89-94):**
```python
if response and response.text:
    self.logger.debug(f"LLM response received: {len(response.text)} chars")
    return response.text
else:
    self.logger.warning("Empty response from LLM")
    last_error = "Empty response"
```

**Replace with:**
```python
if response:
    # Handle multi-part responses properly
    try:
        # Try simple text accessor first (for backwards compatibility)
        text = self._extract_text_from_response(response)
        if text:
            self.logger.debug(f"LLM response received: {len(text)} chars")
            return text
        else:
            self.logger.warning("Empty response from LLM")
            last_error = "Empty response"
    except Exception as e:
        last_error = f"Error parsing response: {str(e)}"
        self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
        await asyncio.sleep(2 ** attempt)
        continue
else:
    self.logger.warning("No response from LLM")
    last_error = "No response"
```

#### Step 3: Add Response Extraction Method

**Add this new method to the `LLMClient` class (around line 107, after `_generate_with_retry`):**

```python
def _extract_text_from_response(self, response) -> str:
    """
    Extract text from Gemini response, handling both simple and complex responses.

    Args:
        response: Gemini API response object

    Returns:
        Extracted text string

    Raises:
        ValueError: If response cannot be parsed
    """
    # Try the simple text accessor first (for single-part responses)
    try:
        if hasattr(response, 'text') and response.text:
            return response.text
    except ValueError as e:
        # This is expected for multi-part responses
        self.logger.debug(f"Simple text accessor failed (expected for multi-part): {e}")

    # Handle multi-part responses
    if not hasattr(response, 'candidates') or not response.candidates:
        raise ValueError("Response has no candidates")

    if len(response.candidates) == 0:
        raise ValueError("Response candidates list is empty")

    candidate = response.candidates[0]

    # Check if response was blocked by safety filters
    if hasattr(candidate, 'finish_reason'):
        from google.generativeai.types import FinishReason
        if candidate.finish_reason == FinishReason.SAFETY:
            self.logger.warning("Response blocked by safety filters")
            raise ValueError("Response blocked by safety filters")
        elif candidate.finish_reason == FinishReason.RECITATION:
            self.logger.warning("Response blocked due to recitation")
            raise ValueError("Response blocked due to recitation")

    # Extract text from all parts
    if not hasattr(candidate, 'content') or not candidate.content:
        raise ValueError("Candidate has no content")

    if not hasattr(candidate.content, 'parts') or not candidate.content.parts:
        raise ValueError("Content has no parts")

    # Concatenate all text parts
    text_parts = []
    for part in candidate.content.parts:
        if hasattr(part, 'text') and part.text:
            text_parts.append(part.text)

    if not text_parts:
        raise ValueError("No text found in response parts")

    return ''.join(text_parts)
```

#### Step 4: Test the Fix

**Create a test script:** `medusa-cli/test_llm_fix.py`

```python
#!/usr/bin/env python3
"""
Quick test script to verify LLM response parsing fix
"""
import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from medusa.core.llm import LLMClient, LLMConfig

async def test_llm():
    """Test LLM with a simple prompt"""

    # Load config
    import yaml
    config_path = Path.home() / ".medusa" / "config.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Create LLM client
    llm_config = LLMConfig(
        api_key=config['api_key'],
        model=config['llm']['model'],
        temperature=config['llm']['temperature'],
        max_tokens=config['llm']['max_tokens'],
        timeout=config['llm']['timeout'],
        max_retries=config['llm']['max_retries']
    )

    client = LLMClient(llm_config)

    # Test with simple prompt
    print("Testing LLM response parsing...")
    try:
        response = await client._generate_with_retry(
            "Say 'Hello, MEDUSA is working!' in one sentence."
        )
        print(f"✅ SUCCESS: Got response: {response[:100]}...")
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_llm())
    sys.exit(0 if success else 1)
```

**Run the test:**
```bash
cd medusa-cli
source ../.venv/bin/activate
python test_llm_fix.py
```

**Expected output:**
```
Testing LLM response parsing...
✅ SUCCESS: Got response: Hello, MEDUSA is working!...
```

#### Step 5: Test with Observe Mode

```bash
source .venv/bin/activate
timeout 120 medusa observe --target http://localhost:3001
```

**Expected behavior:**
- Should NOT crash with parsing error
- Should complete passive reconnaissance
- Should display findings
- Should generate report

#### Step 6: Verify Fix

**Checklist:**
- [ ] No more "response.text quick accessor" errors
- [ ] Observe mode completes successfully
- [ ] Findings are generated
- [ ] Log file created in `~/.medusa/logs/`
- [ ] Report generated in `~/.medusa/reports/`

---

### Fix 1.2: Add Missing Dependency
**Issue:** Issue #1 - prompt_toolkit missing from requirements
**Time Estimate:** 5 minutes
**Difficulty:** Easy

#### Step 1: Update requirements.txt

**File:** `medusa-cli/requirements.txt`
**Add after line 8 (after rich):**

```txt
# Terminal UI
rich==13.7.1
prompt_toolkit==3.0.52  # ADD THIS LINE

# HTTP Client (async)
httpx==0.26.0
```

#### Step 2: Update setup.py Comments

**File:** `medusa-cli/setup.py`
**Add comment around line 16:**

```python
# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    # Note: Includes prompt_toolkit for interactive shell completion
```

#### Step 3: Verify

```bash
cd medusa-cli
source ../.venv/bin/activate

# Reinstall to pick up new requirement
pip install -e .

# Verify installation
pip list | grep prompt
# Should show: prompt-toolkit    3.0.52
```

#### Step 4: Test Fresh Install

```bash
# Create fresh venv
cd /tmp
python3 -m venv test_medusa
source test_medusa/bin/activate

# Install medusa
cd /Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli
pip install -e .

# Test
medusa --version
# Should work without errors
```

---

## Phase 2: Medium Priority Fixes (Priority 2)

### Fix 2.1: Repair FTP Server
**Issue:** Issue #3 - FTP container unhealthy
**Time Estimate:** 30-60 minutes
**Difficulty:** Medium

#### Step 1: Investigate FTP Logs

```bash
# Check container logs
docker logs medusa_ftp_server --tail 50

# Check health check logs
docker inspect medusa_ftp_server | grep -A 10 Health
```

#### Step 2: Common FTP Issues to Check

**Issue A: Port binding conflict**
```bash
# Check if port 21 is already in use
lsof -i :21
netstat -an | grep :21
```

**Issue B: Permission issues**
```bash
# Check FTP container filesystem
docker exec medusa_ftp_server ls -la /etc/vsftpd/
docker exec medusa_ftp_server cat /var/log/vsftpd.log 2>&1
```

**Issue C: Configuration error**
```bash
# Validate vsftpd config
docker exec medusa_ftp_server vsftpd -version
docker exec medusa_ftp_server cat /etc/vsftpd/vsftpd.conf
```

#### Step 3: Review Health Check Configuration

**File:** `lab-environment/docker-compose.yml` or root `docker-compose.yml`

Find the FTP service definition and check health check:
```yaml
ftp-server:
  # ... other config ...
  healthcheck:
    test: ["CMD", "nc", "-z", "localhost", "21"]
    # OR
    test: ["CMD-SHELL", "netstat -an | grep :21 || exit 1"]
    interval: 10s
    timeout: 5s
    retries: 3
```

#### Step 4: Potential Fixes

**Fix A: Update health check (if nc is missing)**
```yaml
healthcheck:
  test: ["CMD-SHELL", "ps aux | grep vsftpd | grep -v grep || exit 1"]
  interval: 10s
  timeout: 5s
  retries: 3
```

**Fix B: Restart with clean state**
```bash
docker-compose down ftp-server
docker-compose up -d ftp-server
docker logs -f medusa_ftp_server
```

**Fix C: Rebuild if needed**
```bash
docker-compose build --no-cache ftp-server
docker-compose up -d ftp-server
```

#### Step 5: Verify Fix

```bash
# Check health status
docker ps | grep ftp
# Should show "healthy" not "unhealthy"

# Test FTP connectivity
ftp localhost 21
# OR
telnet localhost 21
# Should connect and show FTP banner
```

#### Step 6: Test FTP Functionality

```bash
# Test anonymous login
ftp localhost 21
# user: anonymous
# password: <any>

# Or with curl
curl ftp://localhost:21/ --user anonymous:test
```

---

### Fix 2.2: Add Integration Tests
**Time Estimate:** 2-4 hours
**Difficulty:** Medium-High

#### Step 1: Create LLM Response Test

**File:** `medusa-cli/tests/integration/test_llm_response_parsing.py`

```python
"""
Integration tests for LLM response parsing
Tests various Gemini response types
"""
import pytest
import asyncio
from medusa.core.llm import LLMClient, LLMConfig
from pathlib import Path
import yaml

@pytest.fixture
def llm_config():
    """Load LLM config from user's config file"""
    config_path = Path.home() / ".medusa" / "config.yaml"
    if not config_path.exists():
        pytest.skip("No MEDUSA config found")

    with open(config_path) as f:
        config = yaml.safe_load(f)

    return LLMConfig(
        api_key=config['api_key'],
        model=config['llm']['model'],
        temperature=config['llm']['temperature'],
        max_tokens=config['llm']['max_tokens'],
        timeout=config['llm']['timeout'],
        max_retries=config['llm']['max_retries']
    )

@pytest.fixture
def llm_client(llm_config):
    """Create LLM client"""
    return LLMClient(llm_config)

@pytest.mark.asyncio
async def test_simple_text_response(llm_client):
    """Test simple single-part text response"""
    response = await llm_client._generate_with_retry(
        "Say 'test' and nothing else."
    )
    assert response is not None
    assert len(response) > 0
    assert 'test' in response.lower()

@pytest.mark.asyncio
async def test_multi_part_response(llm_client):
    """Test multi-part response handling"""
    response = await llm_client._generate_with_retry(
        "Describe port scanning in exactly two sentences."
    )
    assert response is not None
    assert len(response) > 20  # Should be substantial

@pytest.mark.asyncio
async def test_code_response(llm_client):
    """Test response containing code blocks"""
    response = await llm_client._generate_with_retry(
        "Show a simple Python function that says hello. Use markdown code blocks."
    )
    assert response is not None
    assert 'def' in response or 'hello' in response.lower()

@pytest.mark.asyncio
async def test_json_response(llm_client):
    """Test JSON response parsing"""
    response = await llm_client._generate_with_retry(
        "Return this exact JSON: {\"status\": \"ok\", \"value\": 42}"
    )
    assert response is not None
    assert 'status' in response or 'ok' in response

@pytest.mark.asyncio
async def test_long_response(llm_client):
    """Test handling of long responses"""
    response = await llm_client._generate_with_retry(
        "List 10 common web vulnerabilities with brief descriptions."
    )
    assert response is not None
    assert len(response) > 100
```

#### Step 2: Create End-to-End Observe Mode Test

**File:** `medusa-cli/tests/integration/test_observe_mode_e2e.py`

```python
"""
End-to-end test for observe mode
"""
import pytest
import asyncio
import subprocess
import time
from pathlib import Path

@pytest.mark.integration
@pytest.mark.slow
def test_observe_mode_completes():
    """Test that observe mode completes without crashing"""

    # Start observe mode with timeout
    process = subprocess.Popen(
        ['medusa', 'observe', '--target', 'http://localhost:3001'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        # Wait up to 120 seconds
        stdout, stderr = process.communicate(timeout=120)

        # Check for success indicators
        assert 'LLM response' not in stderr  # Should not have LLM errors
        assert process.returncode == 0 or 'Reconnaissance complete' in stdout

        # Check log was created
        logs_dir = Path.home() / ".medusa" / "logs"
        log_files = list(logs_dir.glob("run-*.json"))
        assert len(log_files) > 0, "No log files created"

    except subprocess.TimeoutExpired:
        process.kill()
        pytest.fail("Observe mode timed out after 120 seconds")

@pytest.mark.integration
def test_observe_mode_generates_report():
    """Test that observe mode generates a report"""

    # Run observe mode
    result = subprocess.run(
        ['medusa', 'observe', '--target', 'localhost'],
        capture_output=True,
        text=True,
        timeout=120
    )

    # Check reports directory
    reports_dir = Path.home() / ".medusa" / "reports"
    report_files = list(reports_dir.glob("report-*.html"))

    assert len(report_files) > 0, "No report files generated"
```

#### Step 3: Run Tests

```bash
cd medusa-cli
source ../.venv/bin/activate

# Install test dependencies
pip install pytest pytest-asyncio pytest-timeout

# Run LLM tests
pytest tests/integration/test_llm_response_parsing.py -v

# Run observe mode test (slow)
pytest tests/integration/test_observe_mode_e2e.py -v -s

# Run all integration tests
pytest tests/integration/ -v
```

---

## Phase 3: Documentation & Polish (Priority 3)

### Fix 3.1: Update Documentation
**Time Estimate:** 2-3 hours
**Difficulty:** Easy

#### Update 1: README.md

**Add troubleshooting section:**

```markdown
## 🔧 Troubleshooting

### Common Issues

#### Issue: `ModuleNotFoundError: No module named 'prompt_toolkit'`
**Solution:** Install missing dependency:
```bash
pip install prompt_toolkit==3.0.52
```

#### Issue: LLM response parsing errors
**Symptoms:** Error message about `response.text` accessor
**Solution:** Update to latest version with multi-part response support
```bash
cd medusa-cli
git pull
pip install -e . --upgrade
```

#### Issue: FTP server unhealthy in Docker
**Solution:** Restart the FTP container:
```bash
docker-compose restart ftp-server
docker logs -f medusa_ftp_server
```

#### Issue: Observe mode hangs or times out
**Symptoms:** No progress after "Agent Thinking"
**Troubleshooting:**
1. Check API key: `cat ~/.medusa/config.yaml | grep api_key`
2. Test API connectivity: `curl https://generativelanguage.googleapis.com/v1beta/models -H "x-goog-api-key: YOUR_KEY"`
3. Check rate limits in Google Cloud Console
4. Try using mock mode: `medusa observe --target localhost --mock`
```

#### Update 2: Create TROUBLESHOOTING.md

**File:** `docs/TROUBLESHOOTING.md`

```markdown
# MEDUSA Troubleshooting Guide

## Installation Issues

### Missing Dependencies
If you get import errors, install all dependencies:
```bash
cd medusa-cli
pip install -r requirements.txt
pip install -e .
```

Required packages:
- typer[all]==0.9.0
- rich==13.7.1
- **prompt_toolkit==3.0.52** ⚠️ Often missed
- httpx==0.26.0
- pyyaml==6.0.1
- google-generativeai==0.3.2
- jinja2==3.1.3

[... continue with detailed troubleshooting ...]
```

#### Update 3: Add Developer Setup Guide

**File:** `docs/DEVELOPER_SETUP.md`

```markdown
# Developer Setup Guide

## Prerequisites
- Python 3.9+ (3.13 recommended)
- Docker Desktop
- Git
- 8GB+ RAM

## Fresh Installation

### 1. Clone Repository
```bash
git clone <repo-url>
cd project-medusa
```

### 2. Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install MEDUSA CLI
```bash
cd medusa-cli
pip install -e ".[dev]"  # Install with dev dependencies
```

### 4. Verify Installation
```bash
medusa --version  # Should show 1.0.0
medusa status     # Should show config
```

### 5. Start Docker Lab
```bash
cd ../lab-environment
cp .env.example .env
# Edit .env and set passwords
docker-compose up -d
```

### 6. Run Tests
```bash
cd ../medusa-cli
pytest tests/ -v
```

[... continue with detailed setup ...]
```

---

## Phase 4: Validation & Testing (Final Step)

### Validation Checklist

#### Critical Functionality
- [ ] `medusa --version` works
- [ ] `medusa status` shows configuration
- [ ] `medusa observe --target localhost:3001` completes successfully
- [ ] `medusa run --autonomous --target localhost` works (with approval)
- [ ] `medusa shell --target localhost` starts interactive shell
- [ ] Reports generate without errors

#### Docker Lab
- [ ] All 11 services start successfully
- [ ] All services show "healthy" status
- [ ] FTP server is accessible
- [ ] Web UIs load (ports 8080, 8000, 8081)
- [ ] APIs respond to requests

#### Dependencies
- [ ] All Python packages install without errors
- [ ] `requirements.txt` is complete
- [ ] Fresh install works in new venv

#### Testing
- [ ] Unit tests pass: `pytest tests/unit/ -v`
- [ ] Integration tests pass: `pytest tests/integration/ -v`
- [ ] LLM response tests pass
- [ ] Observe mode e2e test passes

#### Documentation
- [ ] README.md is up to date
- [ ] TROUBLESHOOTING.md exists
- [ ] All fixes are documented
- [ ] Known issues section updated

---

## Final Testing Script

Create `scripts/validate_fixes.sh`:

```bash
#!/bin/bash
# Comprehensive validation script for MEDUSA fixes

set -e

echo "🔍 MEDUSA Validation Script"
echo "================================"

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check 1: Virtual environment
echo -e "\n${YELLOW}[1/8]${NC} Checking virtual environment..."
if [ -d ".venv" ]; then
    echo -e "${GREEN}✓${NC} Virtual environment exists"
else
    echo -e "${RED}✗${NC} Virtual environment not found"
    exit 1
fi

# Check 2: Dependencies
echo -e "\n${YELLOW}[2/8]${NC} Checking dependencies..."
source .venv/bin/activate
if pip list | grep -q "prompt-toolkit"; then
    echo -e "${GREEN}✓${NC} prompt_toolkit installed"
else
    echo -e "${RED}✗${NC} prompt_toolkit missing"
    exit 1
fi

# Check 3: CLI works
echo -e "\n${YELLOW}[3/8]${NC} Testing CLI..."
if medusa --version > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} CLI loads successfully"
else
    echo -e "${RED}✗${NC} CLI failed to load"
    exit 1
fi

# Check 4: Docker services
echo -e "\n${YELLOW}[4/8]${NC} Checking Docker services..."
UNHEALTHY=$(docker ps --filter health=unhealthy --format "{{.Names}}" | wc -l)
if [ "$UNHEALTHY" -eq 0 ]; then
    echo -e "${GREEN}✓${NC} All Docker services healthy"
else
    echo -e "${RED}✗${NC} $UNHEALTHY services unhealthy"
    docker ps --filter health=unhealthy
fi

# Check 5: LLM test
echo -e "\n${YELLOW}[5/8]${NC} Testing LLM response parsing..."
cd medusa-cli
if [ -f "test_llm_fix.py" ]; then
    if python test_llm_fix.py > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} LLM parsing works"
    else
        echo -e "${RED}✗${NC} LLM parsing failed"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠${NC} LLM test script not found, skipping"
fi
cd ..

# Check 6: Unit tests
echo -e "\n${YELLOW}[6/8]${NC} Running unit tests..."
cd medusa-cli
if pytest tests/unit/ -q > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Unit tests pass"
else
    echo -e "${RED}✗${NC} Unit tests failed"
    pytest tests/unit/ -v
    exit 1
fi
cd ..

# Check 7: Observe mode quick test
echo -e "\n${YELLOW}[7/8]${NC} Testing observe mode (30 second timeout)..."
timeout 30 medusa observe --target localhost > /dev/null 2>&1 &
OBSERVE_PID=$!
sleep 5
if ps -p $OBSERVE_PID > /dev/null; then
    echo -e "${GREEN}✓${NC} Observe mode started successfully"
    kill $OBSERVE_PID 2>/dev/null || true
else
    echo -e "${RED}✗${NC} Observe mode crashed"
    exit 1
fi

# Check 8: Logs and reports
echo -e "\n${YELLOW}[8/8]${NC} Checking logs and reports..."
if [ -d "$HOME/.medusa/logs" ] && [ -d "$HOME/.medusa/reports" ]; then
    LOG_COUNT=$(find "$HOME/.medusa/logs" -name "*.json" | wc -l)
    REPORT_COUNT=$(find "$HOME/.medusa/reports" -name "*.html" | wc -l)
    echo -e "${GREEN}✓${NC} Found $LOG_COUNT logs and $REPORT_COUNT reports"
else
    echo -e "${RED}✗${NC} Logs or reports directory missing"
    exit 1
fi

# Final summary
echo -e "\n${GREEN}================================${NC}"
echo -e "${GREEN}✓ All validation checks passed!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Run full integration tests: pytest tests/integration/ -v"
echo "  2. Test observe mode: medusa observe --target localhost:3001"
echo "  3. Review generated reports: medusa reports"
```

Make executable and run:
```bash
chmod +x scripts/validate_fixes.sh
./scripts/validate_fixes.sh
```

---

## Success Metrics

### Before Fixes
- ❌ Observe mode: BROKEN (crashes)
- ❌ Autonomous mode: BROKEN (crashes)
- ❌ Shell mode with LLM: BROKEN (crashes)
- ⚠️ Fresh install: BROKEN (missing dependency)
- ⚠️ FTP service: UNHEALTHY
- **Overall Status:** 40% functional

### After Fixes
- ✅ Observe mode: WORKING
- ✅ Autonomous mode: WORKING
- ✅ Shell mode with LLM: WORKING
- ✅ Fresh install: WORKING
- ✅ FTP service: HEALTHY
- **Overall Status:** 100% functional

---

## Risk Management

### Risks During Implementation

#### Risk 1: LLM API Changes
**Mitigation:** Test with multiple response types; add comprehensive error handling

#### Risk 2: Breaking Existing Functionality
**Mitigation:** Keep backup (`llm.py.backup`); run full test suite before/after

#### Risk 3: Docker Issues
**Mitigation:** Document current state; use `docker-compose down && up` for clean restart

#### Risk 4: Time Overruns
**Mitigation:** Implement fixes in priority order; each fix is independent

---

## Rollback Plan

If any fix causes issues:

### Rollback LLM Changes
```bash
cd medusa-cli/src/medusa/core
cp llm.py.backup llm.py
pip install -e . --force-reinstall
```

### Rollback Docker Changes
```bash
git checkout docker-compose.yml
docker-compose down
docker-compose up -d
```

### Rollback Requirements
```bash
git checkout medusa-cli/requirements.txt
pip install -r medusa-cli/requirements.txt --force-reinstall
```

---

## Post-Implementation Tasks

### Code Review
- [ ] Review all changes with team
- [ ] Ensure code follows style guide
- [ ] Check for security implications

### Testing
- [ ] Run full test suite
- [ ] Manual testing of all modes
- [ ] Performance testing

### Documentation
- [ ] Update changelog
- [ ] Add release notes
- [ ] Update version number if needed

### Deployment
- [ ] Create PR with all fixes
- [ ] Get code review approval
- [ ] Merge to main branch
- [ ] Tag release
- [ ] Update documentation site

---

## Conclusion

This fix plan provides a comprehensive, step-by-step approach to resolving all identified issues in MEDUSA. Following this plan will result in a fully functional AI-powered penetration testing tool.

**Estimated Timeline:**
- Phase 1 (Critical): 2-3 hours
- Phase 2 (Medium): 3-5 hours
- Phase 3 (Documentation): 2-3 hours
- Phase 4 (Validation): 1-2 hours
- **Total: 8-13 hours** (including testing and validation)

**Next Step:** Begin with Phase 1, Fix 1.1 (LLM Response Parsing Bug)

---

**Document Version:** 1.0
**Last Updated:** November 4, 2025
**Status:** Ready for Implementation
