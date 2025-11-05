# MEDUSA Test Suite Documentation

> Comprehensive testing strategy for the MEDUSA AI Pentesting Agent

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Test Categories](#test-categories)
- [Lab Environment](#lab-environment)
- [Coverage Requirements](#coverage-requirements)
- [CI/CD Integration](#cicd-integration)
- [Writing New Tests](#writing-new-tests)
- [Troubleshooting](#troubleshooting)

## Overview

MEDUSA uses a comprehensive multi-tier testing strategy to ensure reliability, security, and performance:

```
┌─────────────────────────────────────────────────────────┐
│                    Test Pyramid                          │
├─────────────────────────────────────────────────────────┤
│                   E2E Tests (Slow)                       │
│              ▲                                           │
│             ╱ ╲     Full workflows against lab           │
│            ╱   ╲    ~10-15 tests                         │
│           ╱─────╲                                        │
│          ╱       ╲                                       │
│         ╱ Integration╲  Component interactions           │
│        ╱   Tests      ╲ ~30-40 tests                     │
│       ╱───────────────╲                                  │
│      ╱                 ╲                                 │
│     ╱   Unit Tests      ╲ Fast, isolated                │
│    ╱     ~100+ tests     ╲                              │
│   ╱───────────────────────╲                             │
└─────────────────────────────────────────────────────────┘
```

## Test Structure

```
tests/
├── README.md                      # This file
├── conftest.py                    # Shared pytest fixtures
├── __init__.py
│
├── unit/                          # Unit tests (fast, isolated)
│   ├── test_llm.py               # LLM client tests
│   ├── test_approval.py          # Approval system tests
│   ├── test_config.py            # Configuration tests
│   └── test_reporter.py          # Report generation tests
│
├── integration/                   # Integration tests (with dependencies)
│   ├── test_llm_integration.py   # Real LLM integration
│   ├── test_lab_connectivity.py  # Lab environment connectivity
│   └── test_observe_mode.py      # Observe mode integration
│
├── e2e/                          # End-to-end tests (full workflows)
│   └── test_autonomous_mode.py   # Autonomous mode E2E tests
│
├── performance/                   # Performance & benchmarks
│   └── test_benchmarks.py        # Performance benchmarks
│
├── security/                      # Security tests
│   └── test_input_validation.py  # Input validation & security
│
└── fixtures/                      # Test data & fixtures
    ├── sample_config.yaml
    └── mock_responses.json
```

## Running Tests

### Quick Start

```bash
# Run all tests
pytest

# Run specific test category
pytest tests/unit/              # Unit tests only
pytest tests/integration/       # Integration tests
pytest tests/e2e/              # E2E tests

# Run with coverage
pytest --cov=medusa --cov-report=html

# Run with specific markers
pytest -m unit                 # Unit tests
pytest -m integration          # Integration tests
pytest -m slow                 # Slow tests
pytest -m requires_docker      # Tests requiring Docker
```

### Test Markers

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Fast, isolated unit tests
- `@pytest.mark.integration` - Tests with external dependencies
- `@pytest.mark.e2e` - End-to-end workflow tests
- `@pytest.mark.slow` - Tests that take > 1 second
- `@pytest.mark.requires_docker` - Needs Docker/lab environment
- `@pytest.mark.requires_api` - Needs real API key (Gemini)
- `@pytest.mark.performance` - Performance benchmarks
- `@pytest.mark.security` - Security validation tests

### Running Tests by Speed

```bash
# Fast tests only (< 1 second)
pytest -m "not slow"

# All tests including slow ones
pytest

# Only slow tests
pytest -m slow
```

### Running Tests with Lab Environment

```bash
# 1. Start the lab environment
cd ../lab-environment
./start.sh

# 2. Run tests that require lab
cd ../medusa-cli
pytest -m requires_docker

# 3. Cleanup
cd ../lab-environment
docker-compose down
```

## Test Categories

### Unit Tests (`tests/unit/`)

**Purpose**: Test individual components in isolation

**Characteristics**:
- Fast (< 100ms per test)
- No external dependencies
- Mock all I/O operations
- 100+ tests
- Target: 90%+ coverage on core modules

**Example**:
```python
@pytest.mark.unit
def test_llm_config_validation():
    """Test that LLM config validates API key"""
    with pytest.raises(ValueError):
        LLMConfig(api_key="")
```

**Run**: `pytest tests/unit/ -v`

### Integration Tests (`tests/integration/`)

**Purpose**: Test component interactions and external dependencies

**Characteristics**:
- Moderate speed (1-10 seconds per test)
- May use external services (lab, APIs)
- Tests real integrations
- 30-40 tests
- Target: 85%+ coverage

**Example**:
```python
@pytest.mark.integration
@pytest.mark.requires_docker
async def test_nmap_scan_against_lab():
    """Test nmap scanning against lab environment"""
    scanner = NmapScanner()
    result = await scanner.scan("localhost", "8080,3001")
    assert len(result["ports"]) > 0
```

**Run**: `pytest tests/integration/ -v`

### End-to-End Tests (`tests/e2e/`)

**Purpose**: Test complete workflows from start to finish

**Characteristics**:
- Slow (30-300 seconds per test)
- Full workflow validation
- Uses lab environment
- 10-15 tests
- Tests real-world scenarios

**Example**:
```python
@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.requires_docker
async def test_complete_autonomous_workflow():
    """Test full autonomous pentest workflow"""
    client = MedusaClient("http://localhost:8080")

    # Phase 1: Reconnaissance
    recon = await client.reconnaissance()
    assert len(recon["findings"]) > 0

    # Phase 2: Enumeration
    enum = await client.enumerate(recon["findings"])
    assert len(enum["services"]) > 0

    # Phase 3: Vulnerability Assessment
    vulns = await client.assess_vulnerabilities(enum)
    assert len(vulns) > 0
```

**Run**: `pytest tests/e2e/ -v -m e2e`

### Performance Tests (`tests/performance/`)

**Purpose**: Ensure MEDUSA meets performance requirements

**Requirements**:
- Mock LLM response: < 1 second
- Reconnaissance: < 5 seconds (mock mode)
- Memory usage: < 100 MB per scan
- No memory leaks
- Throughput: > 10 req/s (mock mode)

**Example**:
```python
@pytest.mark.performance
async def test_reconnaissance_speed():
    """Benchmark reconnaissance performance"""
    start = time.time()
    await client.reconnaissance()
    duration = time.time() - start

    assert duration < 5.0, f"Too slow: {duration}s"
```

**Run**: `pytest tests/performance/ -v -m performance`

### Security Tests (`tests/security/`)

**Purpose**: Ensure MEDUSA itself is secure

**Tests for**:
- Command injection prevention
- Path traversal prevention
- SQL injection prevention (in logging)
- Input validation
- No hardcoded secrets
- Secure random usage

**Example**:
```python
@pytest.mark.security
async def test_prevent_command_injection():
    """Test command injection is prevented"""
    malicious = "http://test.com; rm -rf /"

    with pytest.raises(ValueError):
        await client.scan(malicious)
```

**Run**: `pytest tests/security/ -v -m security`

## Lab Environment

### Starting the Lab

```bash
cd lab-environment/

# Quick start
./start.sh

# With rebuild
./start.sh --rebuild

# Quiet mode
./start.sh --quiet
```

### Verifying the Lab

```bash
# Full verification
./verify.sh

# Verbose output
./verify.sh --verbose

# JSON output (for automation)
./verify.sh --json
```

### Lab Services

The lab provides 8 vulnerable services:

1. **EHR Web App** (8080) - SQL injection, XSS, directory traversal
2. **EHR API** (3001) - Broken authentication, JWT issues
3. **MySQL** (3306) - Weak credentials, exposed port
4. **SSH** (2222) - Weak credentials, sudo misconfiguration
5. **FTP** (21) - Anonymous access, sensitive files
6. **LDAP** (389) - Anonymous bind, weak credentials
7. **Log Collector** (8081) - No authentication
8. **Workstation** (445, 5900) - SMB shares, weak VNC

See `../lab-environment/VULNERABILITIES.md` for complete documentation.

### Lab-Dependent Tests

Tests marked with `@pytest.mark.requires_docker` need the lab:

```bash
# Start lab
cd ../lab-environment && ./start.sh

# Run lab-dependent tests
cd ../medusa-cli
pytest -m requires_docker

# Cleanup
cd ../lab-environment && docker-compose down
```

## Coverage Requirements

### Overall Target

- **Minimum**: 70% (enforced by CI/CD)
- **Target**: 80%
- **Ideal**: 85%+

### By Module Priority

#### Critical Modules (90%+ target)
- `src/medusa/client.py` - Main client interface
- `src/medusa/core/llm.py` - LLM integration
- `src/medusa/approval.py` - Approval system
- `src/medusa/config.py` - Configuration

#### Important Modules (85%+ target)
- `src/medusa/tools/*.py` - Tool integrations
- `src/medusa/modes/*.py` - Operating modes

#### Support Modules (80%+ target)
- `src/medusa/utils/*.py` - Utilities
- `src/medusa/reporter.py` - Reporting

### Checking Coverage

```bash
# Generate HTML coverage report
pytest --cov=medusa --cov-report=html

# Open report
open htmlcov/index.html

# Terminal report
pytest --cov=medusa --cov-report=term-missing

# Check if meets threshold (70%)
coverage report --fail-under=70
```

### Coverage Configuration

Coverage settings are in:
- `.coveragerc` - Coverage.py configuration
- `pytest.ini` - Pytest configuration

## CI/CD Integration

### GitHub Actions Workflows

#### 1. `test.yml` - Core Tests
Runs on every push/PR:
- Unit tests (Python 3.9-3.12)
- Integration tests
- Linting (flake8, black, mypy)
- Security scanning (bandit, safety)
- Coverage reporting (Codecov)

#### 2. `lab-tests.yml` - Lab Environment Tests
Runs on push to main/develop:
- Lab validation
- Integration tests against lab
- E2E tests (autonomous mode)
- Performance benchmarks
- Security tests

#### 3. Scheduled Tests
Daily at 2 AM UTC:
- Full lab validation
- E2E tests with real LLM (if API key available)
- Long-running stress tests

### Local CI Simulation

```bash
# Run the same tests as CI
pytest tests/ \
  --cov=medusa \
  --cov-report=xml \
  --cov-report=term-missing \
  --junitxml=test-results.xml

# Check coverage threshold
coverage report --fail-under=70

# Run linting
flake8 src/medusa
black --check src/medusa tests/
mypy src/medusa
```

## Writing New Tests

### Test Template

```python
#!/usr/bin/env python3
"""
Test module description
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.mark.unit  # or integration, e2e, etc.
def test_something():
    """
    Test description

    Verifies that...
    """
    # Arrange
    ...

    # Act
    ...

    # Assert
    ...


@pytest.mark.asyncio
async def test_async_something():
    """Test async functionality"""
    result = await async_function()
    assert result is not None
```

### Best Practices

1. **One Assertion Focus Per Test**
   ```python
   # Good
   def test_config_validates_api_key():
       """Test that empty API key is rejected"""
       with pytest.raises(ValueError):
           Config(api_key="")

   # Avoid
   def test_config():
       """Test config"""  # Too vague
       config = Config()
       assert config.api_key
       assert config.timeout
       assert config.retries  # Too many unrelated assertions
   ```

2. **Use Descriptive Names**
   ```python
   # Good
   def test_reconnaissance_returns_open_ports()

   # Avoid
   def test_recon()
   def test1()
   ```

3. **Use Fixtures for Setup**
   ```python
   @pytest.fixture
   def mock_llm_client():
       """Provide a mock LLM client"""
       return MockLLMClient(config=LLMConfig(api_key="test"))

   def test_something(mock_llm_client):
       result = mock_llm_client.get_recommendation()
       assert result is not None
   ```

4. **Mark Tests Appropriately**
   ```python
   @pytest.mark.unit
   def test_fast_unit_test():
       pass

   @pytest.mark.integration
   @pytest.mark.requires_docker
   def test_needs_lab():
       pass

   @pytest.mark.slow
   def test_long_running():
       pass
   ```

5. **Use Parametrize for Multiple Inputs**
   ```python
   @pytest.mark.parametrize("port,expected", [
       (80, True),
       (443, True),
       (999999, False),
       (-1, False),
   ])
   def test_port_validation(port, expected):
       result = is_valid_port(port)
       assert result == expected
   ```

### Async Tests

```python
@pytest.mark.asyncio
async def test_async_operation():
    """Test async functionality"""
    result = await async_function()
    assert result is not None
```

### Mocking

```python
from unittest.mock import Mock, AsyncMock, patch

def test_with_mock():
    """Test with mocked dependency"""
    mock_api = Mock()
    mock_api.call.return_value = {"status": "success"}

    result = function_using_api(mock_api)
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_async_with_mock():
    """Test async with mocked dependency"""
    mock_client = AsyncMock()
    mock_client.get_data.return_value = {"data": "test"}

    result = await async_function(mock_client)
    assert result["data"] == "test"
```

## Troubleshooting

### Common Issues

#### Tests Can't Import Modules

```bash
# Ensure PYTHONPATH is set
export PYTHONPATH=$PWD/src:$PYTHONPATH

# Or run pytest from project root
pytest
```

#### Lab Environment Tests Failing

```bash
# Check if lab is running
docker ps | grep medusa

# Start lab
cd ../lab-environment && ./start.sh

# Verify lab
./verify.sh --verbose

# Check logs
docker-compose logs
```

#### Coverage Report Missing Files

```bash
# Ensure coverage is configured correctly
cat .coveragerc

# Run with explicit source
pytest --cov=src/medusa --cov-report=html
```

#### Tests Hanging

```bash
# Use timeout
pytest --timeout=60

# Run specific test with verbose output
pytest tests/path/to/test.py::test_name -v -s
```

#### Import Errors in Tests

```python
# Add this to test files
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
```

### Debug Mode

```bash
# Run with print statements visible
pytest -s

# Run with pdb on failure
pytest --pdb

# Extra verbose output
pytest -vv

# Show local variables in tracebacks
pytest -l
```

### Performance Issues

```bash
# Show slowest tests
pytest --durations=10

# Run only fast tests
pytest -m "not slow"

# Profile tests
pytest --profile
```

## Useful Commands

```bash
# Run all tests with coverage
pytest --cov=medusa --cov-report=html

# Run specific test file
pytest tests/unit/test_llm.py

# Run specific test function
pytest tests/unit/test_llm.py::test_mock_llm_client

# Run tests matching pattern
pytest -k "test_reconnaissance"

# List all tests without running
pytest --collect-only

# Run tests in parallel (requires pytest-xdist)
pytest -n auto

# Generate JUnit XML (for CI)
pytest --junitxml=test-results.xml

# Watch mode (requires pytest-watch)
ptw

# Update snapshots (if using pytest-snapshot)
pytest --snapshot-update
```

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [MEDUSA Lab Vulnerabilities](../lab-environment/VULNERABILITIES.md)
- [GitHub Actions Workflows](../.github/workflows/)

## Contributing

When adding new features to MEDUSA:

1. ✅ Write tests first (TDD approach)
2. ✅ Ensure tests pass locally
3. ✅ Maintain >70% coverage
4. ✅ Add appropriate markers
5. ✅ Update this documentation if needed
6. ✅ Verify CI passes

## Questions?

- Check existing tests for examples
- Review `conftest.py` for available fixtures
- See CI workflows for comprehensive examples
- Open an issue for clarification

---

**Last Updated**: 2025-11-05
**Maintained By**: MEDUSA QA Team
**Version**: 1.0
