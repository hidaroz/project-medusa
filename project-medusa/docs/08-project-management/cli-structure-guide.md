# MEDUSA CLI - Structure & Organization Guide

**Last Updated**: October 31, 2025  
**Status**: ✅ Properly Structured

---

## 📁 Directory Structure

```
medusa-cli/
├── src/medusa/              # 📦 Main Python package
│   ├── core/               # 🧠 Core functionality
│   │   ├── __init__.py
│   │   └── llm.py          # LLM integration (Gemini API)
│   ├── modes/              # 🎮 Operating modes
│   │   ├── __init__.py
│   │   ├── autonomous.py   # Full automation with approval gates
│   │   ├── interactive.py  # Natural language shell
│   │   └── observe.py      # Read-only reconnaissance
│   ├── __init__.py         # Package exports
│   ├── cli.py              # 🚪 CLI entry point (Typer framework)
│   ├── client.py           # 📡 Backend/API client
│   ├── config.py           # ⚙️ Configuration management
│   ├── display.py          # 🎨 Terminal UI (Rich library)
│   ├── approval.py         # 🛡️ Safety gates & risk management
│   └── reporter.py         # 📊 Report generation (HTML/JSON)
│
├── tests/                   # ✅ Test suite (NEW)
│   ├── __init__.py
│   ├── conftest.py         # Pytest configuration & fixtures
│   ├── README.md           # Test suite documentation
│   ├── unit/               # Fast, isolated unit tests
│   │   ├── __init__.py
│   │   ├── test_config.py  # Configuration tests
│   │   └── test_approval.py # Approval gate tests
│   ├── integration/        # Component interaction tests
│   │   ├── __init__.py
│   │   └── test_llm_integration.py # LLM integration tests
│   └── fixtures/           # Shared test data
│       ├── __init__.py
│       ├── sample_config.yaml # Test configuration
│       └── mock_responses.json # Mock API responses
│
├── docs/                    # 📚 Documentation
│   ├── README.md           # Component overview
│   ├── ARCHITECTURE.md     # Technical architecture
│   ├── QUICKSTART.md       # Getting started
│   ├── QUICK_START_LLM.md  # LLM setup guide
│   ├── USAGE_EXAMPLES.md   # How-to examples
│   ├── INTEGRATION_GUIDE.md # Integration instructions
│   ├── PROJECT_OVERVIEW.md # Detailed overview
│   └── PROJECT_SUMMARY.md  # Executive summary
│
├── requirements.txt         # Python dependencies
├── pyproject.toml          # Package metadata
├── setup.py                # Installation script
└── test_install.sh         # Installation verification

```

---

## 🎯 Module Purposes

### Core Package (`src/medusa/`)

| Module | Purpose | Key Classes/Functions |
|--------|---------|----------------------|
| `cli.py` | CLI interface & commands | `app` (Typer app), `run`, `setup`, `version` |
| `client.py` | API communication | `MedusaClient`, async HTTP methods |
| `config.py` | Configuration management | `Config`, `get_config()`, setup wizard |
| `display.py` | Terminal UI rendering | `display` object, Rich formatting |
| `approval.py` | Safety & risk management | `ApprovalGate`, `Action`, `RiskLevel` |
| `reporter.py` | Report generation | `ReportGenerator`, HTML/JSON output |

### Core Subpackage (`src/medusa/core/`)

| Module | Purpose | Key Classes/Functions |
|--------|---------|----------------------|
| `llm.py` | LLM integration | `LLMClient`, `MockLLMClient`, `LLMConfig` |

**Future additions**:
- `database.py` - Database abstraction
- `utils.py` - Shared utilities
- `exceptions.py` - Custom exceptions

### Modes Subpackage (`src/medusa/modes/`)

| Module | Purpose | Key Classes |
|--------|---------|-------------|
| `autonomous.py` | Full automation mode | `AutonomousMode` |
| `interactive.py` | Natural language shell | `InteractiveMode` |
| `observe.py` | Read-only mode | `ObserveMode` |

**Future additions**:
- `training.py` - Training mode for LLM
- `replay.py` - Replay previous operations

---

## 🧪 Test Organization

### Test Philosophy

- **Unit tests**: Test individual functions/classes in isolation
- **Integration tests**: Test component interactions
- **Fixtures**: Shared test data and mocks

### Test File Mapping

| Source Module | Unit Test | Integration Test |
|---------------|-----------|------------------|
| `config.py` | `tests/unit/test_config.py` | - |
| `approval.py` | `tests/unit/test_approval.py` | - |
| `core/llm.py` | `tests/unit/test_llm.py` (future) | `tests/integration/test_llm_integration.py` |
| `client.py` | `tests/unit/test_client.py` (future) | - |
| `modes/*.py` | - | `tests/integration/test_modes.py` (future) |

### Running Tests

```bash
# All tests
pytest

# Specific category
pytest tests/unit/ -v
pytest tests/integration/ -v

# With coverage
pytest --cov=medusa --cov-report=html
```

---

## 📝 Documentation Organization

### User-Facing Documentation

| File | Audience | Purpose |
|------|----------|---------|
| `README.md` | Everyone | First stop, overview, installation |
| `QUICKSTART.md` | New users | Get running quickly |
| `QUICK_START_LLM.md` | Users setting up LLM | LLM configuration guide |
| `USAGE_EXAMPLES.md` | Users | Practical examples |

### Developer Documentation

| File | Audience | Purpose |
|------|----------|---------|
| `ARCHITECTURE.md` | Developers | Technical design, patterns |
| `INTEGRATION_GUIDE.md` | Integrators | How to integrate with MEDUSA |
| `PROJECT_OVERVIEW.md` | Stakeholders | Detailed project information |
| `STRUCTURE_GUIDE.md` | This file | Structure reference |

### Test Documentation

| File | Audience | Purpose |
|------|----------|---------|
| `tests/README.md` | Developers | Test suite guide |
| `tests/conftest.py` | Test writers | Shared fixtures |

---

## 🔧 Configuration Files

| File | Purpose |
|------|---------|
| `requirements.txt` | Python dependencies (pip) |
| `pyproject.toml` | Package metadata, build config |
| `setup.py` | Installation script |
| `pytest.ini` (future) | Pytest configuration |
| `.coveragerc` (future) | Coverage configuration |

---

## 📊 Dependency Graph

```
┌─────────────────┐
│     cli.py      │  ← Entry point
└────────┬────────┘
         │
    ┌────┴────┬─────────┬──────────┬─────────┐
    │         │         │          │         │
┌───▼──┐  ┌──▼──┐  ┌───▼────┐  ┌──▼────┐  ┌▼────────┐
│config│  │modes│  │display │  │approval│  │reporter │
└───┬──┘  └──┬──┘  └────────┘  └────────┘  └─────────┘
    │        │
    │    ┌───▼────┐
    │    │ client │
    │    └───┬────┘
    │        │
    └────┬───┴───┐
         │       │
    ┌────▼──┐  ┌─▼──────┐
    │core/  │  │display │
    │llm.py │  └────────┘
    └───────┘
```

---

## 🎨 Code Style

### Naming Conventions

```python
# Files
my_module.py          # snake_case

# Classes
class MyClass:        # PascalCase
    pass

# Functions
def my_function():    # snake_case
    pass

# Variables
my_variable = 42      # snake_case

# Constants
MAX_RETRIES = 3       # UPPER_SNAKE_CASE

# Private
def _internal():      # leading underscore
    pass
```

### Import Order

```python
# 1. Standard library
import os
from typing import Dict

# 2. Third-party
import typer
from rich import Console

# 3. Local
from medusa.config import get_config
from medusa.core.llm import LLMClient
```

### Docstring Style

```python
def function_name(arg1: str, arg2: int) -> Dict[str, Any]:
    """
    Brief one-line description.
    
    Longer description if needed, explaining what the
    function does in more detail.
    
    Args:
        arg1: Description of arg1
        arg2: Description of arg2
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When something is wrong
        
    Example:
        >>> result = function_name("test", 42)
        >>> print(result)
        {'key': 'value'}
    """
```

---

## 🚀 Adding New Features

### Adding a New Module

1. **Create module in appropriate location**:
   - Core functionality → `src/medusa/core/`
   - Operating mode → `src/medusa/modes/`
   - Main feature → `src/medusa/`

2. **Update `__init__.py`**:
   ```python
   # src/medusa/__init__.py
   from medusa.new_module import NewClass
   
   __all__ = ["NewClass", ...]
   ```

3. **Write tests**:
   - Unit tests → `tests/unit/test_new_module.py`
   - Integration tests → `tests/integration/test_new_feature.py`

4. **Document**:
   - Add docstrings
   - Update README if user-facing
   - Update ARCHITECTURE.md if design-impacting

### Adding a New Operating Mode

1. **Create mode file**: `src/medusa/modes/new_mode.py`

2. **Implement mode class**:
   ```python
   class NewMode:
       """New operating mode description"""
       
       def __init__(self, config: Config):
           self.config = config
       
       async def run(self):
           """Main execution method"""
           pass
   ```

3. **Register in `modes/__init__.py`**:
   ```python
   from medusa.modes.new_mode import NewMode
   
   __all__ = ["AutonomousMode", "InteractiveMode", "ObserveMode", "NewMode"]
   ```

4. **Add CLI command** in `cli.py`:
   ```python
   @app.command()
   def new_mode():
       """Run in new mode"""
       mode = NewMode(get_config())
       asyncio.run(mode.run())
   ```

### Adding Test Coverage

1. **Create test file**: `tests/unit/test_new_module.py`

2. **Write tests**:
   ```python
   import pytest
   from medusa.new_module import new_function
   
   class TestNewFunction:
       def test_valid_input(self):
           result = new_function("valid")
           assert result == "expected"
   ```

3. **Run tests**:
   ```bash
   pytest tests/unit/test_new_module.py -v
   ```

4. **Check coverage**:
   ```bash
   pytest --cov=medusa.new_module --cov-report=term-missing
   ```

---

## 📦 Package Distribution

### Local Development Installation

```bash
# Editable install (for development)
cd medusa-cli
pip install -e .

# Verify installation
medusa --version
```

### Building for Distribution

```bash
# Build wheel and source distribution
python -m build

# Install from built package
pip install dist/medusa_pentest-*.whl
```

### Publishing to PyPI (Future)

```bash
# Test on TestPyPI first
python -m twine upload --repository testpypi dist/*

# Then publish to PyPI
python -m twine upload dist/*
```

---

## 🔍 Troubleshooting

### Import Errors

**Problem**: `ModuleNotFoundError: No module named 'medusa'`

**Solution**:
```bash
# Install in editable mode
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

### Test Discovery Issues

**Problem**: pytest can't find tests

**Solution**:
```bash
# Run from medusa-cli directory
cd medusa-cli
pytest

# Or specify path
pytest tests/ -v
```

### Configuration Issues

**Problem**: Config file not found

**Solution**:
```bash
# Run setup wizard
medusa setup

# Or manually create config
mkdir -p ~/.medusa
cp tests/fixtures/sample_config.yaml ~/.medusa/config.yaml
```

---

## ✅ Quality Checklist

Before committing code:

- [ ] Code follows PEP 8 style guide
- [ ] Functions have type hints
- [ ] Public functions have docstrings
- [ ] Tests written and passing
- [ ] Documentation updated
- [ ] No sensitive data (API keys, etc.)
- [ ] Imports organized correctly
- [ ] Error handling implemented

---

## 📚 Related Documentation

- [Main Project README](../README.md)
- [Project Conventions](../PROJECT_CONVENTIONS.md)
- [Cursor AI Rules](../.cursorrules)
- [Restructure Summary](../RESTRUCTURE_SUMMARY.md)
- [Architecture Guide](./ARCHITECTURE.md)
- [Test Suite Guide](./tests/README.md)

---

**Maintained by**: MEDUSA Development Team  
**Questions?**: Open an issue or see README

