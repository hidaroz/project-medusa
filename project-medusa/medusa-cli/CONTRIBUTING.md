# Contributing to MEDUSA

Thank you for your interest in contributing to MEDUSA! This document provides guidelines and instructions for contributing to the project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. Please be respectful and constructive in all interactions.

### Expected Behavior

- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, trolling, or insulting comments
- Publishing others' private information
- Any conduct which could reasonably be considered inappropriate

---

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Python 3.11+** installed
- **Git** for version control
- **Docker** for testing lab environments (optional)
- Basic knowledge of:
  - Python programming
  - Penetration testing concepts
  - LLM/AI concepts (for core contributions)

### Initial Setup

1. **Fork the repository**
   ```bash
   # Click "Fork" on GitHub
   # Then clone your fork
   git clone https://github.com/YOUR_USERNAME/medusa.git
   cd medusa/medusa-cli
   ```

2. **Set up upstream remote**
   ```bash
   git remote add upstream https://github.com/original/medusa.git
   git fetch upstream
   ```

3. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   # Or if that fails:
   pip install -e .
   pip install -r requirements-dev.txt
   ```

5. **Verify installation**
   ```bash
   medusa --version
   pytest tests/
   ```

---

## Development Environment

### Recommended Tools

- **IDE:** VSCode, PyCharm, or Vim
- **Code Formatter:** Black
- **Linter:** Ruff or Flake8
- **Type Checker:** MyPy
- **Testing:** Pytest

### VSCode Setup

Create `.vscode/settings.json`:

```json
{
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": false,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false
}
```

### Pre-commit Hooks

Install pre-commit hooks to ensure code quality:

```bash
pip install pre-commit
pre-commit install
```

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
  - repo: https://github.com/charliermarsh/ruff-pre-commit
    rev: v0.0.270
    hooks:
      - id: ruff
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
```

---

## Project Structure

```
medusa-cli/
├── src/medusa/           # Main package
│   ├── __init__.py
│   ├── cli.py           # CLI entry point (Typer)
│   ├── config.py        # Configuration management
│   ├── client.py        # Backend API client
│   ├── display.py       # Terminal UI (Rich)
│   ├── reporter.py      # Report generation
│   ├── approval.py      # Risk approval gates
│   ├── core/            # Core functionality
│   │   └── llm.py       # LLM integration
│   ├── modes/           # Operating modes
│   │   ├── autonomous.py
│   │   ├── interactive.py
│   │   └── observe.py
│   └── templates/       # Report templates
│       ├── technical_report.html
│       ├── executive_summary.html
│       └── report.md
├── tests/               # Test suite
│   ├── unit/
│   ├── integration/
│   └── conftest.py
├── docs/                # Documentation
├── pyproject.toml       # Project metadata
└── README.md
```

### Key Modules

| Module | Purpose | Key Classes/Functions |
|--------|---------|----------------------|
| `cli.py` | CLI interface | `app`, command handlers |
| `config.py` | Configuration | `Config`, `get_config()` |
| `client.py` | Backend API | `MedusaClient` |
| `display.py` | Terminal UI | `MedusaDisplay` |
| `reporter.py` | Reports | `ReportGenerator` |
| `core/llm.py` | LLM integration | `LLMClient` |
| `modes/autonomous.py` | Autonomous mode | `run_autonomous()` |

---

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

1. **Bug Reports** - Report issues you encounter
2. **Feature Requests** - Suggest new features
3. **Bug Fixes** - Fix reported issues
4. **New Features** - Implement new functionality
5. **Documentation** - Improve docs, guides, examples
6. **Tests** - Add or improve test coverage
7. **Templates** - Create new report templates
8. **Integrations** - Add support for new tools/LLMs

### Finding Issues to Work On

- **Good First Issue:** Look for issues tagged `good-first-issue`
- **Help Wanted:** Check `help-wanted` label
- **Bug Fixes:** Search for `bug` label
- **Features:** Look for `enhancement` label

### Before Starting

1. **Check existing issues/PRs** to avoid duplicate work
2. **Comment on the issue** to let others know you're working on it
3. **Ask questions** if you need clarification
4. **Start small** - begin with documentation or small fixes

---

## Coding Standards

### Python Style Guide

We follow **PEP 8** with some modifications:

- **Line length:** 100 characters (not 79)
- **Formatter:** Black (with default settings)
- **Import order:** stdlib → third-party → local
- **Docstrings:** Google style

### Code Formatting

Use Black for automatic formatting:

```bash
black src/medusa tests/
```

### Linting

Use Ruff for linting:

```bash
ruff check src/medusa tests/
ruff check --fix src/medusa tests/  # Auto-fix
```

### Type Hints

Use type hints for all function signatures:

```python
from typing import Dict, List, Optional, Any

def process_findings(findings: List[Dict[str, Any]]) -> Optional[str]:
    """Process findings and return summary.

    Args:
        findings: List of finding dictionaries

    Returns:
        Summary string, or None if no findings
    """
    if not findings:
        return None
    return f"Found {len(findings)} issues"
```

### Docstring Format

Use Google-style docstrings:

```python
def generate_report(data: Dict[str, Any], output_path: Path) -> Path:
    """Generate HTML report from operation data.

    This function takes operation results and generates a comprehensive
    HTML report with findings, MITRE ATT&CK coverage, and recommendations.

    Args:
        data: Dictionary containing operation results with keys:
            - findings: List of security findings
            - mitre_coverage: List of MITRE techniques
            - summary: Summary statistics
        output_path: Path where report should be saved

    Returns:
        Path to the generated report file

    Raises:
        ValueError: If data is missing required fields
        IOError: If output_path is not writable

    Examples:
        >>> data = {"findings": [], "summary": {}}
        >>> report_path = generate_report(data, Path("report.html"))
        >>> print(report_path)
        /path/to/report.html
    """
    # Implementation here
    pass
```

### Naming Conventions

- **Variables/Functions:** `snake_case`
- **Classes:** `PascalCase`
- **Constants:** `UPPER_SNAKE_CASE`
- **Private methods:** `_leading_underscore`

```python
# Good
class ReportGenerator:
    MAX_FINDINGS = 100

    def __init__(self):
        self.output_dir = Path("reports")

    def _prepare_data(self, raw_data: Dict) -> Dict:
        pass

# Avoid
class reportGenerator:  # Wrong case
    maxFindings = 100   # Wrong case

    def PrepareData(self, RawData):  # Wrong case
        pass
```

---

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=medusa --cov-report=html

# Run specific test file
pytest tests/unit/test_reporter.py

# Run specific test
pytest tests/unit/test_reporter.py::TestReportGenerator::test_json_log

# Run with verbose output
pytest -v

# Run with print statements
pytest -s
```

### Writing Tests

Use pytest conventions:

```python
import pytest
from medusa.reporter import ReportGenerator

class TestReportGenerator:
    """Tests for ReportGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a ReportGenerator instance."""
        return ReportGenerator()

    @pytest.fixture
    def sample_data(self):
        """Sample operation data."""
        return {
            "findings": [
                {"severity": "high", "title": "SQL Injection"}
            ],
            "summary": {"total_findings": 1}
        }

    def test_generate_html_report(self, generator, sample_data, tmp_path):
        """Test HTML report generation."""
        # Arrange
        operation_id = "test-001"

        # Act
        report_path = generator.generate_html_report(
            sample_data, operation_id
        )

        # Assert
        assert report_path.exists()
        assert report_path.suffix == ".html"
        assert operation_id in report_path.name

    def test_generate_report_with_empty_data(self, generator):
        """Test report generation with empty data."""
        with pytest.raises(ValueError):
            generator.generate_html_report({}, "test-002")
```

### Test Coverage Requirements

- **Minimum coverage:** 80% overall
- **Core modules:** 90% coverage
- **New features:** Must include tests
- **Bug fixes:** Add regression tests

### Test Categories

```bash
# Unit tests (fast, no external dependencies)
pytest tests/unit/

# Integration tests (slower, may use external services)
pytest tests/integration/

# End-to-end tests
pytest tests/e2e/
```

---

## Documentation

### Updating Documentation

When making changes, update relevant documentation:

1. **Code Comments** - Explain complex logic
2. **Docstrings** - Document all public APIs
3. **README.md** - Update if changing features
4. **USAGE_EXAMPLES.md** - Add new examples
5. **ARCHITECTURE.md** - Update for structural changes

### Documentation Standards

- Use clear, concise language
- Provide examples for complex features
- Keep documentation up-to-date with code
- Include command outputs in examples

### Building Documentation

```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Build HTML docs
cd docs
make html

# View docs
open _build/html/index.html
```

---

## Pull Request Process

### Before Submitting

1. **Update your fork**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests**
   ```bash
   pytest
   black --check src/
   ruff check src/
   ```

3. **Update documentation**
   - Add docstrings
   - Update README if needed
   - Add usage examples

4. **Commit changes**
   ```bash
   git add .
   git commit -m "Add feature: short description"
   ```

### Commit Message Format

Follow Conventional Commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

**Examples:**

```bash
feat(reporter): add PDF export functionality

- Implemented PDF generation using WeasyPrint
- Added generate_pdf_report() method
- Updated documentation with PDF examples

Closes #123
```

```bash
fix(llm): handle rate limit errors gracefully

Previously, rate limit errors would crash the application.
Now we retry with exponential backoff.

Fixes #456
```

### Creating a Pull Request

1. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create PR on GitHub**
   - Go to your fork on GitHub
   - Click "New Pull Request"
   - Fill out the PR template
   - Link related issues

3. **PR Title Format**
   ```
   [Type] Brief description
   ```
   Examples:
   - `[Feature] Add PDF export to reporter`
   - `[Fix] Handle LLM timeout errors`
   - `[Docs] Update installation guide`

4. **PR Description Template**
   ```markdown
   ## Description
   Brief description of changes

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update

   ## Testing
   - [ ] Tests added/updated
   - [ ] All tests passing
   - [ ] Manual testing completed

   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Documentation updated
   - [ ] No new warnings
   - [ ] Backward compatible

   ## Related Issues
   Closes #123
   Relates to #456
   ```

### Review Process

1. **Automated Checks**
   - CI/CD runs tests
   - Code quality checks
   - Coverage reports

2. **Code Review**
   - Maintainer reviews code
   - May request changes
   - Address feedback promptly

3. **Approval & Merge**
   - Approved by maintainer
   - Squash merge to main
   - Branch deleted

### After PR is Merged

1. **Update your local repository**
   ```bash
   git checkout main
   git pull upstream main
   ```

2. **Delete feature branch**
   ```bash
   git branch -d feature/your-feature-name
   git push origin --delete feature/your-feature-name
   ```

---

## Development Workflow

### Typical Development Cycle

1. **Sync with upstream**
   ```bash
   git checkout main
   git pull upstream main
   ```

2. **Create feature branch**
   ```bash
   git checkout -b feature/add-new-template
   ```

3. **Make changes**
   ```bash
   # Edit files
   # Add tests
   # Update docs
   ```

4. **Test changes**
   ```bash
   pytest
   black src/
   ruff check src/
   ```

5. **Commit**
   ```bash
   git add .
   git commit -m "feat(templates): add CSV export template"
   ```

6. **Push and PR**
   ```bash
   git push origin feature/add-new-template
   # Create PR on GitHub
   ```

---

## Areas Needing Contribution

### High Priority

- [ ] Additional report templates (JSON, XML, CSV)
- [ ] More LLM provider integrations (OpenAI, Anthropic)
- [ ] Enhanced MITRE ATT&CK visualization
- [ ] Integration with popular security tools
- [ ] Improved error handling and recovery

### Medium Priority

- [ ] Web UI for report viewing
- [ ] Report comparison features
- [ ] Custom plugin system
- [ ] More test coverage
- [ ] Performance optimizations

### Documentation

- [ ] Video tutorials
- [ ] More usage examples
- [ ] API reference documentation
- [ ] Architecture deep-dives
- [ ] Best practices guide

---

## Community

### Communication Channels

- **GitHub Issues:** Bug reports, feature requests
- **GitHub Discussions:** Questions, ideas, general discussion
- **Discord:** Real-time chat (link in README)
- **Email:** security@medusa-pentest.io

### Getting Help

- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- Search existing issues
- Ask in GitHub Discussions
- Join Discord community

### Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes
- Hall of Fame on website

---

## Security Vulnerabilities

**DO NOT** report security vulnerabilities publicly!

Instead:
1. Email: security@medusa-pentest.io
2. Include detailed description
3. Steps to reproduce
4. Potential impact

We will respond within 48 hours.

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

## Questions?

If you have questions about contributing:

1. Check this guide
2. Read existing issues/PRs
3. Ask in GitHub Discussions
4. Join our Discord

**Thank you for contributing to MEDUSA!** 🎉

---

**Last Updated:** 2025-11-05
**Version:** 1.0.0
