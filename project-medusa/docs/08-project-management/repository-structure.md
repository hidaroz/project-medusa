# MEDUSA Project Structure Guide

**Complete Reference for Repository Organization**

Last Updated: November 4, 2025

---

## 📁 High-Level Structure

```
project-medusa/                     # Root directory
├── .cursorrules                    # AI agent guidance (Cursor)
├── README.md                       # 🎯 PROJECT ENTRY POINT
├── STRUCTURE.md                    # This file - structure reference
├── env.example                     # Environment variables template
│
├── medusa-cli/                     # ⭐ MAIN: Python AI pentesting agent
├── medusa-backend/                 # Python FastAPI backend (tool integration)
├── medusa-webapp/                  # Next.js EHR web interface
├── lab-environment/                # Docker vulnerable infrastructure
├── training-data/                  # AI training datasets
│
├── docs/                           # 📚 Comprehensive documentation
├── scripts/                        # Utility scripts
└── archive/                        # Deprecated components
```

---

## 🎯 Component Details

### **Primary Component: `medusa-cli/`**
**Purpose**: Main AI-powered penetration testing agent

```
medusa-cli/
├── src/medusa/                   # Main Python package
│   ├── core/                    # Core functionality
│   │   ├── llm.py              # LLM integration (Gemini)
│   │   ├── tools.py            # Tool integration layer
│   │   └── workflow.py         # Workflow management
│   ├── modes/                   # Operating modes
│   │   ├── autonomous.py       # Full automation with approvals
│   │   ├── interactive.py      # Natural language shell
│   │   └── observe.py          # Read-only reconnaissance
│   ├── tools/                   # Security tools
│   │   ├── nmap/               # Nmap integration
│   │   ├── metasploit/         # Metasploit integration
│   │   └── parsers/            # Output parsers
│   ├── utils/                   # Utilities
│   │   ├── command_parser.py   # Command parsing
│   │   ├── formatters.py       # Output formatting
│   │   └── validators.py       # Input validation
│   ├── cli.py                   # CLI entry point
│   ├── config.py                # Configuration management
│   ├── client.py                # Backend API client
│   ├── display.py               # Terminal UI (Rich)
│   ├── approval.py              # Safety gates
│   └── reporter.py              # Report generation
│
├── tests/                        # ✅ Comprehensive test suite
│   ├── conftest.py              # Pytest configuration
│   ├── unit/                    # Unit tests (7 files)
│   │   ├── test_config.py
│   │   ├── test_approval.py
│   │   ├── test_llm.py
│   │   ├── test_command_parser.py
│   │   ├── test_nmap_parser.py
│   │   ├── test_reporter.py
│   │   └── __init__.py
│   ├── integration/             # Integration tests (3 files)
│   │   ├── test_llm_integration.py
│   │   ├── test_observe_mode.py
│   │   ├── test_tools_integration.py
│   │   └── __init__.py
│   └── fixtures/                # Test data
│       ├── mock_responses.json
│       ├── sample_config.yaml
│       └── __init__.py
│
├── docs/                         # Component-specific documentation
│   ├── CHECKPOINT_RESUME.md
│   ├── INTERACTIVE_MODE_GUIDE.md
│   ├── LLM_IMPLEMENTATION_SUMMARY.md
│   ├── LLM_INTEGRATION_GUIDE.md
│   └── MODE_WORKFLOW_IMPLEMENTATION.md
│
├── README.md                     # Component overview
├── ARCHITECTURE.md               # Technical architecture
├── QUICKSTART.md                 # Getting started
├── requirements.txt              # Python dependencies
├── requirements-dev.txt          # Dev dependencies
├── pyproject.toml                # Package metadata
├── setup.py                      # Installation
└── pytest.ini                    # Pytest configuration

**Status**: 85% Complete  
**Tests**: 10 test files (7 unit, 3 integration)  
**Dependencies**: 24 packages
```

---

### **Backend: `medusa-backend/`**
**Purpose**: FastAPI backend for tool integration and coordination

```
medusa-backend/
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI application
│   ├── api/                     # API endpoints
│   │   ├── __init__.py
│   │   ├── tools.py            # Tool execution endpoints
│   │   ├── scans.py            # Scan management
│   │   └── reports.py          # Report endpoints
│   ├── core/                    # Core functionality
│   │   ├── __init__.py
│   │   ├── config.py           # Backend configuration
│   │   └── security.py         # Security utilities
│   ├── models/                  # Data models
│   │   ├── __init__.py
│   │   └── scan.py             # Scan models
│   └── services/                # Business logic
│       ├── __init__.py
│       └── tool_executor.py    # Tool execution service
│
├── Dockerfile                   # Docker configuration
├── README.md                    # Backend documentation
└── requirements.txt             # Python dependencies

**Status**: 60% Complete  
**Framework**: FastAPI  
**Purpose**: Tool execution, result aggregation
```

---

### **Lab Environment: `lab-environment/`**
**Purpose**: Docker-based vulnerable infrastructure for testing

```
lab-environment/
├── docker-compose.yml           # Main orchestration
├── docker-compose.override.yml  # Dev overrides
├── Makefile                     # Convenience commands
│
├── services/                    # 8 vulnerable services
│   ├── ehr-webapp/             # PHP vulnerable web app
│   ├── ehr-api/                # Node.js vulnerable API
│   ├── ehr-webapp-static/      # Static Next.js build
│   ├── ssh-server/             # SSH with weak credentials
│   ├── ftp-server/             # Anonymous FTP
│   ├── log-collector/          # Centralized logging
│   └── workstation/            # Windows simulation
│
├── init-scripts/                # Initialization scripts
│   └── db/                     # Database seed data
├── mock-data/                   # Test data
│   ├── documents/
│   └── medical-records/
├── scripts/                     # Utility scripts
│   └── verify.sh               # Service verification
├── docs/                        # Lab documentation
│   └── security/               # Vulnerability docs
│
├── README.md                    # Lab guide
├── setup.sh                     # Setup script
├── start-medusa.sh             # Start script
└── verify.sh                    # Verification script

**Status**: 95% Complete  
**Services**: 8 Docker containers  
**Networks**: DMZ (172.20.0.0/24), Internal (172.21.0.0/24)
```

---

### **Documentation: `docs/`**
**Purpose**: Comprehensive project documentation

```
docs/
├── README.md                    # 🎯 DOCUMENTATION INDEX (start here)
│
├── architecture/                # System design
│   ├── MITRE_ATTACK_MAPPING.md
│   └── NETWORK_ARCHITECTURE.md
│
├── deployment/                  # Deployment guides
│   ├── DEPLOYMENT_GUIDE.md
│   ├── DOCKER_DEPLOYMENT_GUIDE.md
│   └── DEPLOYMENT_CHECKLIST.md
│
├── development/                 # Development docs
│   ├── TOOL_INTEGRATION_SUMMARY.md
│   ├── AUTOMATION_GUIDE.md
│   ├── BACKEND_IMPLEMENTATION_PLAN.md
│   ├── BACKEND_CREATION_LOG.md
│   └── AGENTS.md
│
├── getting-started/             # New user guides
│   ├── QUICK_START.md
│   └── QUICK_START_DOCKER.md
│
├── project-management/          # PMO documentation
│   ├── MEDUSA_PRD.md           # Product requirements
│   ├── PROJECT_TIMELINE.md
│   ├── CLASS_FEEDBACK_SUMMARY.md
│   ├── INDUSTRY_STAKEHOLDERS_FEEDBACK.md
│   ├── MEDUSA_LAB_AUDIT_REPORT.md
│   └── audits/                 # Audit reports
│       ├── MEDUSA_AI_AGENT_AUDIT.md
│       └── MEDUSA_COMPLETION_CHECKLIST.md
│
├── project-summaries/           # Completion summaries
│   ├── LLM_INTEGRATION_COMPLETE.md
│   ├── WORKFLOW_COMPLETION_SUMMARY.md
│   └── REPOSITORY_STRUCTURE_AUDIT.md
│
├── research/                    # Research papers
│   ├── PROJECT_MEDUSA_OVERVIEW.md
│   └── OLLAMA_FINE_TUNING.md
│
├── migration/                   # (Reserved for future)
│
├── ARCHITECTURE.md              # Architecture overview
├── DEPLOYMENT.md                # Deployment overview
├── DEVELOPMENT.md               # Development overview
└── SECURITY.md                  # Security guidelines

**Total**: 30+ documentation files  
**Organization**: By category for easy navigation
```

---

### **Supporting Components**

#### **`medusa-webapp/` - Next.js EHR Frontend**
```
medusa-webapp/
├── src/                         # Source code
│   ├── app/                    # Next.js App Router
│   ├── components/             # React components
│   └── lib/                    # Utilities
├── public/                      # Static assets
├── out/                         # Static build (for lab)
├── Dockerfile                   # Container config
├── next.config.ts              # Next.js config
└── README.md                    # Component docs

**Status**: 90% Complete  
**Framework**: Next.js 14, TypeScript  
**Purpose**: Vulnerable EHR system for testing
```

#### **`training-data/` - AI Training Datasets**
```
training-data/
├── raw/                         # Raw JSON datasets (gitignored)
│   ├── full_agent_dataset.json # Complete dataset
│   ├── recon_dataset.json      # Reconnaissance
│   ├── discovery_dataset.json  # Discovery
│   ├── lateral_movement_dataset.json
│   ├── privilege_esc_dataset.json
│   ├── persistence_dataset.json
│   ├── defense_evasion_dataset.json
│   ├── credential_access_dataset.json
│   ├── exe_dataset.json        # Execution
│   ├── inital_access_dataset.json  # ⚠️ Typo in filename
│   └── dataset_template.json   # Template
│
├── README.md                    # Dataset overview
└── CONFIG.md                    # Usage instructions

**Total Size**: 1.9 MB (11 datasets)  
**Organization**: MITRE ATT&CK phases  
**Status**: 80% Complete
```

#### **`scripts/` - Utility Scripts**
```
scripts/
├── build-docker.sh              # Build Docker images
├── clean.sh                     # Cleanup script
├── run-tests.sh                 # Run test suite
└── setup-dev.sh                 # Dev environment setup
```

#### **`archive/` - Deprecated Code**
```
archive/
├── README.md                    # Explanation of archival
└── medusa-backend/             # Old Node.js backend
    ├── server.js
    ├── package.json
    └── src/routes/

**Note**: Original backend (60% complete) archived in favor of Python FastAPI backend
```

---

## 🗺️ Navigation Guide

### **For New Users:**
1. Start: [`README.md`](README.md) (project root)
2. Then: [`docs/getting-started/QUICK_START.md`](docs/getting-started/QUICK_START.md)
3. Understand: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

### **For Developers:**
1. Overview: [`medusa-cli/README.md`](medusa-cli/README.md)
2. Architecture: [`medusa-cli/ARCHITECTURE.md`](medusa-cli/ARCHITECTURE.md)
3. Testing: [`medusa-cli/tests/README.md`](medusa-cli/tests/README.md)
4. Development: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)

### **For Deployment:**
1. Overview: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
2. Docker: [`docs/deployment/DOCKER_DEPLOYMENT_GUIDE.md`](docs/deployment/DOCKER_DEPLOYMENT_GUIDE.md)
3. Checklist: [`docs/deployment/DEPLOYMENT_CHECKLIST.md`](docs/deployment/DEPLOYMENT_CHECKLIST.md)

### **For Documentation:**
1. Index: [`docs/README.md`](docs/README.md) (📍 START HERE)
2. Browse by category in `docs/` subdirectories
3. Component-specific docs in component roots

---

## 📊 Project Metrics

### Completion Status
| Component | Completion | Test Coverage | Documentation |
|-----------|------------|---------------|---------------|
| medusa-cli | 85% | ✅ High (10 files) | ✅ Excellent |
| medusa-backend | 60% | 🟡 Low | 🟡 Basic |
| medusa-webapp | 90% | ❌ None | ✅ Good |
| lab-environment | 95% | 🟡 Manual | ✅ Excellent |
| training-data | 80% | N/A | ✅ Good |
| **Overall** | **70%** | 🟡 **Medium** | ✅ **Excellent** |

### Documentation Metrics
- Total markdown files: **40+**
- Documentation directories: **8**
- Component READMEs: **6**
- Test documentation: **1 comprehensive guide**
- Organization: ✅ **Well-structured**

### Test Coverage
- **Unit tests**: 7 files
- **Integration tests**: 3 files
- **Fixtures**: Comprehensive conftest.py
- **Total test files**: 10+
- **Test lines**: 1000+ (estimated)

---

## 🎯 File Organization Principles

### By Type
| Type | Location | Example |
|------|----------|---------|
| Source code | `<component>/src/` | `medusa-cli/src/medusa/` |
| Tests | `<component>/tests/` | `medusa-cli/tests/unit/` |
| Documentation | `<component>/` or `docs/` | `medusa-cli/README.md` |
| Configuration | `<component>/` root | `pyproject.toml` |
| Scripts | `scripts/` | `build-docker.sh` |

### By Scope
| Scope | Location |
|-------|----------|
| Project-wide docs | `docs/` |
| Component docs | Component root |
| API/Technical docs | `<component>/docs/` |
| Summaries | `docs/project-summaries/` |

---

## 🔄 Recent Changes

### November 2025
- ✅ Added comprehensive test suite (10 files)
- ✅ Organized documentation into categories
- ✅ Created documentation index (`docs/README.md`)
- ✅ Moved summaries to `docs/project-summaries/`
- ✅ Added `.cursorrules` for AI agent guidance
- ✅ Created this structure guide

### October 2025
- ✅ Restructured from 17 → 7 root directories
- ✅ Renamed `docker-lab/` → `lab-environment/`
- ✅ Organized training data into `training-data/raw/`
- ✅ Archived old Node.js backend
- ✅ Created test infrastructure

---

## 🚀 Quick Actions

### Run Tests
```bash
cd medusa-cli
pytest                    # All tests
pytest tests/unit/ -v     # Unit tests only
pytest --cov=medusa       # With coverage
```

### Start Lab Environment
```bash
cd lab-environment
./start-medusa.sh         # Start all services
./verify.sh               # Verify services
```

### View Documentation
```bash
# Open documentation index
open docs/README.md

# Quick start guide
open docs/getting-started/QUICK_START.md
```

---

## 📚 Related Documents

- [Main README](README.md) - Project overview
- [Documentation Index](docs/README.md) - All documentation
- [Cursor AI Rules](.cursorrules) - AI agent guidance
- [CLI Documentation](medusa-cli/README.md) - Main component
- [Test Guide](medusa-cli/tests/README.md) - Testing

---

## ✅ Quality Checklist

Structure quality indicators:
- ✅ Clear hierarchy (max 3 levels deep)
- ✅ Consistent naming conventions
- ✅ Proper separation of concerns
- ✅ Comprehensive documentation
- ✅ Well-organized tests
- ✅ Logical grouping by category
- ✅ Easy navigation
- ✅ No orphaned files
- ✅ Git-tracked appropriately

---

**Document Version**: 1.0  
**Last Updated**: November 4, 2025  
**Maintained by**: MEDUSA Team  
**Status**: Living document - updated as structure evolves

---

*Navigate the repository with confidence. Everything has its place.* 🎯

