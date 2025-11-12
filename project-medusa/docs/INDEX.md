# MEDUSA Documentation Index

**Master Navigation for All Project Documentation**

> **For AI Agents**: This is the primary documentation entry point. All documentation is organized into numbered sections below. For machine-readable navigation, see `/.ai/FILE_INDEX.json`.

---

## Quick Start

**New to MEDUSA?** Start here:
1. [Getting Started Guide](../GETTING_STARTED.md) - Quick setup and first steps
2. [Project Overview](PROJECT_MEDUSA_OVERVIEW.md) - High-level introduction
3. [Quick Start Dashboard](QUICK_START_MEDUSA_DASHBOARD.md) - Web UI setup

---

## Documentation Sections

### 00 - Getting Started
*Installation, setup, and initial configuration*

**Path**: `/docs/00-getting-started/`

- Quick Start (CLI) - *To be created*
- Quick Start (Docker) - *To be created*
- Installation Guide - *To be created*
- Troubleshooting - *To be created*
- [Dashboard Setup](MEDUSA_DASHBOARD_SETUP.md) - Web UI installation

**Current Location References**:
- [Quick Start Dashboard](QUICK_START_MEDUSA_DASHBOARD.md)
- [Dashboard Setup](MEDUSA_DASHBOARD_SETUP.md)

---

### 01 - Architecture
*System design, components, and technical architecture*

**Path**: `/docs/01-architecture/`

- [**Multi-Agent Evolution Plan**](01-architecture/multi-agent-evolution-plan.md) - 🚀 **NEW: Comprehensive implementation plan for AWS Bedrock, Vector DB, and Multi-Agent System**
- [Project Overview](01-architecture/project-overview.md) - High-level system overview
- [CLI Architecture](01-architecture/cli-architecture.md) - CLI component design
- System Overview - *To be created*
- Component Design - *To be created*
- Network Architecture - *To be created*
- MITRE ATT&CK Mapping - *To be created*
- Database Schema - *To be created*

**Current Location References**:
- [Project Overview](PROJECT_MEDUSA_OVERVIEW.md)
- Architecture docs: `/docs/architecture/`

---

### 02 - Development
*Developer guides, coding standards, and testing*

**Path**: `/docs/02-development/`

- Development Setup - *To be created*
- Coding Standards - *To be created*
- Testing Guide - *To be created*
- CI/CD Pipeline - *To be created*
- Tool Integration - *To be created*

**Current Location References**:
- [Technical Reference](development/TECHNICAL_REFERENCE.md)
- [Quick Reference](development/QUICK_REFERENCE.md)
- [Automation Guide](development/AUTOMATION_GUIDE.md)
- Development docs: `/docs/development/`

---

### 03 - Deployment
*Deployment guides, Docker, and automation*

**Path**: `/docs/03-deployment/`

- Deployment Overview - *To be created*
- Docker Deployment - *To be created*
- Configuration Reference - *To be created*
- Automation Guide - *To be created*

**Current Location References**:
- [Deployment Guide](DEPLOYMENT_GUIDE.md)
- [Deployment Status](DEPLOYMENT_STATUS.md)
- [Automation Guide](development/AUTOMATION_GUIDE.md)
- Deployment docs: `/docs/deployment/`

---

### 04 - Usage
*User guides, CLI reference, and examples*

**Path**: `/docs/04-usage/`

- CLI Reference - *To be created*
- Operating Modes - *To be created*
- Interactive Shell - *To be created*
- Checkpoint System - *To be created*
- Examples - *To be created*

**Current Location References**:
- [CLI README](/medusa-cli/README.md)
- Examples: `/docs/examples/`

---

### 05 - API Reference
*API documentation and specifications*

**Path**: `/docs/05-api-reference/`

- API Overview - *To be created*
- CLI API - *To be created*
- Backend API - *To be created*
- OpenAPI Specification - *To be created*
- WebHook Reference - *To be created*

**Current Location References**:
- [Backend Implementation Plan](BACKEND_IMPLEMENTATION_PLAN.md)
- Backend docs: `/medusa-backend/README.md`

---

### 06 - Security
*Security policies, approval gates, ethical guidelines*

**Path**: `/docs/06-security/`

- Security Policy - *To be created*
- Vulnerability Disclosure - *To be created*
- Approval Gates - *To be created*
- Ethical Guidelines - *To be created*

**Current Location References**:
- [Product Requirements (Security Section)](MEDUSA_PRD.md)
- Security info in component READMEs

---

### 07 - Research
*Academic research, LLM integration, papers*

**Path**: `/docs/07-research/`

- Research Overview - *To be created*
- LLM Integration - *To be created*
- RAG Integration - *To be created*

**Current Location References**:
- [Ollama Fine-Tuning](OLLAMA_FINE_TUNING.md)
- [Project Overview (Research Context)](PROJECT_MEDUSA_OVERVIEW.md)
- RAG Integration Plan: `RAG_INTEGERATION_PLAN.mc` *(note: file extension error)*

---

### 08 - Project Management
*Audits, timelines, feedback, and QA*

**Path**: `/docs/08-project-management/`

**Subdirectories**:
- `audits/` - Project audits and reports
- `feedback/` - Stakeholder and class feedback
- `qa/` - Quality assurance documentation
- `timelines/` - Project schedules and milestones

**Current Location References**:
- [Product Requirements Document](MEDUSA_PRD.md)
- [Project Timeline](PROJECT_TIMELINE.md)
- [Audit Report](project-management/AUDIT_REPORT.md)
- [QA Plan](project-management/QA_PLAN.md)
- [QA Execution Summary](project-management/QA_EXECUTION_SUMMARY.md)
- [Class Feedback](CLASS_FEEDBACK.md)
- [Class Feedback Summary](CLASS_FEEDBACK_SUMMARY.md)
- [Industry Stakeholders Feedback](INDUSTRY_STAKEHOLDERS_FEEDBACK.md)
- [Verification Report](VERIFICATION_REPORT.md)
- Project Management: `/docs/project-management/`
- Project Summaries: `/docs/project-summaries/`

---

## Component Documentation

### MEDUSA CLI
**Path**: `/medusa-cli/`
- [CLI README](/medusa-cli/README.md)
- [CLI Architecture](/medusa-cli/ARCHITECTURE.md) *(if exists)*
- Source: `/medusa-cli/src/medusa/`
- Tests: `/medusa-cli/tests/`

### MEDUSA Backend
**Path**: `/medusa-backend/`
- [Backend README](/medusa-backend/README.md)
- [Backend Implementation Plan](BACKEND_IMPLEMENTATION_PLAN.md)
- Source: `/medusa-backend/app/`

### MEDUSA Web App
**Path**: `/medusa-webapp/`
- [Web App README](/medusa-webapp/README.md)
- [Dashboard Setup](MEDUSA_DASHBOARD_SETUP.md)
- Source: `/medusa-webapp/src/`

### Lab Environment
**Path**: `/lab-environment/`
- [Lab README](/lab-environment/README.md)
- Services: `/lab-environment/services/`
- Lab Status: `/docs/project-summaries/LAB_STATUS.md`

---

## Additional Resources

### Training Data
**Path**: `/training-data/`
- Training datasets for LLM fine-tuning
- Dataset configurations
- See: [Ollama Fine-Tuning](OLLAMA_FINE_TUNING.md)

### Scripts
**Path**: `/scripts/`
- Automation scripts
- Setup scripts
- Utility scripts

### AI Agent Resources
**Path**: `/.ai/`
- [AI Context](../.ai/CONTEXT.md) - Quick context for AI agents
- [File Index](../.ai/FILE_INDEX.json) - Machine-readable navigation
- [Quick Reference](../.ai/QUICK_REFERENCE.md) - Fast lookup guide

---

## Migration Status

This documentation is currently being reorganized. Files marked as "*To be created*" will be consolidated from existing documentation during the reorganization process.

### Current State (Pre-Reorganization)
- **Total Documentation Files**: ~77 markdown files
- **Locations**: `/docs/`, `/medusa-cli/`, root directory
- **Status**: Documentation scattered across multiple locations

### Target State (Post-Reorganization)
- **Structure**: Numbered sections (00-08) for logical flow
- **Consolidation**: Eliminate duplicates, single source of truth
- **AI Optimization**: Enhanced discoverability for AI agents
- **Navigation**: Breadcrumbs and cross-references throughout

---

## Finding What You Need

### By Role

**New User / Student**
1. [Getting Started](../GETTING_STARTED.md)
2. [Quick Start Dashboard](QUICK_START_MEDUSA_DASHBOARD.md)
3. [Project Overview](PROJECT_MEDUSA_OVERVIEW.md)

**Developer**
1. [Development Setup](development/) - Current location
2. [Technical Reference](development/TECHNICAL_REFERENCE.md)
3. [CLI README](/medusa-cli/README.md)

**Researcher**
1. [Project Overview](PROJECT_MEDUSA_OVERVIEW.md)
2. [Ollama Fine-Tuning](OLLAMA_FINE_TUNING.md)
3. [Product Requirements](MEDUSA_PRD.md)

**Project Manager / Instructor**
1. [Project Timeline](PROJECT_TIMELINE.md)
2. [Audit Reports](project-management/)
3. [QA Documentation](project-management/)
4. [Feedback Summaries](CLASS_FEEDBACK_SUMMARY.md)

### By Task

| Task | Documentation |
|------|---------------|
| Initial setup | [Getting Started](../GETTING_STARTED.md) |
| Deploy lab environment | [Deployment Guide](DEPLOYMENT_GUIDE.md) |
| Use CLI tool | [CLI README](/medusa-cli/README.md) |
| Configure LLM | [Ollama Fine-Tuning](OLLAMA_FINE_TUNING.md) |
| Set up web dashboard | [Dashboard Setup](MEDUSA_DASHBOARD_SETUP.md) |
| Run tests | [Development docs](development/) |
| Understand architecture | [Project Overview](PROJECT_MEDUSA_OVERVIEW.md) |
| Review security model | [PRD - Security](MEDUSA_PRD.md) |

---

## Document Conventions

### File Naming
- **Documentation**: `kebab-case.md` (e.g., `quick-start-cli.md`)
- **Constants/Major**: `UPPER_SNAKE_CASE.md` (e.g., `README.md`)

### Section Numbering
- `00-` Getting Started
- `01-` Architecture
- `02-` Development
- `03-` Deployment
- `04-` Usage
- `05-` API Reference
- `06-` Security
- `07-` Research
- `08-` Project Management

### Breadcrumb Format
```markdown
**Navigation**: [Home](../README.md) → [Docs](INDEX.md) → [Section](section/README.md) → Current Page
```

---

## Contributing to Documentation

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on:
- Adding new documentation
- Updating existing docs
- Documentation standards
- Review process

---

## Related Files

- **Main README**: [/README.md](../README.md)
- **Getting Started**: [/GETTING_STARTED.md](../GETTING_STARTED.md)
- **License**: [/LICENSE](../LICENSE) - Apache 2.0
- **Changelog**: [/CHANGELOG.md](../CHANGELOG.md)
- **AI Context**: [/.ai/CONTEXT.md](../.ai/CONTEXT.md)

---

**Last Updated**: 2025-11-06
**Version**: 2.0 (Reorganization in progress)
**Maintainers**: Project MEDUSA Team

---

**For AI Agents**: This index provides human-readable navigation. For programmatic access, use `/.ai/FILE_INDEX.json`. For quick lookups, see `/.ai/QUICK_REFERENCE.md`.
