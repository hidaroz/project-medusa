# Architecture

**System design, components, and technical architecture**

> **Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → Architecture

---

## Overview

This section documents MEDUSA's architecture, including system design, component relationships, and technical implementation details.

## Contents

### System Design
- [Project Overview](project-overview.md) - High-level system overview and goals
- [CLI Architecture](cli-architecture.md) - CLI component design and structure

### Multi-Agent Evolution (NEW!)

> **🎯 First time here?** Start with the [📊 EXECUTIVE SUMMARY](EXECUTIVE-SUMMARY.md)
>
> **📚 Looking for specific docs?** Check the [DOCUMENTATION MAP](DOCUMENTATION-MAP.md)

**Quick Links**:
- [**📊 EXECUTIVE SUMMARY**](EXECUTIVE-SUMMARY.md) - **Start here!** Complete overview and metrics
- [**📚 DOCUMENTATION MAP**](DOCUMENTATION-MAP.md) - Guide to all documentation

**Status & Planning**:
- [**🎉 Current Status Report**](CURRENT-STATUS.md) - **95% complete - 24,444 lines of code - 1-2 hours to production**
- [**🧪 Testing Plan**](TESTING-PLAN.md) - **Comprehensive testing plan for final 5%**
- [**🚀 Multi-Agent Evolution Plan**](multi-agent-evolution-plan.md) - Complete 12-week implementation plan
- [Quick Reference Guide](multi-agent-quick-reference.md) - TL;DR summary and fast-start
- [Implementation Checklist](implementation-checklist.md) - Week-by-week tracking

**Historical Records**:
- [Previous Status Report](FINAL-STATUS.md) - Historical status (85% - Nov 12)
- [Implementation Status](implementation-status.md) - Detailed verification and metrics

### Technical Documentation
- System Overview - *To be created* - Detailed system architecture
- Component Design - *To be created* - Individual component architectures
- Network Architecture - *To be created* - Network topology and security
- MITRE ATT&CK Mapping - *To be created* - Attack technique coverage
- Database Schema - *To be created* - Data models and relationships

---

## Key Architectural Principles

### Modular Design
MEDUSA is built as independent, loosely-coupled components:
- **medusa-cli**: Autonomous AI agent (Python)
- **medusa-backend**: REST API service (FastAPI)
- **medusa-webapp**: Web interface (React)
- **lab-environment**: Vulnerable infrastructure (Docker)

### AI-Driven Architecture
- LLM integration at core (Ollama/Gemini)
- Approval gates for risk management
- Context-aware decision making
- MITRE ATT&CK framework integration

### Security by Design
- Two-tier approval system
- Network isolation (Docker)
- Audit logging throughout
- Ethical guidelines enforcement

---

## Architecture Diagrams

For visual representations of the system:
- See [Main README](../../README.md#-architecture) for system diagram
- Component-specific diagrams in respective READMEs

---

## Component Documentation

- **CLI**: [medusa-cli/README.md](../../medusa-cli/README.md)
- **Backend**: [medusa-backend/README.md](../../medusa-backend/README.md)
- **Frontend**: [medusa-webapp/README.md](../../medusa-webapp/README.md)
- **Lab**: [lab-environment/README.md](../../lab-environment/README.md)

---

## Related Documentation

- **Getting Started**: [Setup Guide](../00-getting-started/)
- **Development**: [Development Guide](../02-development/)
- **API Reference**: [API Documentation](../05-api-reference/)
- **Research**: [LLM Integration](../07-research/)

---

**For Developers**: Understanding the architecture is crucial before contributing. See [Development Guide](../02-development/) after reading this section.
