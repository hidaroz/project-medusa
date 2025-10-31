# MEDUSA Lab Documentation Index

This directory contains all documentation for the MEDUSA Healthcare Security Testing Lab, organized by category for easy navigation.

## 📁 Directory Structure

```
docs/
├── README.md (this file)
├── getting-started/     # Setup and quick start guides
│   ├── SETUP_GUIDE.md
│   ├── QUICK_START_EHR.md
│   └── DEPLOYMENT_GUIDE_EHR.md
├── architecture/        # System architecture and design
│   ├── NETWORK_ARCHITECTURE.md
│   └── PROJECT_SUMMARY.md
├── security/            # Vulnerability documentation
│   ├── VULNERABILITY_DOCUMENTATION.md
│   └── MITRE_ATTACK_MAPPING.md
└── services/            # Service-specific documentation
    └── ehr-webapp/
        ├── INDEX.md
        ├── DELIVERABLES.md
        └── PROJECT_SUMMARY.md
```

## 📖 Quick Navigation

### For First-Time Users
1. Start with: [Getting Started → QUICK_START_EHR.md](./getting-started/QUICK_START_EHR.md)
2. Then read: [Getting Started → SETUP_GUIDE.md](./getting-started/SETUP_GUIDE.md)
3. Explore vulnerabilities: [Security → VULNERABILITY_DOCUMENTATION.md](./security/VULNERABILITY_DOCUMENTATION.md)

### For Security Testers
1. Review architecture: [Architecture → NETWORK_ARCHITECTURE.md](./architecture/NETWORK_ARCHITECTURE.md)
2. Study vulnerabilities: [Security → VULNERABILITY_DOCUMENTATION.md](./security/VULNERABILITY_DOCUMENTATION.md)
3. Practice MITRE techniques: [Security → MITRE_ATTACK_MAPPING.md](./security/MITRE_ATTACK_MAPPING.md)

### For Service Developers
1. Read project overview: [Architecture → PROJECT_SUMMARY.md](./architecture/PROJECT_SUMMARY.md)
2. Service-specific docs: [Services → ehr-webapp/INDEX.md](./services/ehr-webapp/INDEX.md)

## 📚 Documentation by Category

### Getting Started
- **[SETUP_GUIDE.md](./getting-started/SETUP_GUIDE.md)** - Complete setup instructions
- **[QUICK_START_EHR.md](./getting-started/QUICK_START_EHR.md)** - 5-minute deployment guide
- **[DEPLOYMENT_GUIDE_EHR.md](./getting-started/DEPLOYMENT_GUIDE_EHR.md)** - Detailed deployment steps

### Architecture
- **[NETWORK_ARCHITECTURE.md](./architecture/NETWORK_ARCHITECTURE.md)** - Network topology and design
- **[PROJECT_SUMMARY.md](./architecture/PROJECT_SUMMARY.md)** - Complete project overview

### Security
- **[VULNERABILITY_DOCUMENTATION.md](./security/VULNERABILITY_DOCUMENTATION.md)** - Comprehensive vulnerability catalog
- **[MITRE_ATTACK_MAPPING.md](./security/MITRE_ATTACK_MAPPING.md)** - MITRE ATT&CK techniques mapping

### Services
- **[ehr-webapp/INDEX.md](./services/ehr-webapp/INDEX.md)** - EHR webapp documentation index
- **[ehr-webapp/DELIVERABLES.md](./services/ehr-webapp/DELIVERABLES.md)** - EHR webapp deliverables
- **[ehr-webapp/PROJECT_SUMMARY.md](./services/ehr-webapp/PROJECT_SUMMARY.md)** - EHR webapp project summary

## 🔍 Finding Specific Information

### By Task
| Task | Document |
|------|----------|
| Quick deployment | [QUICK_START_EHR.md](./getting-started/QUICK_START_EHR.md) |
| Detailed setup | [SETUP_GUIDE.md](./getting-started/SETUP_GUIDE.md) |
| Understanding architecture | [NETWORK_ARCHITECTURE.md](./architecture/NETWORK_ARCHITECTURE.md) |
| Vulnerability testing | [VULNERABILITY_DOCUMENTATION.md](./security/VULNERABILITY_DOCUMENTATION.md) |
| MITRE ATT&CK mapping | [MITRE_ATTACK_MAPPING.md](./security/MITRE_ATTACK_MAPPING.md) |
| Service details | [services/ehr-webapp/INDEX.md](./services/ehr-webapp/INDEX.md) |

### By Audience
- **Students**: [QUICK_START_EHR.md](./getting-started/QUICK_START_EHR.md) → [VULNERABILITY_DOCUMENTATION.md](./security/VULNERABILITY_DOCUMENTATION.md)
- **Security Testers**: [NETWORK_ARCHITECTURE.md](./architecture/NETWORK_ARCHITECTURE.md) → [MITRE_ATTACK_MAPPING.md](./security/MITRE_ATTACK_MAPPING.md)
- **Developers**: [PROJECT_SUMMARY.md](./architecture/PROJECT_SUMMARY.md) → [ehr-webapp/INDEX.md](./services/ehr-webapp/INDEX.md)

## 📝 Notes

- All documentation paths are relative to the `docker-lab/` directory
- Original location: Some docs moved from root level and `services/ehr-webapp/` directory
- Main entry point: See `../README.md` for the overall lab documentation

## 🔄 Recent Changes

This documentation was reorganized to improve clarity and findability:
- Separated getting started guides from reference documentation
- Grouped security documentation together
- Organized service-specific docs by service
- Maintained all original content, just restructured

