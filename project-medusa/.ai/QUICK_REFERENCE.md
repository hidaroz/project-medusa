# MEDUSA Quick Reference for AI Agents

Fast lookup for common queries and tasks.

## Instant Answers

### "Where is the main CLI code?"
`/medusa-cli/src/medusa/cli.py`

### "How do I set up the development environment?"
1. `/GETTING_STARTED.md` - Quick start
2. `/docs/02-development/development-setup.md` - Detailed guide

### "Where are the tests?"
- CLI tests: `/medusa-cli/tests/`
- Backend tests: `/medusa-backend/tests/`
- Integration tests: `/tests/`

### "How do I deploy the lab?"
1. `/docs/03-deployment/docker-deployment.md`
2. Run: `docker-compose up` from `/lab-environment/`

### "Where is the architecture documented?"
`/docs/01-architecture/system-overview.md`

### "How does the approval system work?"
`/docs/06-security/approval-gates.md`

### "Where are the API endpoints?"
- Backend routes: `/medusa-backend/app/routes/`
- API docs: `/docs/05-api-reference/`

### "How do I use the interactive shell?"
`/docs/04-usage/interactive-shell.md`

### "Where is the LLM integration?"
- Code: `/medusa-cli/src/medusa/llm/`
- Docs: `/docs/07-research/llm-integration.md`

### "Where is the training data?"
`/training-data/datasets/`

### "What's the project structure?"
See `/docs/INDEX.md` for complete navigation

## Component Entry Points

| Component | Path | Main File | README |
|-----------|------|-----------|--------|
| CLI | `/medusa-cli` | `src/medusa/cli.py` | `/medusa-cli/README.md` |
| Backend | `/medusa-backend` | `app/main.py` | `/medusa-backend/README.md` |
| Web App | `/medusa-webapp` | `src/main.jsx` | `/medusa-webapp/README.md` |
| Lab | `/lab-environment` | `docker-compose.yml` | `/lab-environment/README.md` |

## File Naming Conventions

- **Documentation**: `kebab-case.md` (e.g., `quick-start-cli.md`)
- **Python**: `snake_case.py` (e.g., `cli_handler.py`)
- **Directories**: `lowercase-hyphenated` (e.g., `lab-environment`)
- **Constants**: `UPPER_SNAKE_CASE.md` (e.g., `README.md`)

## Documentation Sections

```
/docs/
├── 00-getting-started/    ← Installation, setup
├── 01-architecture/       ← System design
├── 02-development/        ← Dev guides
├── 03-deployment/         ← Deployment
├── 04-usage/              ← User guides
├── 05-api-reference/      ← API docs
├── 06-security/           ← Security policies
├── 07-research/           ← Academic research
└── 08-project-management/ ← PMO, audits
```

## Key Concepts

### MITRE ATT&CK Mapping
Documented in `/docs/01-architecture/mitre-attack-mapping.md`

### Approval Gates
Two-tier system: User approval + Supervisor approval
Details: `/docs/06-security/approval-gates.md`

### Interactive Shell Modes
- Standard mode
- Tab completion
- Checkpoint system
Guide: `/docs/04-usage/interactive-shell.md`

### Training Data Format
JSON-formatted datasets for LLM fine-tuning
Location: `/training-data/datasets/`
Config: `/training-data/CONFIG.md`

## Common Commands

### Setup
```bash
# Clone and setup
git clone <repo>
cd project-medusa
pip install -r medusa-cli/requirements.txt
```

### Running
```bash
# CLI
python -m medusa.cli

# Lab Environment
cd lab-environment
docker-compose up -d

# Backend
cd medusa-backend
uvicorn app.main:app --reload

# Frontend
cd medusa-webapp
npm install && npm run dev
```

### Testing
```bash
# CLI tests
cd medusa-cli
pytest tests/

# Backend tests
cd medusa-backend
pytest tests/
```

## Technology Stack

| Layer | Technology |
|-------|------------|
| CLI | Python 3.x, Click, Rich |
| Backend | FastAPI, Python 3.x |
| Frontend | React, Vite |
| LLM | Ollama (local) |
| Infrastructure | Docker, Docker Compose |
| Testing | pytest, unittest |

## Quick Links

- **Main Index**: `/.ai/FILE_INDEX.json`
- **Documentation Map**: `/docs/INDEX.md`
- **Project Context**: `/.ai/CONTEXT.md`
- **License**: `/LICENSE` (Apache 2.0)

## Emergency Troubleshooting

### "Nothing is working!"
1. Check `/GETTING_STARTED.md`
2. Check `/docs/00-getting-started/troubleshooting.md`

### "Docker issues"
Check `/docs/03-deployment/docker-deployment.md`

### "Import errors"
Check Python path and requirements in component README

### "API not responding"
Check backend configuration in `/medusa-backend/README.md`

## Recent Updates

- **2025-11-06**: Repository reorganization completed
- **2025-11**: Comprehensive audit (77 MD files, 44 Python files)
- **2025-10**: Interactive shell modes merged
- **2025-10**: Professional reporting system added

---

**Pro Tip for AI Agents**: Always check `FILE_INDEX.json` first for structured navigation, then use this quick reference for instant answers to common questions.
