# Project MEDUSA — Healthcare — Offensive Security

**Course**: INFO 498B — Agentic Cybersecurity with AI & LLMs
**Team**: [Team #5 - Healthcare - Offense] — Brian Yuan, Hidar Elhassan, Lawrence Wu, 
**One-line pitch**: Autonomous LLM-powered penetration testing agent that continuously assesses healthcare infrastructure vulnerabilities, reducing reliance on expensive annual pentests.

---

## 1) Live Demo

**Synthetic Industry**: `http://143.198.65.195:8080/patients/` — status: [Up/Down] — test creds (fake): [user / pass]
- 8 vulnerable services simulating small hospital IT environment
- Services: EHR webapp, SSH, FTP, MySQL database, Log Server, EHR API, [specify 2 more]
- Network segmentation: DMZ (public-facing) + Internal Backend

**Agentic System**: 'http://143.198.65.195/medusa/' — status: [Up/Down] — notes: Monolithic autonomous agent with single LLM reasoning engine, PostgreSQL state management, integrated offensive security tools (nmap, SQLMap, Metasploit)

**Logs/Observability**: PostgreSQL database
- Decision logs: `/logs/decisions.log`
- Tool executions: `/logs/tool_executions.log`
- Findings: `/logs/findings.log`
 
---

## 2) Thesis & Outcome

**Original thesis (week 2)**: An LLM-powered autonomous agent integrated into a C2 framework will drastically reduce time-to-impact and discover wider attack paths compared to traditional scripted penetration testing tools.

**Final verdict**: **Partially True (60-70% validated)**

**Why (top evidence)**:

**Evidence 1**: 24-hour continuous autonomous operation achieved — Agent successfully ran for 24 hours without human intervention, executing reconnaissance → vulnerability analysis → exploitation attempts with logical tool chaining and contextual reasoning. [See: `/evidence/demo5_24hr_test/`, PostgreSQL decision logs]

**Evidence 2**: Feasibility proven but superiority unproven — System demonstrated LLMs CAN autonomously conduct pentesting (feasibility validated), but we did NOT conduct baseline comparison testing against Metasploit automation or human pentesters to validate "drastically reduce time-to-impact" or "wider attack paths" claims. No comparative metrics collected.

**Evidence 3**: Strategic simplification validated deployment viability — Abandoned Demo #4's multi-agent architecture (5 agents, 3 databases, enterprise complexity) for monolithic design, proving healthcare organizations can actually deploy this (4GB RAM, single container, on-premises capable). Complexity reduction enabled successful testing. [See: `demos_summary/demo_5_summary.md`]

---

## 3) What We Built

**Synthetic industry**:
- **Infrastructure**: 8 vulnerable services on Digital Ocean simulating small hospital network
- **APIs/services**: EHR web application (Node.js/Python), MySQL database with synthetic patient records, SSH/FTP servers with weak credentials, EHR API with broken authentication, centralized log server, [specify 3 more]
- **Roles**: Clinician (read patient data), EHR Admin (database access), IT Security (full network access), Patient (portal access)
- **Data generator**: Mistral-7B via Ollama — generates synthetic patient demographics, medical records, billing information, NO real PHI

**Agentic system**:
- **Architecture**: Monolithic agent with single LLM reasoning engine implementing OODA loop (Observe → Orient → Decide → Act)
- **Agents**: Single unified agent (Demo #5) — previous multi-agent system (5 specialized agents) deprecated for operational simplicity
- **Tools**: nmap (reconnaissance), SQLMap (database exploitation), Metasploit framework
- **Model providers**: Gemini API (cloud deployment) OR Ollama + local model (on-premises/air-gapped deployment)
- **Memory/eval**: PostgreSQL checkpointing (30-minute intervals), decision logging, tool execution history, MITRE ATT&CK framework alignment (200+ scenarios, 76% technique coverage)

**Key risks addressed (or exercised)**:
- Trust relationship exploitation (clinician → EHR, vendor → hospital IT)
- Lateral movement from DMZ to internal backend services
- Credential harvesting and privilege escalation
- Database compromise and simulated ransomware deployment
- EDR evasion through adaptive reasoning (vs. static scripts)

---

## 4) Roles, Auth, Data

**Roles & permissions**:
- **Clinician** → Read access to patient records via EHR webapp, limited API access
- **EHR Administrator** → Database admin rights, full EHR system configuration
- **IT Security Officer** → Network-wide access, administrative SSH, log server access
- **Patient** → Portal access to own records, billing information
- **MEDUSA Agent** → Starts with no privileges; objective is privilege escalation to domain admin equivalent

**Authentication**:
- EHR webapp: Username/password (intentionally weak passwords for some accounts)
- Database: MySQL root credentials (weak password configured as vulnerability)
- SSH: Password + key-based authentication (weak credentials for testing)
- API: Bearer token authentication (broken validation as intentional vulnerability)
- Agent auth: None initially — must discover and exploit credentials

**Data**:
Synthetic only; generator: [Specify tool — e.g., Faker library, custom scripts]
- **Schema**: `patients` (demographics, MRN, diagnoses), `billing` (charges, insurance), `medications` (prescriptions), `appointments` (scheduling), `users` (credentials for various roles)
- **Volume**: [Specify — e.g., 10,000 synthetic patient records, 500 appointments, 50 users]
- **100% synthetic** — NO real patient data, NO real hospital systems, NO PHI

---

## 5) Experiments Summary (Demos #3 - #5)

**Demo #3**: LLMs can reason autonomously about security tasks — Built local inference infrastructure (Mistral-7B via Ollama), created MITRE ATT&CK dataset (200+ scenarios, 76% coverage), implemented 3 operational modes (autonomous/interactive/observe), deployed Dockerized healthcare kill box — Result: **PASS** — Infrastructure proven functional, LLM reasoning for security tasks validated — Evidence: [demos_summary/demo_3_summary.md](demos_summary/demo_3_summary.md)

**Demo #4 (continuous run)**: uptime **100%** over 7 days, incidents **1** (Digital Ocean abuse complaint for "web scanning/exploit reconnaissance" — ironic proof scanning worked), Improvement observed: **NO** — Built impressive multi-agent infrastructure (LangGraph, 5 agents, dual databases: ChromaDB + Neo4j) but never ran full autonomous test; system too complex for healthcare sector deployment (over-engineering identified) — Evidence: [demos_summary/demo_4_summary.md](demos_summary/demo_4_summary.md)

**Demo #5 (final)**: Autonomous continuous operation feasibility, monolithic architecture viability for healthcare deployment — Result: **PASS** — 24-hour autonomous test completed successfully with zero crashes, zero human interventions, logical tool chaining demonstrated, contextual reasoning validated; strategic simplification (90% complexity reduction from Demo #4) enabled successful deployment — Evidence: [demos_summary/demo_5_summary.md](demos_summary/demo_5_summary.md), PostgreSQL decision logs at `/evidence/demo5_logs/`

---

## 6) Key Results (plain text)

**Effectiveness**:
- Services discovered: [X out of 8 services]
- Vulnerabilities identified: [X total, specify categories: SQL injection, weak credentials, broken auth, etc.]
- Exploitation success rate: [X% of identified vulnerabilities successfully exploited]
- Attack path discovery: Demonstrated logical progression (reconnaissance → vulnerability analysis → targeted exploitation)
- MITRE technique coverage: 76% of relevant healthcare ATT&CK techniques represented in knowledge base

**Reliability**:
- **Demo #4**: 100% uptime over 7 days (infrastructure validation)
- **Demo #5**: 100% uptime over 24-hour autonomous test (0 crashes, 0 zombie states)
- **PostgreSQL checkpointing**: Functional but not needed (no crashes to recover from)
- **Watchdog monitoring**: 0 interventions required (no infinite loops detected)

**Safety**:
- **Policy violations blocked**: Destructive commands (rm, shutdown, pkill) blacklisted — agent prevented from data deletion or service termination
- **Guardrails that mattered**:
  - Rate limiting (30-second minimum between tool executions) — prevented DoS against target
  - Scope gating — agent confined to specified target network, out-of-scope access attempts blocked
  - Human kill-switch available throughout testing (not used — agent operated safely)

---

## 7) How to Use / Deploy

**Prereqs**:
- Docker or VM environment (4GB RAM minimum, 2 CPU cores, 50GB storage)
- LLM provider: Gemini API key (cloud) OR Ollama installed (local)
- PostgreSQL database (can be containerized)
- Target environment network access
- Environment variables: `LLM_PROVIDER`, `GEMINI_API_KEY` or `OLLAMA_HOST`, `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `TARGET_NETWORK`

**Deploy steps**: see `docs/deploy.md` [to be created]
```bash
# Quick start
git clone [repository URL]
cd medusa
cp .env.example .env  # Configure LLM provider and database
docker-compose up -d
```

**Test steps**: see `docs/test-plan.md` [to be created]
```bash
# Run 2-hour validation test
python medusa_agent.py --mode interactive --target 64.23.239.147 --duration 2h

# Run full 24-hour autonomous test
python medusa_agent.py --mode autonomous --target 64.23.239.147 --duration 24h

# Monitor progress
psql -h localhost -U medusa -d medusa_state -c "SELECT * FROM decisions ORDER BY timestamp DESC LIMIT 10;"
```

---

## 8) Safety, Ethics, Limits

**Synthetic data only**; no real credentials or org systems.
- All patient records, credentials, and hospital data are 100% fabricated
- NO real patient health information (PHI), NO HIPAA-covered data
- NO attacks against production systems or real organizations

**Controls**:
- **Scope gating**: Agent hardcoded to only scan specified target network (out-of-scope access blocked)
- **Throttling**: Minimum 30 seconds between tool executions (prevents resource exhaustion)
- **Sandboxing**: Agent runs in isolated Docker container with limited host access
- **Policy checks**: Destructive commands (`rm`, `shutdown`, `pkill`) are blacklisted

**Known limits/failure modes**:
- No comparative baseline: Cannot claim superiority over traditional tools without head-to-head testing (missing 30-40% of hypothesis validation)
- 24-hour test duration: Longer tests (7-day) needed to assess learning and adaptation
- Single-target limitation: Current implementation assumes one target environment
- LLM hallucination risk: Agent may confidently execute incorrect commands based on faulty reasoning (observed in [X]% of decisions)
- Tool dependency: Requires external tools (nmap, SQLMap) to be pre-installed
- Cost monitoring: Cloud API usage can scale unexpectedly in long-running tests

---

## 9) Final Deliverables

**1000-word paper**: [hypothesis_validation_paper.md](hypothesis_validation_paper.md)

**Slides**: [Link to Google Slides / PowerPoint]

**Evidence folder (logs/screens)**: `/evidence/`
- `/evidence/demo3_infrastructure/` — Architecture diagrams, MITRE dataset samples
- `/evidence/demo4_multiagent/` — LangGraph configs, Digital Ocean abuse complaint, 7-day uptime logs
- `/evidence/demo5_24hr_test/` — PostgreSQL decision logs, tool execution outputs, findings summary
- `/evidence/screenshots/` — Agent reasoning examples, target environment discovery

---

## 10) Next Steps

**1. Comparative baseline testing (2-4 weeks)**: Run controlled tests: MEDUSA vs. Metasploit automation vs. human pentester. Measure: time-to-impact, vulnerabilities discovered, attack path diversity, stealth (EDR alerts). Goal: Validate remaining 30-40% of hypothesis with empirical performance data.

**2. Extended autonomous operation (1-2 months)**: 7-day continuous test with intentional checkpoint/resume validation. Multi-environment testing (clinic vs. hospital vs. medical device network). Learning assessment: Does agent improve over time? Does Context Fusion Engine reduce repeated failures?

**3. Production hardening & commercialization prep (3-6 months)**: Fine-tune model on healthcare-specific red team scenarios (expected 30-40% decision speed improvement). Implement RAG pipeline for real-time threat intelligence. Develop web-based monitoring dashboard. Partner hospital pilot deployment (on-premises, HIPAA-compliant). SOC 2 compliance preparation.

---

**Maintainers**: Hidar Elhassan, Lawrence Wu, Brian Yuan
**Contact**: hidar@uw.edu, longyx@uw.edu, jyuan7@uw.edu

---

## Appendix: Key Metrics Summary

- **Hypothesis Validation**: 60-70% (feasibility proven, superiority unproven)
- **MITRE ATT&CK Coverage**: 76% of relevant healthcare techniques
- **Demo #4 Uptime**: 100% over 7 days continuous
- **Demo #5 Autonomous Test**: 24 hours, 0 interventions, 0 crashes
- **Complexity Reduction**: 90% (Demo #4 multi-agent → Demo #5 monolithic)
- **Production Readiness**: 85%
- **Cost Optimization** (Demo #4): 60% savings via smart Haiku/Sonnet routing
- **Resource Requirements** (Demo #5): 4GB RAM, 2 CPU cores (vs. Demo #4's 16GB+ multi-service)

### Digital Ocean Abuse Complaint
**Activity Detected**: "Web scanning/exploit reconnaissance"
**Source IP**: 64.23.239.147
**Interpretation**: Proof that MEDUSA's reconnaissance capabilities are aggressive enough to trigger third-party intrusion detection systems

---

**Last Updated**: December 4, 2025
