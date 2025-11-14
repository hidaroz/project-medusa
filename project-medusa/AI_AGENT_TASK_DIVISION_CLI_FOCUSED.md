# MEDUSA - AI Agent Task Division (CLI/PyPI Package Focused)
## Production-Ready CLI Tool for PyPI Distribution

**Version:** 2.0 (CLI-Focused)
**Date:** November 14, 2025
**Scope Change:** Focus on PyPI package distribution, NOT webapp
**Priority:** CLI excellence, tool integration, RAG reasoning, user experience

---

## 🎯 REVISED VISION

**Goal:** Make MEDUSA the best AI-powered pentesting CLI tool available on PyPI

**What Users Get:**
```bash
pip install medusa-pentest
medusa setup
medusa run --target 192.168.1.0/24
```

**Core Priorities:**
1. ✅ **Flawless Core Functionality** - Everything works reliably
2. ✅ **Rich Tool Integration** - 30+ security tools working perfectly
3. ✅ **Intelligent RAG** - Vector + Graph DB reasoning that actually helps
4. ✅ **Excellent CLI/TUI UX** - Beautiful, intuitive command-line interface
5. ✅ **Easy Setup** - One command to get started
6. ✅ **Great Documentation** - Users can be productive in 5 minutes

**NOT Building (Deferred):**
- ❌ Web dashboard (removed from scope)
- ❌ REST API (not needed without webapp)
- ❌ WebSocket features
- ❌ Multi-user collaboration
- ❌ Team workspaces

---

## 📊 NEW PACKAGE STRUCTURE

```
PHASE 1: CORE CLI EXCELLENCE (P0 - Critical)
├── 1.1  Real Exploitation Engine
├── 1.2  Safe Exploitation Framework
├── 1.3  CLI/TUI User Experience Enhancement
├── 1.4  Configuration & Setup System
├── 1.5  RAG System Optimization (Vector + Graph)
├── 1.6  Tool Integration - Network Suite
├── 1.7  Tool Integration - Web Suite
├── 1.8  Tool Integration - Credential Suite
├── 1.9  Output & Reporting Enhancement
└── 1.10 PyPI Packaging & Distribution

PHASE 2: INTELLIGENCE & AUTOMATION (P1 - High)
├── 2.1  ML Vulnerability Scoring
├── 2.2  ML Attack Path Prediction
├── 2.3  Post-Exploitation Automation
├── 2.4  Continuous Learning System
└── 2.5  Advanced RAG with Learning

PHASE 3: POLISH & ENTERPRISE (P2 - Medium)
├── 3.1  Advanced Reporting Formats
├── 3.2  Plugin Architecture
├── 3.3  CI/CD Integration
├── 3.4  Compliance & Audit Features
└── 3.5  Performance Optimization

Total Packages: 20 (reduced from 28, removed webapp packages)
```

---

## 🚀 PHASE 1: CORE CLI EXCELLENCE (P0 - Critical)

### Package 1.1: Real Exploitation Engine
**Agent Type:** Backend Security Tools Specialist
**Complexity:** High
**Effort:** 60-80 hours
**Dependencies:** None

#### Objectives
- Integrate Metasploit Framework for real exploitation
- Remove simulation-only restriction
- Enable actual exploit execution (with safety)
- Session management for compromised hosts

#### Deliverables
1. **New Files to Create:**
   ```
   medusa-cli/src/medusa/tools/metasploit.py          (500+ LOC)
   medusa-cli/src/medusa/exploits/__init__.py
   medusa-cli/src/medusa/exploits/msf_connector.py    (400+ LOC)
   medusa-cli/src/medusa/exploits/session_manager.py  (300+ LOC)
   medusa-cli/tests/integration/test_metasploit.py    (300+ LOC)
   ```

2. **Key Features:**
   - Metasploit RPC API integration
   - Exploit module search and execution
   - Payload generation and delivery
   - Session management (Meterpreter, shell)
   - Post-exploitation module execution
   - CVE to exploit automatic matching

3. **CLI Integration:**
   ```bash
   medusa exploit --cve CVE-2024-1234 --target 192.168.1.10
   medusa sessions --list
   medusa sessions --interact 1
   ```

#### Acceptance Criteria
- [ ] Connect to MSF RPC successfully
- [ ] Search exploits by CVE/keyword
- [ ] Execute exploits against live targets
- [ ] Manage multiple sessions
- [ ] Run post-exploitation modules
- [ ] Handle errors gracefully
- [ ] 85%+ test coverage
- [ ] Works with `medusa run` workflow

---

### Package 1.2: Safe Exploitation Framework
**Agent Type:** Security & Compliance Specialist
**Complexity:** High
**Effort:** 50-60 hours
**Dependencies:** None

#### Objectives
- Create safety layer for real exploitation
- Implement authorization and scope validation
- Add rollback mechanisms
- Provide audit trail

#### Deliverables
1. **New Files to Create:**
   ```
   medusa-cli/src/medusa/safety/__init__.py
   medusa-cli/src/medusa/safety/scope_validator.py    (250+ LOC)
   medusa-cli/src/medusa/safety/authorization.py      (200+ LOC)
   medusa-cli/src/medusa/safety/rollback.py           (200+ LOC)
   medusa-cli/src/medusa/safety/audit_logger.py       (250+ LOC)
   medusa-cli/tests/unit/test_safety.py               (300+ LOC)
   ```

2. **Key Features:**
   - IP/CIDR scope validation
   - Digital authorization checking
   - Pre-flight safety checks
   - Automatic rollback on failure
   - Immutable audit logs
   - Emergency kill switch

3. **Configuration:**
   ```yaml
   # config.yaml
   safety:
     require_authorization: true
     authorized_scope:
       - 192.168.1.0/24
       - 10.0.0.0/8
     auto_rollback: true
     emergency_stop_key: "ctrl+alt+e"
     audit_log: ~/.medusa/audit.log
   ```

#### Acceptance Criteria
- [ ] Block out-of-scope targets
- [ ] Verify authorization before HIGH/CRITICAL actions
- [ ] Rollback 95%+ of failed exploits
- [ ] Complete audit trail
- [ ] Emergency stop within 2 seconds
- [ ] Integration with approval system
- [ ] 90%+ test coverage

---

### Package 1.3: CLI/TUI User Experience Enhancement
**Agent Type:** CLI/TUI Specialist
**Complexity:** High
**Effort:** 60-80 hours
**Dependencies:** None (can start immediately)

#### Objectives
- Create beautiful, intuitive CLI interface
- Add interactive TUI mode
- Improve real-time feedback
- Enhance progress visualization

#### Deliverables
1. **New Files to Create:**
   ```
   medusa-cli/src/medusa/ui/__init__.py
   medusa-cli/src/medusa/ui/tui.py                    (600+ LOC)
   medusa-cli/src/medusa/ui/progress.py               (300+ LOC)
   medusa-cli/src/medusa/ui/formatting.py             (250+ LOC)
   medusa-cli/src/medusa/ui/interactive.py            (400+ LOC)
   medusa-cli/tests/unit/test_ui.py                   (200+ LOC)
   ```

2. **Features:**
   - **Rich CLI output** (using `rich` library)
     - Colored output
     - Tables for findings
     - Progress bars
     - Syntax highlighting

   - **Interactive TUI mode** (using `textual` or `urwid`)
     - Live operation dashboard
     - Agent activity panel
     - Findings list (updating in real-time)
     - Graph visualization (ASCII art or unicode)
     - Log viewer

   - **Better prompts** (using `questionary` or `prompt_toolkit`)
     - Interactive setup wizard
     - Config selection
     - Target input with validation
     - Approval prompts

3. **CLI Commands Enhancement:**
   ```bash
   # Rich output
   medusa run --target 192.168.1.0/24 --rich

   # Interactive TUI mode
   medusa tui

   # Interactive setup
   medusa setup --interactive

   # Watch mode (live updates)
   medusa watch <operation-id>

   # Pretty findings
   medusa findings --format table
   medusa findings --format json
   medusa findings --export report.pdf
   ```

4. **TUI Layout:**
   ```
   ┌─ MEDUSA - AI-Powered Pentesting ────────────────────┐
   │ Operation: scan-192.168.1.0     Status: ⚡ Running  │
   ├──────────────────────────────────────────────────────┤
   │ ┌─ Agents ────────┐ ┌─ Findings ──────────────────┐ │
   │ │ 🔍 Recon    ✓   │ │ ❗ CVE-2024-1234 (Critical) │ │
   │ │ 🔎 Analysis ⚙️   │ │ ⚠️  Weak Password (High)    │ │
   │ │ 💥 Exploit  💤  │ │ ℹ️  Open Port 22 (Info)     │ │
   │ └─────────────────┘ └─────────────────────────────┘ │
   │ ┌─ Activity Log ──────────────────────────────────┐ │
   │ │ [12:34] Scanning 192.168.1.0/24...              │ │
   │ │ [12:35] Found 15 hosts                          │ │
   │ │ [12:36] Analyzing host 192.168.1.10...          │ │
   │ └─────────────────────────────────────────────────┘ │
   │ [q] Quit  [p] Pause  [a] Approve  [e] Emergency    │
   └──────────────────────────────────────────────────────┘
   ```

#### Acceptance Criteria
- [ ] Rich colored output working
- [ ] TUI mode fully functional
- [ ] Interactive prompts for setup/config
- [ ] Real-time progress updates
- [ ] Tables, charts, and visualizations
- [ ] Keyboard shortcuts in TUI
- [ ] Responsive to terminal resize
- [ ] Works on macOS, Linux, Windows
- [ ] 80%+ test coverage

---

### Package 1.4: Configuration & Setup System
**Agent Type:** DevOps/CLI Specialist
**Complexity:** Medium
**Effort:** 40-50 hours
**Dependencies:** None

#### Objectives
- Streamline initial setup process
- Create flexible configuration system
- Add profile management
- Environment detection and auto-config

#### Deliverables
1. **New Files to Create:**
   ```
   medusa-cli/src/medusa/setup/__init__.py
   medusa-cli/src/medusa/setup/wizard.py              (400+ LOC)
   medusa-cli/src/medusa/setup/validator.py           (300+ LOC)
   medusa-cli/src/medusa/setup/profiles.py            (250+ LOC)
   medusa-cli/src/medusa/setup/auto_detect.py         (200+ LOC)
   medusa-cli/templates/config.default.yaml           (template)
   medusa-cli/templates/profiles/*.yaml               (preset profiles)
   medusa-cli/tests/unit/test_setup.py                (300+ LOC)
   ```

2. **Setup Workflow:**
   ```bash
   # First-time setup
   medusa setup
   # Interactive wizard:
   # 1. Select LLM provider (AWS Bedrock / OpenAI / Anthropic / Ollama)
   # 2. Configure API keys
   # 3. Set up databases (Neo4j, ChromaDB)
   # 4. Install security tools (optional)
   # 5. Test connections
   # 6. Choose default profile

   # Quick setup with profile
   medusa setup --profile stealth
   medusa setup --profile aggressive
   medusa setup --profile safe

   # Verify configuration
   medusa setup --verify

   # Reset to defaults
   medusa setup --reset
   ```

3. **Configuration Profiles:**
   ```yaml
   # ~/.medusa/profiles/stealth.yaml
   profile:
     name: stealth
     description: Low-noise scanning for stealthy operations

   scanning:
     threads: 5
     timeout: 30
     rate_limit: 1000  # packets/sec

   exploitation:
     mode: simulation  # or real
     max_retries: 1
     require_approval: true

   llm:
     provider: anthropic
     model: claude-sonnet-4
     temperature: 0.3

   tools:
     enabled:
       - nmap
       - amass
       - httpx
     disabled:
       - sqlmap  # too noisy for stealth
   ```

4. **Environment Auto-Detection:**
   - Detect installed security tools
   - Check for Docker/Podman
   - Verify network connectivity
   - Suggest optimal configuration
   - Warn about missing dependencies

5. **Configuration Hierarchy:**
   ```
   Priority (highest to lowest):
   1. CLI flags (--llm-provider anthropic)
   2. Environment variables (MEDUSA_LLM_PROVIDER)
   3. Project config (./medusa.yaml)
   4. User config (~/.medusa/config.yaml)
   5. Profile config (~/.medusa/profiles/default.yaml)
   6. System defaults
   ```

#### Acceptance Criteria
- [ ] Setup wizard completes in < 5 minutes
- [ ] Auto-detection of tools working
- [ ] Profile system functional
- [ ] Configuration validation
- [ ] Clear error messages for misconfigurations
- [ ] Test all connections during setup
- [ ] Support for all LLM providers
- [ ] 85%+ test coverage

---

### Package 1.5: RAG System Optimization (Vector + Graph)
**Agent Type:** ML/RAG Specialist
**Complexity:** High
**Effort:** 70-90 hours
**Dependencies:** None (enhance existing)

#### Objectives
- Optimize RAG reasoning quality
- Improve context fusion from Vector + Graph DBs
- Enhance MITRE ATT&CK integration
- Better exploit/vulnerability matching
- Faster retrieval performance

#### Deliverables
1. **Files to Enhance/Create:**
   ```
   medusa-cli/src/medusa/context/rag_optimizer.py     (500+ LOC)
   medusa-cli/src/medusa/context/hybrid_retrieval.py  (400+ LOC)
   medusa-cli/src/medusa/context/reranker.py          (300+ LOC)
   medusa-cli/src/medusa/context/query_optimizer.py   (250+ LOC)
   medusa-cli/src/medusa/context/cache.py             (200+ LOC)
   medusa-cli/tests/unit/test_rag_system.py           (400+ LOC)
   ```

2. **RAG Enhancements:**

   **A. Hybrid Retrieval Strategy**
   - Vector DB (ChromaDB) for semantic search
   - Graph DB (Neo4j) for relationship queries
   - Fusion of both contexts
   - Intelligent routing based on query type

   **B. Query Optimization**
   ```python
   # Optimize queries for different contexts

   # Vulnerability lookup → Vector DB
   "What exploits are available for CVE-2024-1234?"
   → ChromaDB similarity search

   # Attack path → Graph DB
   "How can I move from host A to host B?"
   → Neo4j graph traversal

   # Historical knowledge → Vector DB
   "What worked on similar Windows 2019 servers?"
   → ChromaDB with filters

   # Network topology → Graph DB
   "What hosts are connected to the database server?"
   → Neo4j relationship query

   # Hybrid query → Both DBs
   "What's the best way to exploit this network?"
   → Fuse results from both
   ```

   **C. Re-ranking & Filtering**
   - Relevance scoring
   - MITRE ATT&CK technique matching
   - CVE severity weighting
   - Historical success rate
   - Context-aware filtering

   **D. MITRE ATT&CK Deep Integration**
   - Embed all techniques in Vector DB
   - Link techniques to tools in Graph DB
   - Suggest techniques for current phase
   - Track technique coverage

   **E. Performance Optimization**
   - Query caching (Redis or in-memory)
   - Batch retrieval
   - Async queries
   - Index optimization
   - Embedding cache

3. **Enhanced Context Fusion:**
   ```python
   class EnhancedContextFusion:
       async def get_context(self, query: str, operation_state: dict) -> Context:
           """
           Intelligent context retrieval and fusion
           """
           # 1. Classify query type
           query_type = self.classify_query(query)

           # 2. Route to appropriate retrieval
           if query_type == "vulnerability":
               vector_results = await self.vector_search(query)
               graph_results = await self.graph_lookup(vector_results[0].cve)
           elif query_type == "attack_path":
               graph_results = await self.graph_path_search(query)
               vector_results = await self.enrich_with_tactics(graph_results)
           else:
               # Hybrid search
               vector_results, graph_results = await asyncio.gather(
                   self.vector_search(query),
                   self.graph_search(query)
               )

           # 3. Fuse and re-rank
           fused_context = self.fuse_contexts(vector_results, graph_results)
           ranked_context = self.rerank(fused_context, operation_state)

           # 4. Add MITRE ATT&CK context
           enriched_context = self.add_mitre_context(ranked_context)

           return enriched_context
   ```

4. **Metrics & Monitoring:**
   - Context relevance scoring
   - Retrieval latency tracking
   - Cache hit rate
   - Query success rate
   - LLM token usage optimization

#### Acceptance Criteria
- [ ] Hybrid retrieval working (Vector + Graph)
- [ ] Query classification accurate (90%+)
- [ ] Context relevance improved (A/B test)
- [ ] MITRE ATT&CK techniques integrated
- [ ] Retrieval latency < 500ms
- [ ] Cache hit rate > 60%
- [ ] Re-ranking improves result quality
- [ ] 85%+ test coverage
- [ ] CLI command: `medusa rag-test --query "..."` for testing

---

### Package 1.6: Tool Integration - Network Suite
**Agent Type:** Security Tools Integration Specialist
**Complexity:** High
**Effort:** 80-100 hours
**Dependencies:** None

#### Objectives
- Integrate 8-10 essential network security tools
- Standardize tool wrappers
- Implement robust output parsing
- Add to RAG knowledge base

#### Deliverables
1. **New Files to Create:**
   ```
   medusa-cli/src/medusa/tools/network/
     __init__.py
     responder.py                                      (250+ LOC)
     bloodhound.py                                     (300+ LOC)
     crackmapexec.py                                   (350+ LOC)
     impacket.py                                       (400+ LOC)
     enum4linux.py                                     (200+ LOC)
     hydra.py                                          (250+ LOC)
     masscan.py                                        (200+ LOC)
     netcat.py                                         (150+ LOC)
   medusa-cli/tests/integration/test_network_tools.py (400+ LOC)
   ```

2. **Tools to Integrate:**
   - **Responder** - LLMNR/NBT-NS poisoning
   - **BloodHound** - Active Directory mapping
   - **CrackMapExec** - SMB/WinRM/MSSQL exploitation
   - **Impacket** - SMB/RPC protocol suite
   - **Enum4Linux** - SMB enumeration
   - **Hydra** - Network service brute-forcing
   - **Masscan** - Ultra-fast port scanning
   - **Netcat** - Network Swiss Army knife

3. **Standard Tool Wrapper:**
   ```python
   class NetworkTool(BaseTool):
       """Standard interface for all network tools"""

       name: str
       description: str
       risk_level: RiskLevel
       required_binaries: List[str]

       async def check_installed(self) -> bool:
           """Verify tool is installed"""

       async def execute(self, **kwargs) -> ToolResult:
           """Execute tool with parameters"""

       async def parse_output(self, raw: str) -> StructuredOutput:
           """Parse tool output into structured format"""

       def get_help(self) -> str:
           """Get tool usage help"""

       def to_rag(self) -> dict:
           """Export tool knowledge for RAG system"""
   ```

4. **CLI Integration:**
   ```bash
   # List available tools
   medusa tools --list --category network

   # Check tool installation
   medusa tools --check crackmapexec

   # Run tool directly
   medusa tool crackmapexec --target 192.168.1.10 --user admin --pass-list passwords.txt

   # Install missing tools
   medusa tools --install hydra
   ```

#### Acceptance Criteria
- [ ] All 8 tools integrated and working
- [ ] Standardized wrapper pattern
- [ ] Output parsing to structured format
- [ ] Error handling for missing tools
- [ ] Integration with agents
- [ ] Added to RAG knowledge base
- [ ] CLI commands working
- [ ] 80%+ test coverage

---

### Package 1.7: Tool Integration - Web Suite
**Agent Type:** Security Tools Integration Specialist
**Complexity:** High
**Effort:** 70-90 hours
**Dependencies:** None

#### Objectives
- Integrate 7-9 web application testing tools
- Implement web-specific parsers
- Add to RAG system

#### Deliverables
1. **New Files to Create:**
   ```
   medusa-cli/src/medusa/tools/web/
     __init__.py
     nikto.py                                          (200+ LOC)
     nuclei.py                                         (350+ LOC)
     wpscan.py                                         (250+ LOC)
     ffuf.py                                           (200+ LOC)
     jwt_tool.py                                       (200+ LOC)
     whatweb.py                                        (150+ LOC)
     wafw00f.py                                        (150+ LOC)
     gobuster.py                                       (200+ LOC)
   medusa-cli/tests/integration/test_web_tools.py     (400+ LOC)
   ```

2. **Tools to Integrate:**
   - **Nikto** - Web server scanner
   - **Nuclei** - Template-based vulnerability scanner
   - **WPScan** - WordPress security scanner
   - **ffuf** - Fast web fuzzer
   - **JWT_Tool** - JWT token testing
   - **WhatWeb** - Web technology identifier
   - **wafw00f** - WAF detection
   - **Gobuster** - Directory/DNS brute-forcing

3. **Features:**
   - Template management for Nuclei
   - Auto-update of vulnerability databases
   - WAF detection before scanning
   - Technology stack identification
   - Intelligent fuzzing based on findings

#### Acceptance Criteria
- [ ] All 8 tools working
- [ ] Nuclei templates auto-updated
- [ ] WAF detection functional
- [ ] Output parsing accurate
- [ ] Integration with web_scanner agent
- [ ] Added to RAG system
- [ ] 80%+ test coverage

---

### Package 1.8: Tool Integration - Credential Suite
**Agent Type:** Security Tools Integration Specialist
**Complexity:** Medium
**Effort:** 50-60 hours
**Dependencies:** None

#### Objectives
- Integrate credential tools
- Implement secure credential storage
- Add credential workflow

#### Deliverables
1. **New Files to Create:**
   ```
   medusa-cli/src/medusa/tools/credentials/
     __init__.py
     hashcat.py                                        (300+ LOC)
     john.py                                           (250+ LOC)
     mimikatz.py                                       (350+ LOC)
     lazagne.py                                        (200+ LOC)
   medusa-cli/src/medusa/credentials/
     __init__.py
     vault.py                                          (300+ LOC)
     harvester.py                                      (250+ LOC)
   medusa-cli/tests/integration/test_credential_tools.py (300+ LOC)
   ```

2. **Tools:**
   - **Hashcat** - GPU password cracking
   - **John the Ripper** - CPU password cracking
   - **Mimikatz** - Windows credential extraction
   - **LaZagne** - Multi-platform credential recovery

3. **Credential Vault:**
   - Encrypted storage
   - Automatic deduplication
   - Credential validation
   - Export/import functionality

#### Acceptance Criteria
- [ ] All 4 tools integrated
- [ ] Secure credential storage
- [ ] Deduplication working
- [ ] Integration with exploitation
- [ ] 80%+ test coverage

---

### Package 1.9: Output & Reporting Enhancement
**Agent Type:** Backend/Reporting Specialist
**Complexity:** Medium
**Effort:** 50-60 hours
**Dependencies:** Package 1.3 (for rich output)

#### Objectives
- Enhance CLI output formatting
- Improve report generation
- Add multiple export formats
- Create report templates

#### Deliverables
1. **Files to Enhance/Create:**
   ```
   medusa-cli/src/medusa/reporter.py                  (+400 LOC)
   medusa-cli/src/medusa/reports/
     templates/
       cli_summary.j2                                  (template)
       executive_report.html.j2                        (template)
       technical_report.md.j2                          (template)
     exporters/
       pdf_exporter.py                                 (300+ LOC)
       markdown_exporter.py                            (200+ LOC)
       json_exporter.py                                (150+ LOC)
       sarif_exporter.py                               (250+ LOC)
   medusa-cli/tests/unit/test_reporting.py            (300+ LOC)
   ```

2. **Features:**
   - **CLI Output Formats:**
     - Rich tables (default)
     - JSON (machine-readable)
     - Plain text (parseable)
     - Markdown (documentation)

   - **Report Types:**
     - Executive summary
     - Technical detailed
     - Findings list
     - MITRE ATT&CK coverage
     - Timeline of attack

   - **Export Formats:**
     - PDF (professional)
     - Markdown (editable)
     - JSON (programmatic)
     - SARIF (CI/CD integration)
     - CSV (spreadsheet)

3. **CLI Commands:**
   ```bash
   # Generate report after operation
   medusa report <operation-id> --format pdf --output report.pdf
   medusa report <operation-id> --format markdown --output report.md
   medusa report <operation-id> --format sarif --output results.sarif

   # Real-time output formats
   medusa run --target ... --output-format json > results.json
   medusa findings --format table
   medusa findings --format csv > findings.csv

   # Custom templates
   medusa report --template custom.j2 --output custom_report.pdf
   ```

#### Acceptance Criteria
- [ ] All output formats working
- [ ] PDF generation functional
- [ ] SARIF format for CI/CD
- [ ] Templates customizable
- [ ] Rich CLI output beautiful
- [ ] 80%+ test coverage

---

### Package 1.10: PyPI Packaging & Distribution
**Agent Type:** DevOps/Python Packaging Specialist
**Complexity:** Medium
**Effort:** 40-50 hours
**Dependencies:** All other Phase 1 packages should be near complete

#### Objectives
- Prepare MEDUSA for PyPI distribution
- Create robust installation process
- Handle dependencies properly
- Provide excellent documentation

#### Deliverables
1. **New/Enhanced Files:**
   ```
   pyproject.toml                                      (comprehensive)
   setup.py                                            (if needed)
   MANIFEST.in
   medusa-cli/src/medusa/__version__.py
   medusa-cli/src/medusa/__main__.py                   (entry point)

   docs/
     installation.md
     quickstart.md
     configuration.md
     troubleshooting.md
     tool-installation.md

   scripts/
     install-tools.sh                                  (Linux/macOS)
     install-tools.ps1                                 (Windows)
     post-install.py                                   (setup wizard)

   .github/workflows/
     publish-pypi.yml                                  (CI/CD for publishing)
     test-install.yml                                  (test pip install)
   ```

2. **PyPI Package Structure:**
   ```
   medusa-security/
   ├── pyproject.toml
   ├── README.md (PyPI landing page)
   ├── LICENSE
   ├── CHANGELOG.md
   ├── medusa-cli/
   │   └── src/medusa/
   │       ├── __init__.py
   │       ├── __main__.py
   │       ├── __version__.py
   │       └── ... (all modules)
   └── tests/
   ```

3. **pyproject.toml Configuration:**
   ```toml
   [build-system]
   requires = ["setuptools>=68.0", "wheel"]
   build-backend = "setuptools.build_meta"

   [project]
   name = "medusa-security"
   version = "2.0.0"
   description = "AI-powered autonomous pentesting platform"
   readme = "README.md"
   authors = [{name = "MEDUSA Team", email = "info@medusa-security.dev"}]
   license = {text = "MIT"}
   requires-python = ">=3.10"

   dependencies = [
       "anthropic>=0.21.0",
       "openai>=1.0.0",
       "boto3>=1.34.0",
       "neo4j>=5.18.0",
       "chromadb>=0.4.0",
       "rich>=13.0.0",
       "textual>=0.50.0",
       "click>=8.1.0",
       "pyyaml>=6.0",
       "pydantic>=2.0.0",
       "httpx>=0.27.0",
       "aiofiles>=23.0.0",
       # ... more
   ]

   [project.optional-dependencies]
   dev = [
       "pytest>=8.0.0",
       "pytest-cov>=4.0.0",
       "pytest-asyncio>=0.23.0",
       "black>=24.0.0",
       "ruff>=0.3.0",
       "mypy>=1.8.0",
   ]

   ml = [
       "scikit-learn>=1.4.0",
       "torch>=2.2.0",
       "transformers>=4.38.0",
   ]

   [project.scripts]
   medusa = "medusa.cli:main"

   [project.urls]
   Homepage = "https://github.com/yourusername/medusa"
   Documentation = "https://docs.medusa-security.dev"
   Repository = "https://github.com/yourusername/medusa"
   Issues = "https://github.com/yourusername/medusa/issues"
   ```

4. **Installation Experience:**
   ```bash
   # Install from PyPI
   pip install medusa-security

   # With ML features
   pip install medusa-security[ml]

   # Development install
   pip install medusa-security[dev]

   # First-time setup
   medusa setup --interactive

   # Install security tools (optional)
   medusa tools --install-all
   # or
   medusa tools --install nmap,masscan,nuclei

   # Verify installation
   medusa --version
   medusa setup --verify

   # Quick start
   medusa quickstart
   ```

5. **Documentation for PyPI:**
   - Comprehensive README.md
   - Installation instructions
   - Quick start guide
   - Configuration examples
   - Troubleshooting guide
   - Link to full documentation

6. **Testing Installation:**
   ```yaml
   # .github/workflows/test-install.yml
   name: Test PyPI Installation

   on: [push, pull_request]

   jobs:
     test-install:
       runs-on: ${{ matrix.os }}
       strategy:
         matrix:
           os: [ubuntu-latest, macos-latest, windows-latest]
           python-version: ["3.10", "3.11", "3.12"]

       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-python@v5
           with:
             python-version: ${{ matrix.python-version }}

         - name: Build package
           run: python -m build

         - name: Install package
           run: pip install dist/*.whl

         - name: Test CLI
           run: |
             medusa --version
             medusa --help
             medusa setup --dry-run

         - name: Run basic tests
           run: medusa self-test
   ```

7. **Publishing Process:**
   ```bash
   # Update version
   bump2version minor  # or patch, major

   # Build distribution
   python -m build

   # Test on TestPyPI first
   python -m twine upload --repository testpypi dist/*
   pip install --index-url https://test.pypi.org/simple/ medusa-security

   # Publish to PyPI (after testing)
   python -m twine upload dist/*
   ```

#### Acceptance Criteria
- [ ] Package builds successfully
- [ ] Installation via pip works
- [ ] All dependencies resolved
- [ ] Entry points working (`medusa` command)
- [ ] Post-install setup wizard runs
- [ ] Works on Linux, macOS, Windows
- [ ] Documentation complete
- [ ] Published to TestPyPI successfully
- [ ] CI/CD pipeline for publishing
- [ ] Version management automated

---

## 🎯 PHASE 2: INTELLIGENCE & AUTOMATION (P1)

### Package 2.1: ML Vulnerability Scoring
**Agent Type:** ML/Data Science Specialist
**Complexity:** High
**Effort:** 80-100 hours
**Dependencies:** Phase 1 complete (operational data needed)

#### Objectives
- Build ML model for exploit success prediction
- Integrate with RAG system
- Improve agent decision-making

#### Deliverables
1. **New Files:**
   ```
   medusa-cli/src/medusa/ml/
     __init__.py
     vulnerability_scorer.py                           (500+ LOC)
     feature_engineering.py                            (350+ LOC)
     model_trainer.py                                  (300+ LOC)
   medusa-cli/models/                                  (trained models)
   medusa-cli/training-data/                           (datasets)
   ```

2. **Features:**
   - Predict exploitation success probability
   - Feature engineering from CVE data
   - Model training pipeline
   - Integration with context fusion
   - CLI: `medusa ml train` and `medusa ml predict`

#### Acceptance Criteria
- [ ] 75%+ accuracy on test set
- [ ] Model training automated
- [ ] Integration with agents
- [ ] CLI commands working
- [ ] 85%+ test coverage

---

### Package 2.2: ML Attack Path Prediction
**Agent Type:** ML/Graph Analytics Specialist
**Complexity:** Very High
**Effort:** 100-120 hours
**Dependencies:** Package 2.1

#### Objectives
- Graph neural network for attack path optimization
- Predict most likely successful paths
- Integrate with Neo4j

#### Deliverables
1. **New Files:**
   ```
   medusa-cli/src/medusa/ml/
     attack_path_predictor.py                          (600+ LOC)
     graph_embeddings.py                               (400+ LOC)
   medusa-cli/models/attack_path_model.h5
   ```

2. **Features:**
   - GNN-based path prediction
   - Real-time path ranking
   - Integration with orchestrator

#### Acceptance Criteria
- [ ] 70%+ accuracy on validation
- [ ] Real-time inference (<2s)
- [ ] Neo4j integration working
- [ ] 85%+ test coverage

---

### Package 2.3: Post-Exploitation Automation
**Agent Type:** Backend Security Specialist
**Complexity:** High
**Effort:** 80-100 hours
**Dependencies:** Packages 1.1, 1.2

#### Objectives
- Automated privilege escalation
- Automated lateral movement
- Credential harvesting

#### Deliverables
1. **New Agents:**
   ```
   medusa-cli/src/medusa/agents/
     privilege_escalation_agent.py                     (700+ LOC)
     lateral_movement_agent.py                         (650+ LOC)
   ```

2. **Features:**
   - LinPEAS/WinPEAS integration
   - Pass-the-hash automation
   - Credential reuse testing
   - CLI: `medusa privesc` and `medusa lateral`

#### Acceptance Criteria
- [ ] Automated privesc working
- [ ] Lateral movement detection
- [ ] Safe execution with rollback
- [ ] 80%+ test coverage

---

### Package 2.4: Continuous Learning System
**Agent Type:** ML/Backend Specialist
**Complexity:** High
**Effort:** 60-80 hours
**Dependencies:** Packages 2.1, 2.2

#### Objectives
- Learn from every operation
- Auto-update knowledge base
- Optimize agent performance

#### Deliverables
1. **New Files:**
   ```
   medusa-cli/src/medusa/learning/
     outcome_tracker.py                                (400+ LOC)
     knowledge_updater.py                              (450+ LOC)
     agent_optimizer.py                                (500+ LOC)
   ```

2. **Features:**
   - Track success/failure rates
   - Update RAG system automatically
   - Agent performance optimization

#### Acceptance Criteria
- [ ] Outcome tracking functional
- [ ] Knowledge base auto-updates
- [ ] Agent performance improves over time
- [ ] 80%+ test coverage

---

### Package 2.5: Advanced RAG with Learning
**Agent Type:** ML/RAG Specialist
**Complexity:** High
**Effort:** 60-80 hours
**Dependencies:** Packages 1.5, 2.4

#### Objectives
- Integrate learning system with RAG
- Personalized recommendations
- Context-aware retrieval

#### Deliverables
1. **Enhanced Files:**
   ```
   medusa-cli/src/medusa/context/
     adaptive_rag.py                                   (500+ LOC)
     personalization.py                                (400+ LOC)
   ```

2. **Features:**
   - Learn from successful operations
   - Personalize recommendations
   - Adapt to user preferences

#### Acceptance Criteria
- [ ] Learning integration working
- [ ] Recommendations improve over time
- [ ] User-specific adaptation
- [ ] 85%+ test coverage

---

## 🎯 PHASE 3: POLISH & ENTERPRISE (P2)

### Package 3.1: Advanced Reporting Formats
**Enhancement to 1.9**
- More report templates
- Compliance framework reports
- Custom branding

### Package 3.2: Plugin Architecture
- Extensible plugin system
- Community plugins
- Plugin marketplace

### Package 3.3: CI/CD Integration
- GitHub Actions
- GitLab CI
- Jenkins plugins

### Package 3.4: Compliance & Audit
- Enhanced audit logging
- Compliance mappings
- Digital authorization

### Package 3.5: Performance Optimization
- Query optimization
- Caching improvements
- Parallel execution

---

## 📊 REVISED DEPENDENCY MATRIX

```
Phase 1 (Can Start Immediately):
├── 1.1 Real Exploitation        [No Deps]
├── 1.2 Safe Exploitation        [No Deps]
├── 1.3 CLI/TUI Enhancement      [No Deps]
├── 1.4 Config & Setup           [No Deps]
├── 1.5 RAG Optimization         [No Deps]
├── 1.6 Network Tools            [No Deps]
├── 1.7 Web Tools                [No Deps]
├── 1.8 Credential Tools         [No Deps]
├── 1.9 Reporting                [Needs: 1.3]
└── 1.10 PyPI Packaging          [Needs: All above]

Phase 2 (After Phase 1):
├── 2.1 ML Vulnerability         [Needs: Operational data]
├── 2.2 ML Attack Path           [Needs: 2.1]
├── 2.3 Post-Exploitation        [Needs: 1.1, 1.2]
├── 2.4 Continuous Learning      [Needs: 2.1, 2.2]
└── 2.5 Advanced RAG             [Needs: 1.5, 2.4]

Phase 3 (Polish):
All can start after Phase 1 complete
```

---

## 🚀 RECOMMENDED EXECUTION PLAN

### Strategy: 4-6 Agents for 12 Weeks

```
Week 1-2: Foundation
Agent 1: 1.1 Real Exploitation
Agent 2: 1.2 Safe Exploitation
Agent 3: 1.3 CLI/TUI Enhancement
Agent 4: 1.5 RAG Optimization
Agent 5: 1.6 Network Tools
Agent 6: 1.7 Web Tools

Week 3-4: Core Complete
Agent 1: 1.8 Credential Tools
Agent 2: 1.4 Config & Setup
Agent 3: 1.9 Reporting (needs 1.3)
Agent 4: Continue 1.5 if needed
Agent 5: Continue 1.6 if needed
Agent 6: Continue 1.7 if needed

Week 5-6: Integration & Testing
All agents: Integration testing
Agent lead: 1.10 PyPI Packaging

Week 7-12: Phase 2 (Intelligence)
Parallel work on ML features
```

---

## 🎯 SUCCESS METRICS (Revised)

### Phase 1 Success
- [ ] `pip install medusa-security` works flawlessly
- [ ] Setup completes in < 5 minutes
- [ ] TUI mode is beautiful and functional
- [ ] 30+ tools integrated and working
- [ ] RAG system provides relevant context 90%+ of time
- [ ] Reports generated in multiple formats
- [ ] 85%+ test coverage
- [ ] Works on Linux, macOS, Windows

### Phase 2 Success
- [ ] ML models achieve 75%+ accuracy
- [ ] Automated post-exploitation working
- [ ] Continuous learning improves performance
- [ ] RAG adapts to user patterns

### Overall Project Success
- [ ] 1000+ pip installs in first month
- [ ] Positive user feedback (4+/5 rating)
- [ ] Active community contributions
- [ ] Recognized as top CLI pentesting tool

---

**Version:** 2.0 (CLI-Focused)
**Last Updated:** November 14, 2025
**Scope:** PyPI package, not webapp
