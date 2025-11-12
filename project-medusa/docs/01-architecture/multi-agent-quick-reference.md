# Multi-Agent Evolution: Quick Reference

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → [Full Plan](multi-agent-evolution-plan.md) → Quick Reference

---

## 🎯 TL;DR

**What**: Evolve MEDUSA from single-agent to multi-agent system with AWS Bedrock and intelligent context engineering

**Timeline**: 12 weeks (3 phases)

**Cost**: ~$0.06-0.15 per operation (with smart routing)

**Impact**: Production-grade AI security platform suitable for research publication

---

## 📊 Three Major Upgrades

### 1. ☁️ AWS Bedrock Integration
- **Claude 3.5 Sonnet** for strategic planning (smart)
- **Claude 3.5 Haiku** for tool execution (fast + cheap)
- **Titan Embeddings** for vector database
- **Cost tracking** per operation and per agent
- **70-80% cost savings** with smart routing

### 2. 🧠 Context Fusion Engine
- **Vector DB (Chroma)** for semantic search
  - 200+ MITRE ATT&CK techniques
  - 100+ CVEs indexed
  - Tool documentation (Nmap, SQLMap, etc.)
- **Graph DB (Neo4j)** - already implemented
  - Infrastructure relationships
  - Attack paths
- **Fusion Engine** combines both for rich LLM context

### 3. 🤖 Multi-Agent System (6 Agents)
1. **Orchestrator** - Coordinates everything (Sonnet)
2. **Recon Agent** - Port scanning, enumeration (Haiku)
3. **Vuln Analysis** - SQL injection, CVE matching (Haiku)
4. **Exploitation** - Execute attacks with approval (Haiku)
5. **Planning Agent** - Strategic planning (Sonnet)
6. **Reporting Agent** - Documentation (Haiku)

---

## 🗓️ Phase Timeline

| Phase | Weeks | Focus | Key Deliverable |
|-------|-------|-------|-----------------|
| **Phase 1** | 1-3 | AWS Bedrock | Cost-optimized LLM with routing |
| **Phase 2** | 4-7 | Context Fusion | Vector + Graph context engine |
| **Phase 3** | 8-12 | Multi-Agent | 6 specialized agents + orchestrator |

---

## 💡 Key Design Decisions

### AWS Bedrock
- ✅ **Primary** (cloud-based, zero-footprint)
- ✅ Ollama as **fallback** (local, air-gapped)
- ✅ **Cost tracking** is mandatory
- ✅ Smart/fast model routing (Sonnet vs Haiku)

### Vector Database
- ✅ **Chroma** (simple, Python-native)
- ✅ **Titan Embeddings** (primary) + local fallback
- ✅ Index **tool docs first**, then MITRE, then CVEs
- ✅ Historical ops as "Phase 3" feature

### Multi-Agent Architecture
- ✅ **6 agents** with clear specialization
- ✅ **Hybrid communication**: Shared state (Neo4j) + Message bus
- ✅ **Different models per agent**: Sonnet for planning, Haiku for tools
- ✅ **Orchestrator has final authority** (safety lock)
- ✅ **Agents have memory**: Short-term (operation) + Long-term (DB)

---

## 🔑 Critical Success Factors

### Phase 1 Success Criteria
- ✅ Bedrock health check passes
- ✅ Cost tracking accurate within 1%
- ✅ Smart routing reduces costs by 40%+

### Phase 2 Success Criteria
- ✅ 200+ MITRE techniques indexed
- ✅ Vector search 90%+ relevant results
- ✅ Context improves LLM quality (validated)

### Phase 3 Success Criteria
- ✅ All 6 agents operational
- ✅ Agent success rate > 85%
- ✅ Full operation < 10 minutes
- ✅ Cost per operation < $0.50

---

## 💰 Cost Breakdown

### Development (One-time)
- AWS Bedrock testing: ~$180 total
- Vector DB embedding: Included above

### Operations (Per pentest operation)
**With Smart Routing** (recommended):
- Reconnaissance: $0.004
- Vuln Analysis: $0.006
- Planning: $0.045
- Reporting: $0.008
- **Total: ~$0.06-0.15**

**Without Routing** (all Sonnet):
- **Total: ~$0.50-0.80**

**Savings: 70-80%**

---

## 🚀 Getting Started

### Step 1: Set Up AWS
```bash
# Install AWS CLI
pip install boto3 botocore

# Configure credentials
aws configure
```

### Step 2: Create Development Branch
```bash
git checkout -b feature/multi-agent-evolution
```

### Step 3: Start with Phase 1.1
Read: [Multi-Agent Evolution Plan](multi-agent-evolution-plan.md) → Phase 1.1

Implement: `medusa-cli/src/medusa/core/llm/providers/bedrock.py`

### Step 4: Track Progress
Use GitHub Projects or similar to track:
- [ ] Phase 1.1: Bedrock Provider
- [ ] Phase 1.2: Model Routing
- [ ] Phase 1.3: Cost Tracking
- [ ] ... (see full plan)

---

## 📁 File Structure

### New Files to Create

```
medusa-cli/src/medusa/
├── core/llm/
│   ├── providers/
│   │   └── bedrock.py          # NEW: AWS Bedrock provider
│   ├── router.py                # NEW: Smart model routing
│   └── cost_tracker.py          # NEW: Cost tracking
├── context/
│   ├── vector_store.py          # NEW: Chroma vector DB
│   ├── fusion_engine.py         # NEW: Context fusion
│   └── cve_indexer.py           # NEW: CVE database indexer
└── agents/
    ├── base.py                  # NEW: Base agent class
    ├── message_bus.py           # NEW: Agent communication
    ├── recon_agent.py           # NEW: Reconnaissance
    ├── vuln_analysis_agent.py   # NEW: Vuln analysis
    ├── exploit_agent.py         # NEW: Exploitation
    ├── planning_agent.py        # NEW: Strategic planning
    ├── reporting_agent.py       # NEW: Reporting
    └── orchestrator.py          # NEW: Orchestrator

medusa-cli/scripts/
├── index_mitre_attack.py        # NEW: MITRE indexer
└── index_tool_docs.py           # NEW: Tool doc indexer
```

---

## 🛡️ Safety Reminders

1. **Approval Gates** - Exploitation ALWAYS requires approval
2. **Cost Limits** - Default $5 max per operation
3. **Audit Logging** - All actions logged
4. **Credential Security** - AWS keys never logged

---

## 🔗 Quick Links

- **Full Implementation Plan**: [multi-agent-evolution-plan.md](multi-agent-evolution-plan.md)
- **AWS Bedrock Docs**: https://docs.aws.amazon.com/bedrock/
- **ChromaDB Docs**: https://docs.trychroma.com/
- **MITRE ATT&CK**: https://attack.mitre.org/

---

## 📞 Questions?

See the [Full Plan](multi-agent-evolution-plan.md) for:
- Detailed code implementations
- Week-by-week tasks
- Testing strategies
- Integration patterns
- Cost optimization techniques

---

**Last Updated**: 2025-11-12
**Status**: Ready for Implementation
**Priority**: High

---

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → [Full Plan](multi-agent-evolution-plan.md) → Quick Reference
