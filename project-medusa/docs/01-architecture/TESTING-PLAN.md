# MEDUSA Multi-Agent System: Comprehensive Testing Plan

**Date**: 2025-11-14
**Status**: 95% Complete - Testing Plan for Remaining 5%
**Purpose**: Detailed plan to verify all untested components

---

## 🎯 Overview

This document provides a **step-by-step testing plan** for all components that have been implemented but not yet verified as working. The goal is to move from **95% to 100% complete** with full confidence in system functionality.

---

## 📋 Testing Scope

### What's Already Tested ✅
- ✅ Basic CLI framework (existing tests)
- ✅ LLM integration (unit tests exist)
- ✅ Configuration management
- ✅ Basic approval system
- ✅ Reporter functionality

### What Needs Testing ⚠️
- ⚠️ **AWS Bedrock integration** (provider, cost tracking)
- ⚠️ **Vector database** (ChromaDB, embeddings)
- ⚠️ **Context fusion engine** (vector + graph)
- ⚠️ **All 6 agents** (end-to-end)
- ⚠️ **Multi-agent coordination** (orchestrator)
- ⚠️ **CLI commands** (`agent run`, `agent status`, `agent report`)
- ⚠️ **Indexer scripts** (MITRE, CVE, tool docs)
- ⚠️ **Smart model routing**
- ⚠️ **Message bus** (pub/sub)

---

## 🧪 Testing Strategy

### Testing Levels

```
Level 1: Dependency Verification (30 min)
   ↓
Level 2: Unit Testing (4-6 hours)
   ↓
Level 3: Integration Testing (6-8 hours)
   ↓
Level 4: End-to-End Testing (4-6 hours)
   ↓
Level 5: Performance & Cost Validation (2-4 hours)
```

**Total Estimated Time**: **16-24 hours** (2-3 days)

---

## 📦 Level 1: Dependency Verification

**Goal**: Ensure all dependencies are installed and importable
**Duration**: 30 minutes
**Priority**: CRITICAL (blocks everything else)

### 1.1 Install Dependencies

```bash
cd /Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install all dependencies
pip install -r requirements.txt
```

**Expected Output**:
```
Successfully installed chromadb-1.3.x
Successfully installed sentence-transformers-5.1.x
Successfully installed torch-2.3.x
...
```

**Potential Issues**:
- ChromaDB may require system libraries (sqlite3-dev on Linux)
- PyTorch download is large (~2GB)
- sentence-transformers downloads models (~500MB)

**Troubleshooting**:
```bash
# If ChromaDB fails on Linux
sudo apt-get install libsqlite3-dev

# If pip fails
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Check individual packages
pip show chromadb
pip show sentence-transformers
pip show boto3
```

### 1.2 Verify Imports

**Test File**: Create `tests/verify_imports.py`

```python
"""
Verify all critical imports work
Run: python tests/verify_imports.py
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def test_imports():
    """Test all critical imports"""

    print("Testing imports...")

    # Core LLM
    try:
        from medusa.core.llm.providers.bedrock import BedrockProvider
        print("✅ BedrockProvider imported")
    except Exception as e:
        print(f"❌ BedrockProvider failed: {e}")
        return False

    try:
        from medusa.core.llm.router import ModelRouter
        print("✅ ModelRouter imported")
    except Exception as e:
        print(f"❌ ModelRouter failed: {e}")
        return False

    try:
        from medusa.core.cost_tracker import OperationCostTracker
        print("✅ OperationCostTracker imported")
    except Exception as e:
        print(f"❌ OperationCostTracker failed: {e}")
        return False

    # Context
    try:
        from medusa.context.vector_store import VectorStore
        print("✅ VectorStore imported")
    except Exception as e:
        print(f"❌ VectorStore failed: {e}")
        return False

    try:
        from medusa.context.fusion_engine import ContextFusionEngine
        print("✅ ContextFusionEngine imported")
    except Exception as e:
        print(f"❌ ContextFusionEngine failed: {e}")
        return False

    # Agents
    try:
        from medusa.agents.orchestrator_agent import OrchestratorAgent
        print("✅ OrchestratorAgent imported")
    except Exception as e:
        print(f"❌ OrchestratorAgent failed: {e}")
        return False

    try:
        from medusa.agents.reconnaissance_agent import ReconnaissanceAgent
        print("✅ ReconnaissanceAgent imported")
    except Exception as e:
        print(f"❌ ReconnaissanceAgent failed: {e}")
        return False

    try:
        from medusa.agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent
        print("✅ VulnerabilityAnalysisAgent imported")
    except Exception as e:
        print(f"❌ VulnerabilityAnalysisAgent failed: {e}")
        return False

    try:
        from medusa.agents.exploitation_agent import ExploitationAgent
        print("✅ ExploitationAgent imported")
    except Exception as e:
        print(f"❌ ExploitationAgent failed: {e}")
        return False

    try:
        from medusa.agents.planning_agent import PlanningAgent
        print("✅ PlanningAgent imported")
    except Exception as e:
        print(f"❌ PlanningAgent failed: {e}")
        return False

    try:
        from medusa.agents.reporting_agent import ReportingAgent
        print("✅ ReportingAgent imported")
    except Exception as e:
        print(f"❌ ReportingAgent failed: {e}")
        return False

    try:
        from medusa.agents.message_bus import MessageBus
        print("✅ MessageBus imported")
    except Exception as e:
        print(f"❌ MessageBus failed: {e}")
        return False

    # CLI
    try:
        from medusa.cli_multi_agent import agent_app
        print("✅ CLI multi-agent commands imported")
    except Exception as e:
        print(f"❌ CLI multi-agent failed: {e}")
        return False

    print("\n✅ All imports successful!")
    return True

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)
```

**Run**:
```bash
cd medusa-cli
python tests/verify_imports.py
```

**Success Criteria**: All imports pass ✅

---

## 🧩 Level 2: Unit Testing

**Goal**: Test individual components in isolation
**Duration**: 4-6 hours
**Priority**: HIGH

### 2.1 AWS Bedrock Provider Tests

**Test File**: `tests/unit/test_bedrock_provider.py`

```python
"""
Unit tests for BedrockProvider
Tests cost tracking, model selection, error handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError


def test_bedrock_provider_initialization():
    """Test BedrockProvider initializes correctly"""
    from medusa.core.llm.providers.bedrock import BedrockProvider

    with patch('boto3.client'):
        provider = BedrockProvider(
            model="anthropic.claude-3-5-sonnet-20241022-v2:0",
            region="us-west-2"
        )
        assert provider.model == "anthropic.claude-3-5-sonnet-20241022-v2:0"
        assert provider.region == "us-west-2"


def test_bedrock_cost_calculation():
    """Test cost calculation is accurate"""
    from medusa.core.llm.providers.bedrock import BedrockProvider

    with patch('boto3.client'):
        provider = BedrockProvider(
            model="anthropic.claude-3-5-sonnet-20241022-v2:0"
        )

        # Test Sonnet pricing: $3/$15 per 1M tokens
        cost = provider._calculate_cost(
            input_tokens=1000,  # 1K tokens
            output_tokens=500   # 0.5K tokens
        )

        expected = (1000/1_000_000 * 3.00) + (500/1_000_000 * 15.00)
        assert abs(cost - expected) < 0.0001


def test_bedrock_haiku_cost_calculation():
    """Test Haiku has correct pricing"""
    from medusa.core.llm.providers.bedrock import BedrockProvider

    with patch('boto3.client'):
        provider = BedrockProvider(
            model="anthropic.claude-3-5-haiku-20241022-v1:0"
        )

        # Test Haiku pricing: $0.80/$4 per 1M tokens
        cost = provider._calculate_cost(
            input_tokens=1000,
            output_tokens=500
        )

        expected = (1000/1_000_000 * 0.80) + (500/1_000_000 * 4.00)
        assert abs(cost - expected) < 0.0001


def test_bedrock_error_handling():
    """Test BedrockProvider handles errors correctly"""
    from medusa.core.llm.providers.bedrock import BedrockProvider
    from medusa.core.llm.exceptions import LLMAuthenticationError

    with patch('boto3.client') as mock_client:
        provider = BedrockProvider()

        # Simulate authentication error
        mock_runtime = Mock()
        mock_runtime.invoke_model.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException'}},
            'invoke_model'
        )
        provider.bedrock_runtime = mock_runtime

        with pytest.raises(LLMAuthenticationError):
            provider.generate("test prompt")
```

**Run**:
```bash
pytest tests/unit/test_bedrock_provider.py -v
```

**Success Criteria**: All tests pass ✅

---

### 2.2 Model Router Tests

**Test File**: `tests/unit/test_model_router.py`

```python
"""
Unit tests for ModelRouter
Tests complexity assessment and model selection
"""

import pytest
from medusa.core.llm.router import ModelRouter, TaskComplexity


def test_router_initialization():
    """Test ModelRouter initializes with correct models"""
    router = ModelRouter(
        smart_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
        fast_model="anthropic.claude-3-5-haiku-20241022-v1:0"
    )

    assert router.smart_model == "anthropic.claude-3-5-sonnet-20241022-v2:0"
    assert router.fast_model == "anthropic.claude-3-5-haiku-20241022-v1:0"


def test_router_selects_smart_for_complex():
    """Test router selects Sonnet for complex tasks"""
    router = ModelRouter(
        smart_model="sonnet",
        fast_model="haiku"
    )

    # Complex tasks should use smart model
    complex_tasks = [
        "strategic_planning",
        "exploitation_planning",
        "attack_chain_generation",
        "report_generation"
    ]

    for task in complex_tasks:
        model = router.select_model(task)
        assert model == "sonnet", f"Task {task} should use smart model"


def test_router_selects_fast_for_simple():
    """Test router selects Haiku for simple tasks"""
    router = ModelRouter(
        smart_model="sonnet",
        fast_model="haiku"
    )

    # Simple tasks should use fast model
    simple_tasks = [
        "tool_execution",
        "output_parsing",
        "data_extraction",
        "command_generation"
    ]

    for task in simple_tasks:
        model = router.select_model(task)
        assert model == "haiku", f"Task {task} should use fast model"


def test_router_complexity_assessment():
    """Test complexity assessment logic"""
    router = ModelRouter()

    # Test with context size
    complexity = router._assess_complexity(
        "analysis",
        context={"text_length": 5000}  # Large context
    )
    assert complexity == TaskComplexity.COMPLEX

    complexity = router._assess_complexity(
        "parsing",
        context={"text_length": 500}  # Small context
    )
    assert complexity == TaskComplexity.SIMPLE
```

**Run**:
```bash
pytest tests/unit/test_model_router.py -v
```

---

### 2.3 Cost Tracker Tests

**Test File**: `tests/unit/test_cost_tracker.py`

```python
"""
Unit tests for OperationCostTracker
Tests cost recording, aggregation, and reporting
"""

import pytest
from datetime import datetime
from medusa.core.cost_tracker import OperationCostTracker, CostEntry


def test_cost_tracker_initialization():
    """Test CostTracker initializes correctly"""
    tracker = OperationCostTracker(operation_id="TEST-001")
    assert tracker.operation_id == "TEST-001"
    assert len(tracker.entries) == 0


def test_cost_tracker_record():
    """Test recording cost entries"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record(
        agent="orchestrator",
        task_type="planning",
        model="sonnet",
        input_tokens=1000,
        output_tokens=500,
        cost_usd=0.025,
        latency_ms=1200
    )

    assert len(tracker.entries) == 1
    entry = tracker.entries[0]
    assert entry.agent == "orchestrator"
    assert entry.task_type == "planning"
    assert entry.cost_usd == 0.025


def test_cost_tracker_summary():
    """Test cost summary calculation"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    # Record multiple entries
    tracker.record("orchestrator", "planning", "sonnet", 1000, 500, 0.025, 1000)
    tracker.record("recon", "scanning", "haiku", 500, 200, 0.005, 500)
    tracker.record("reporting", "generate_report", "sonnet", 2000, 1000, 0.050, 2000)

    tracker.finalize()
    summary = tracker.get_summary()

    assert summary["total_cost_usd"] == 0.080
    assert summary["total_input_tokens"] == 3500
    assert summary["total_output_tokens"] == 1700
    assert "orchestrator" in summary["agent_breakdown"]
    assert "recon" in summary["agent_breakdown"]


def test_cost_tracker_export_json():
    """Test JSON export functionality"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("recon", "scanning", "haiku", 500, 200, 0.005, 500)
    tracker.finalize()

    json_data = tracker.export_json()

    assert "operation_id" in json_data
    assert "summary" in json_data
    assert "entries" in json_data
    assert json_data["operation_id"] == "TEST-001"
```

**Run**:
```bash
pytest tests/unit/test_cost_tracker.py -v
```

---

### 2.4 Vector Store Tests

**Test File**: `tests/unit/test_vector_store.py`

```python
"""
Unit tests for VectorStore
Tests ChromaDB integration and search functionality
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from medusa.context.vector_store import VectorStore


@pytest.fixture
def mock_chroma_client():
    """Mock ChromaDB client"""
    mock = MagicMock()
    mock_collection = MagicMock()
    mock_collection.count.return_value = 100
    mock.get_or_create_collection.return_value = mock_collection
    return mock


def test_vector_store_initialization(mock_chroma_client):
    """Test VectorStore initializes with ChromaDB"""
    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()
        assert store.client is not None
        assert "mitre_attack" in store.collections


def test_vector_store_search_mitre(mock_chroma_client):
    """Test MITRE ATT&CK search"""
    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Mock search results
        store.collections["mitre_attack"].query.return_value = {
            "ids": [["T1046"]],
            "documents": [["Network Service Scanning"]],
            "metadatas": [[{
                "technique_id": "T1046",
                "technique_name": "Network Service Scanning",
                "tactic": "discovery"
            }]]
        }

        results = store.search_mitre_techniques("port scanning", top_k=5)

        assert len(results) > 0
        assert results[0]["technique_id"] == "T1046"


def test_vector_store_stats(mock_chroma_client):
    """Test getting vector store statistics"""
    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        stats = store.get_stats()

        assert "mitre_attack" in stats
        assert "cve_database" in stats
        assert "tool_docs" in stats
```

**Run**:
```bash
pytest tests/unit/test_vector_store.py -v
```

---

## 🔗 Level 3: Integration Testing

**Goal**: Test components working together
**Duration**: 6-8 hours
**Priority**: HIGH

### 3.1 Indexer Scripts Integration Tests

**Duration**: 20-30 minutes (includes actual indexing)

#### 3.1.1 Test MITRE ATT&CK Indexer

```bash
# Run the indexer
cd medusa-cli
python scripts/index_mitre_attack.py

# Expected output:
# Downloading MITRE ATT&CK from GitHub...
# Downloaded 600+ techniques
# Indexing into vector store...
# ✅ Indexed 600+ MITRE techniques
# Testing semantic search...
# Query: "network scanning"
# Found 5 relevant techniques
```

**Verification**:
```python
# Create tests/integration/test_mitre_indexer.py

import pytest
from medusa.context.vector_store import VectorStore


def test_mitre_indexer_populated_database():
    """Test MITRE indexer actually populated the database"""
    store = VectorStore()

    stats = store.get_stats()
    assert stats["mitre_attack"]["count"] > 200, "Should have 200+ MITRE techniques"

    # Test semantic search works
    results = store.search_mitre_techniques("scanning networks", top_k=5)
    assert len(results) > 0, "Should find relevant techniques"
    assert any("scan" in r.get("technique_name", "").lower() for r in results)
```

#### 3.1.2 Test Tool Documentation Indexer

```bash
python scripts/index_tool_docs.py

# Expected output:
# Indexing tool documentation...
# ✅ Indexed Nmap (50+ commands)
# ✅ Indexed SQLMap (40+ options)
# ✅ Indexed Kerbrute (10+ commands)
# ✅ Indexed HTTPX (20+ options)
# ✅ Indexed Amass (30+ commands)
```

**Verification**:
```python
def test_tool_docs_indexer():
    """Test tool documentation is searchable"""
    store = VectorStore()

    # Search for nmap commands
    results = store.search_tool_usage("scan all ports", top_k=3)
    assert len(results) > 0
    assert any("nmap" in r.get("tool", "").lower() for r in results)
```

#### 3.1.3 Test CVE Indexer

```bash
python scripts/index_cves.py

# Expected output:
# Indexing CVE database...
# ✅ Indexed 100+ high-severity CVEs
```

**Verification**:
```python
def test_cve_indexer():
    """Test CVE database is searchable"""
    store = VectorStore()

    # Search for specific vulnerabilities
    results = store.search_cves("remote code execution java", top_k=5)
    assert len(results) > 0
    assert any(r.get("severity") in ["high", "critical"] for r in results)
```

**Run All Indexer Tests**:
```bash
pytest tests/integration/test_indexers.py -v
```

---

### 3.2 Context Fusion Engine Integration Tests

**Test File**: `tests/integration/test_context_fusion.py`

```python
"""
Integration tests for Context Fusion Engine
Tests vector + graph context building
"""

import pytest
from medusa.context.fusion_engine import ContextFusionEngine
from medusa.context.vector_store import VectorStore
from medusa.world_model.client import WorldModelClient


@pytest.mark.asyncio
async def test_context_fusion_reconnaissance():
    """Test building reconnaissance context"""

    # Initialize components
    vector_store = VectorStore()
    world_model = WorldModelClient()
    await world_model.connect()

    engine = ContextFusionEngine(
        vector_store=vector_store,
        world_model=world_model
    )

    # Build context
    context = engine.build_context_for_reconnaissance(
        target="test.example.com",
        current_findings=[]
    )

    # Verify context contains relevant info
    assert "mitre_techniques" in context
    assert "tool_suggestions" in context
    assert len(context["mitre_techniques"]) > 0

    await world_model.close()


@pytest.mark.asyncio
async def test_context_fusion_vulnerability_analysis():
    """Test building vulnerability analysis context"""

    vector_store = VectorStore()
    world_model = WorldModelClient()
    await world_model.connect()

    engine = ContextFusionEngine(
        vector_store=vector_store,
        world_model=world_model
    )

    context = engine.build_context_for_vulnerability_analysis(
        target_services=[
            {"service": "http", "version": "Apache 2.4.49"}
        ]
    )

    assert "cves" in context
    assert "exploitation_guidance" in context

    await world_model.close()
```

**Run**:
```bash
pytest tests/integration/test_context_fusion.py -v
```

---

### 3.3 Agent Integration Tests

**Test File**: `tests/integration/test_agents_integration.py`

```python
"""
Integration tests for individual agents
Tests each agent with real dependencies
"""

import pytest
from medusa.agents.reconnaissance_agent import ReconnaissanceAgent
from medusa.agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent
from medusa.context.fusion_engine import ContextFusionEngine


@pytest.mark.asyncio
async def test_reconnaissance_agent_with_context():
    """Test ReconnaissanceAgent uses context fusion"""

    # Setup
    context_engine = ContextFusionEngine()
    agent = ReconnaissanceAgent(
        agent_id="recon-test",
        context_engine=context_engine
    )

    # Create a simple reconnaissance task
    task = {
        "type": "port_scan",
        "target": "127.0.0.1",  # localhost for safety
        "parameters": {
            "ports": "80,443"
        }
    }

    # Execute (with mock LLM to avoid actual API calls)
    with patch_llm_provider():
        result = await agent.execute_task(task)

    assert result is not None
    assert result.status in ["completed", "failed"]


@pytest.mark.asyncio
async def test_vulnerability_analysis_agent():
    """Test VulnerabilityAnalysisAgent with context"""

    context_engine = ContextFusionEngine()
    agent = VulnerabilityAnalysisAgent(
        agent_id="vuln-test",
        context_engine=context_engine
    )

    task = {
        "type": "analyze_service",
        "target": "test-service",
        "service_info": {
            "name": "Apache HTTPD",
            "version": "2.4.49"
        }
    }

    with patch_llm_provider():
        result = await agent.execute_task(task)

    assert result is not None
```

**Run**:
```bash
pytest tests/integration/test_agents_integration.py -v
```

---

## 🎭 Level 4: End-to-End Testing

**Goal**: Test complete multi-agent operations
**Duration**: 4-6 hours
**Priority**: CRITICAL

### 4.1 Multi-Agent Orchestration Test

**Test File**: `tests/integration/test_e2e_multi_agent.py`

```python
"""
End-to-end tests for multi-agent operations
Tests complete operation flow from start to finish
"""

import pytest
import asyncio
from medusa.agents.orchestrator_agent import OrchestratorAgent


@pytest.mark.asyncio
@pytest.mark.slow
async def test_full_operation_recon_only():
    """
    Test complete reconnaissance-only operation
    This is the safest E2E test (no exploitation)
    """

    # Initialize orchestrator
    orchestrator = OrchestratorAgent(
        operation_id="E2E-TEST-RECON",
        config={
            "llm_provider": "mock",  # Use mock for testing
            "require_approval": False  # Auto-approve for testing
        }
    )

    # Start operation
    result = await orchestrator.start_operation(
        target="scanme.nmap.org",  # Legal test target
        operation_type="recon_only",
        objectives=["discover_services"]
    )

    # Verify operation completed
    assert result.status == "completed"
    assert result.operation_id == "E2E-TEST-RECON"

    # Verify agents were used
    assert len(result.agent_results) > 0
    assert any(r.agent_id.startswith("recon") for r in result.agent_results)

    # Verify cost tracking
    assert result.cost_summary is not None
    assert result.cost_summary.total_cost_usd > 0


@pytest.mark.asyncio
@pytest.mark.slow
async def test_full_operation_with_cost_limits():
    """Test operation respects cost limits"""

    orchestrator = OrchestratorAgent(
        operation_id="E2E-TEST-COST",
        config={
            "llm_provider": "mock",
            "max_cost_usd": 0.10  # Low limit for testing
        }
    )

    result = await orchestrator.start_operation(
        target="test.local",
        operation_type="full_assessment",
        objectives=["comprehensive_scan"]
    )

    # Verify cost limit was respected
    assert result.cost_summary.total_cost_usd <= 0.10


@pytest.mark.asyncio
@pytest.mark.slow
async def test_agent_coordination():
    """Test agents coordinate via message bus"""

    orchestrator = OrchestratorAgent(
        operation_id="E2E-TEST-COORD"
    )

    # Monitor message bus activity
    message_count = 0

    async def message_listener(topic, message):
        nonlocal message_count
        message_count += 1

    orchestrator.message_bus.subscribe("agent.*", message_listener)

    result = await orchestrator.start_operation(
        target="test.local",
        operation_type="recon_only",
        objectives=["quick_scan"]
    )

    # Verify agents communicated
    assert message_count > 0, "Agents should communicate via message bus"
```

**Run**:
```bash
# Run E2E tests (these take longer)
pytest tests/integration/test_e2e_multi_agent.py -v --slow
```

---

### 4.2 CLI Commands End-to-End Test

**Test File**: `tests/integration/test_cli_e2e.py`

```python
"""
End-to-end CLI command tests
Tests actual CLI invocation
"""

import pytest
from typer.testing import CliRunner
from medusa.cli import app

runner = CliRunner()


def test_cli_agent_run_help():
    """Test 'medusa agent run --help' works"""
    result = runner.invoke(app, ["agent", "run", "--help"])

    assert result.exit_code == 0
    assert "multi-agent" in result.output.lower()
    assert "--type" in result.output


@pytest.mark.slow
def test_cli_agent_run_dry_run():
    """Test 'medusa agent run' in dry-run mode"""
    result = runner.invoke(app, [
        "agent", "run",
        "test.local",
        "--type", "recon_only",
        "--dry-run"  # Don't actually execute
    ])

    # Should show what would be executed
    assert result.exit_code == 0
    assert "would execute" in result.output.lower()


def test_cli_agent_status():
    """Test 'medusa agent status' command"""
    result = runner.invoke(app, ["agent", "status"])

    # Should show status even if no operations
    assert result.exit_code == 0
```

**Run**:
```bash
pytest tests/integration/test_cli_e2e.py -v
```

---

## 📊 Level 5: Performance & Cost Validation

**Goal**: Validate performance and cost metrics
**Duration**: 2-4 hours
**Priority**: MEDIUM

### 5.1 Cost Optimization Validation

**Test File**: `tests/performance/test_cost_optimization.py`

```python
"""
Performance tests for cost optimization
Validates smart routing saves money
"""

import pytest
from medusa.core.llm.router import ModelRouter
from medusa.core.cost_tracker import OperationCostTracker


def test_smart_routing_reduces_cost():
    """Test that smart routing is cheaper than all-Sonnet"""

    # Simulate operation with smart routing
    tracker_smart = OperationCostTracker("SMART-001")
    router = ModelRouter(smart_model="sonnet", fast_model="haiku")

    # Typical operation tasks
    tasks = [
        ("orchestrator", "strategic_planning", True),   # Complex
        ("recon", "port_scan", False),                  # Simple
        ("recon", "service_detect", False),             # Simple
        ("vuln", "analyze_findings", False),            # Simple
        ("planning", "attack_chain", True),             # Complex
        ("reporting", "generate_report", True),         # Complex
    ]

    cost_smart = 0
    cost_all_sonnet = 0

    for agent, task_type, is_complex in tasks:
        # Smart routing
        model = router.select_model(task_type)
        if model == "haiku":
            cost = 0.005  # Haiku cost
        else:
            cost = 0.025  # Sonnet cost
        cost_smart += cost

        # All Sonnet
        cost_all_sonnet += 0.025

    # Smart routing should be significantly cheaper
    savings_percent = ((cost_all_sonnet - cost_smart) / cost_all_sonnet) * 100
    assert savings_percent > 40, f"Should save >40%, got {savings_percent}%"


@pytest.mark.asyncio
async def test_operation_stays_under_budget():
    """Test operation completes within expected budget"""
    from medusa.agents.orchestrator_agent import OrchestratorAgent

    orchestrator = OrchestratorAgent(
        operation_id="BUDGET-TEST",
        config={"max_cost_usd": 0.50}
    )

    result = await orchestrator.start_operation(
        target="test.local",
        operation_type="recon_only",
        objectives=["quick_scan"]
    )

    assert result.cost_summary.total_cost_usd < 0.50
    assert result.cost_summary.total_cost_usd < 0.25, "Should be well under budget"
```

**Run**:
```bash
pytest tests/performance/test_cost_optimization.py -v
```

---

### 5.2 Performance Benchmarks

**Test File**: `tests/performance/test_benchmarks.py`

```python
"""
Performance benchmarks
Measures operation duration and throughput
"""

import pytest
import time
import asyncio


@pytest.mark.asyncio
@pytest.mark.benchmark
async def test_operation_duration():
    """Test operation completes in reasonable time"""
    from medusa.agents.orchestrator_agent import OrchestratorAgent

    orchestrator = OrchestratorAgent(
        operation_id="PERF-TEST",
        config={"llm_provider": "mock"}  # Fast mock for benchmark
    )

    start = time.time()

    result = await orchestrator.start_operation(
        target="test.local",
        operation_type="recon_only",
        objectives=["quick_scan"]
    )

    duration = time.time() - start

    # Recon-only should complete in < 5 minutes with mock LLM
    assert duration < 300, f"Operation took {duration}s, expected < 300s"

    print(f"\n⏱️  Operation duration: {duration:.2f}s")


@pytest.mark.asyncio
@pytest.mark.benchmark
async def test_context_fusion_performance():
    """Test context fusion is fast enough"""
    from medusa.context.fusion_engine import ContextFusionEngine

    engine = ContextFusionEngine()

    start = time.time()

    context = engine.build_context_for_reconnaissance(
        target="test.example.com",
        current_findings=[]
    )

    duration = time.time() - start

    # Context building should be fast (< 2 seconds)
    assert duration < 2.0, f"Context fusion took {duration}s, expected < 2s"

    print(f"\n⏱️  Context fusion: {duration:.2f}s")
```

**Run**:
```bash
pytest tests/performance/test_benchmarks.py -v --benchmark
```

---

## 📋 Testing Checklist

### Phase 1: Environment Setup
- [ ] Virtual environment created
- [ ] All dependencies installed (`pip install -r requirements.txt`)
- [ ] ChromaDB installed successfully
- [ ] sentence-transformers installed
- [ ] boto3 installed
- [ ] All imports verified (run `verify_imports.py`)

### Phase 2: Data Population
- [ ] MITRE ATT&CK indexer run (`index_mitre_attack.py`)
- [ ] Tool docs indexer run (`index_tool_docs.py`)
- [ ] CVE indexer run (`index_cves.py`)
- [ ] Vector store stats verified (200+ MITRE techniques)

### Phase 3: Unit Tests
- [ ] Bedrock provider tests pass
- [ ] Model router tests pass
- [ ] Cost tracker tests pass
- [ ] Vector store tests pass
- [ ] All unit tests pass (`pytest tests/unit/ -v`)

### Phase 4: Integration Tests
- [ ] Indexer integration tests pass
- [ ] Context fusion tests pass
- [ ] Individual agent tests pass
- [ ] All integration tests pass (`pytest tests/integration/ -v`)

### Phase 5: End-to-End Tests
- [ ] Multi-agent orchestration test passes
- [ ] CLI commands work
- [ ] Cost limits respected
- [ ] Agent coordination verified
- [ ] E2E tests pass (`pytest tests/integration/test_e2e*.py -v --slow`)

### Phase 6: Performance Validation
- [ ] Cost optimization verified (>40% savings)
- [ ] Operation duration acceptable (< 10 min)
- [ ] Context fusion performance good (< 2s)
- [ ] Performance tests pass (`pytest tests/performance/ -v`)

---

## 🚀 Quick Start Testing Guide

### Minimal Viable Testing (2-3 hours)

If you have limited time, run these essential tests:

```bash
# 1. Install dependencies (30 min)
pip install -r requirements.txt

# 2. Verify imports (5 min)
python tests/verify_imports.py

# 3. Run indexers (15 min)
python scripts/index_mitre_attack.py
python scripts/index_tool_docs.py
python scripts/index_cves.py

# 4. Run existing test suite (60-90 min)
pytest tests/integration/test_multi_agent_integration.py -v
pytest tests/integration/test_cli_multi_agent.py -v

# 5. Manual CLI test (10 min)
medusa agent run --help
medusa agent status --help
medusa agent report --help
```

**Success Criteria**: All steps complete without errors ✅

---

### Comprehensive Testing (16-24 hours)

For full validation:

```bash
# Day 1: Setup + Unit Tests (6-8 hours)
pip install -r requirements.txt
python tests/verify_imports.py
pytest tests/unit/ -v --cov=medusa

# Day 2: Integration Tests (6-8 hours)
python scripts/index_mitre_attack.py
python scripts/index_tool_docs.py
python scripts/index_cves.py
pytest tests/integration/ -v

# Day 3: E2E + Performance (4-6 hours)
pytest tests/integration/test_e2e*.py -v --slow
pytest tests/performance/ -v --benchmark
```

---

## 📈 Success Metrics

### Test Coverage Goals

| Component | Target Coverage | Priority |
|-----------|----------------|----------|
| Bedrock Provider | 90% | HIGH |
| Model Router | 100% | HIGH |
| Cost Tracker | 90% | HIGH |
| Vector Store | 80% | MEDIUM |
| Context Fusion | 80% | MEDIUM |
| Agents | 70% | MEDIUM |
| CLI Commands | 60% | MEDIUM |

### Performance Targets

| Metric | Target | Acceptable |
|--------|--------|------------|
| Full Operation (recon-only) | < 5 min | < 10 min |
| Context Fusion | < 1s | < 2s |
| Vector Search | < 500ms | < 1s |
| Cost per Operation | < $0.22 | < $0.50 |
| Smart Routing Savings | > 60% | > 40% |

---

## 🐛 Troubleshooting Guide

### Common Issues

#### ChromaDB Installation Fails

```bash
# Linux
sudo apt-get install libsqlite3-dev
pip install chromadb

# macOS
brew install sqlite
pip install chromadb
```

#### PyTorch Download Too Large

```bash
# Install CPU-only version (smaller)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
```

#### Import Errors After Installation

```bash
# Ensure you're in the right directory
cd medusa-cli

# Add src to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Or in Python
import sys
sys.path.insert(0, 'src')
```

#### AWS Bedrock Credentials Not Found

```bash
# Configure AWS credentials
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-west-2
```

#### Tests Fail with "No module named 'medusa'"

```bash
# Install package in development mode
cd medusa-cli
pip install -e .
```

---

## 📝 Test Results Documentation

### Recording Test Results

Create `TEST-RESULTS.md` to track progress:

```markdown
# Test Results

**Date**: 2025-11-14
**Tester**: [Your Name]

## Environment
- Python: 3.11.x
- OS: macOS/Linux/Windows
- Dependencies: Installed ✅

## Unit Tests
- test_bedrock_provider.py: ✅ PASS (5/5 tests)
- test_model_router.py: ✅ PASS (4/4 tests)
- test_cost_tracker.py: ✅ PASS (4/4 tests)
- test_vector_store.py: ⚠️ PARTIAL (3/4 tests)

## Integration Tests
- test_indexers.py: ✅ PASS (3/3 tests)
- test_context_fusion.py: ✅ PASS (2/2 tests)
- test_agents_integration.py: ✅ PASS (2/2 tests)

## E2E Tests
- test_e2e_multi_agent.py: ✅ PASS (3/3 tests)
- test_cli_e2e.py: ✅ PASS (3/3 tests)

## Performance
- Cost optimization: ✅ 67% savings
- Operation duration: ✅ 4.5 minutes
- Context fusion: ✅ 0.8 seconds

## Overall Status
✅ READY FOR PRODUCTION
```

---

## 🎯 Final Recommendation

### Testing Priority Order

1. **Critical Path** (Must Complete):
   - Install dependencies
   - Verify imports
   - Run indexers
   - Run existing test suite

2. **High Priority** (Should Complete):
   - Unit tests for Bedrock, Router, Cost Tracker
   - Integration tests for context fusion
   - One E2E test

3. **Nice to Have** (Time Permitting):
   - Full E2E suite
   - Performance benchmarks
   - Edge case testing

### Timeline

- **Minimum**: 2-3 hours (Critical Path only)
- **Recommended**: 8-12 hours (Critical + High Priority)
- **Comprehensive**: 16-24 hours (Everything)

---

**Last Updated**: 2025-11-14
**Status**: Testing Plan Complete
**Next Action**: Begin with Phase 1 (Environment Setup)

---

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → Testing Plan
