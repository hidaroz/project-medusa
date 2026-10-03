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

    print("🧪 Testing MEDUSA Multi-Agent System Imports...")
    print("=" * 60)

    passed = 0
    failed = 0
    errors = []

    # Core LLM
    print("\n📦 Core LLM Components:")
    try:
        from medusa.core.llm.providers.bedrock import BedrockProvider
        print("  ✅ BedrockProvider imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ BedrockProvider failed: {e}")
        errors.append(("BedrockProvider", str(e)))
        failed += 1

    try:
        from medusa.core.llm.router import ModelRouter
        print("  ✅ ModelRouter imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ ModelRouter failed: {e}")
        errors.append(("ModelRouter", str(e)))
        failed += 1

    try:
        from medusa.core.cost_tracker import OperationCostTracker
        print("  ✅ OperationCostTracker imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ OperationCostTracker failed: {e}")
        errors.append(("OperationCostTracker", str(e)))
        failed += 1

    # Context
    print("\n📦 Context Engineering Components:")
    try:
        from medusa.context.vector_store import VectorStore
        print("  ✅ VectorStore imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ VectorStore failed: {e}")
        errors.append(("VectorStore", str(e)))
        failed += 1

    try:
        from medusa.context.fusion_engine import ContextFusionEngine
        print("  ✅ ContextFusionEngine imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ ContextFusionEngine failed: {e}")
        errors.append(("ContextFusionEngine", str(e)))
        failed += 1

    # Agents
    print("\n📦 Agent Components:")
    try:
        from medusa.agents.orchestrator_agent import OrchestratorAgent
        print("  ✅ OrchestratorAgent imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ OrchestratorAgent failed: {e}")
        errors.append(("OrchestratorAgent", str(e)))
        failed += 1

    try:
        from medusa.agents.reconnaissance_agent import ReconnaissanceAgent
        print("  ✅ ReconnaissanceAgent imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ ReconnaissanceAgent failed: {e}")
        errors.append(("ReconnaissanceAgent", str(e)))
        failed += 1

    try:
        from medusa.agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent
        print("  ✅ VulnerabilityAnalysisAgent imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ VulnerabilityAnalysisAgent failed: {e}")
        errors.append(("VulnerabilityAnalysisAgent", str(e)))
        failed += 1

    try:
        from medusa.agents.exploitation_agent import ExploitationAgent
        print("  ✅ ExploitationAgent imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ ExploitationAgent failed: {e}")
        errors.append(("ExploitationAgent", str(e)))
        failed += 1

    try:
        from medusa.agents.planning_agent import PlanningAgent
        print("  ✅ PlanningAgent imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ PlanningAgent failed: {e}")
        errors.append(("PlanningAgent", str(e)))
        failed += 1

    try:
        from medusa.agents.reporting_agent import ReportingAgent
        print("  ✅ ReportingAgent imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ ReportingAgent failed: {e}")
        errors.append(("ReportingAgent", str(e)))
        failed += 1

    try:
        from medusa.agents.message_bus import MessageBus
        print("  ✅ MessageBus imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ MessageBus failed: {e}")
        errors.append(("MessageBus", str(e)))
        failed += 1

    # CLI
    print("\n📦 CLI Components:")
    try:
        from medusa.cli_multi_agent import agent_app
        print("  ✅ CLI multi-agent commands imported")
        passed += 1
    except Exception as e:
        print(f"  ❌ CLI multi-agent failed: {e}")
        errors.append(("CLI multi-agent", str(e)))
        failed += 1

    # Summary
    print("\n" + "=" * 60)
    print(f"📊 Import Test Results:")
    print(f"  ✅ Passed: {passed}")
    print(f"  ❌ Failed: {failed}")
    print(f"  📈 Success Rate: {(passed/(passed+failed)*100):.1f}%")

    if failed > 0:
        print("\n⚠️  Failed Imports:")
        for component, error in errors:
            print(f"  - {component}: {error}")
        return False
    else:
        print("\n🎉 All imports successful!")
        return True

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)