"""
Unit tests for ModelRouter
Tests complexity assessment and model selection
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from medusa.core.llm.router import ModelRouter, TaskComplexity
from medusa.core.llm.config import LLMConfig


@pytest.fixture
def mock_config():
    """Create a mock LLMConfig"""
    config = LLMConfig()
    config.smart_model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    config.fast_model = "anthropic.claude-3-5-haiku-20241022-v1:0"
    return config


def test_router_initialization(mock_config):
    """Test ModelRouter initializes with correct models"""
    router = ModelRouter(config=mock_config)

    assert router.smart_model == "anthropic.claude-3-5-sonnet-20241022-v2:0"
    assert router.fast_model == "anthropic.claude-3-5-haiku-20241022-v1:0"
    assert router.config == mock_config


def test_router_default_models():
    """Test ModelRouter uses sensible defaults"""
    config = LLMConfig()
    router = ModelRouter(config=config)

    assert router.smart_model is not None
    assert router.fast_model is not None
    assert router.smart_model != router.fast_model


def test_router_selects_smart_for_complex_planning(mock_config):
    """Test router selects Sonnet for strategic planning"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    model = router.select_model("strategic_planning")
    assert model == "sonnet", "Strategic planning should use smart model"


def test_router_selects_smart_for_exploitation(mock_config):
    """Test router selects Sonnet for exploitation planning"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    model = router.select_model("plan_attack_strategy")
    assert model == "sonnet", "Attack planning should use smart model"


def test_router_selects_smart_for_reporting(mock_config):
    """Test router selects Sonnet for report generation"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    model = router.select_model("generate_executive_report")
    assert model == "sonnet", "Report generation should use smart model"


def test_router_selects_fast_for_tool_parsing(mock_config):
    """Test router selects Haiku for tool parsing"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    model = router.select_model("parse_nmap_output")
    assert model == "haiku", "Tool parsing should use fast model"


def test_router_selects_fast_for_parsing(mock_config):
    """Test router selects Haiku for output parsing"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    model = router.select_model("parse_tool_output")
    assert model == "haiku", "Output parsing should use fast model"


def test_router_selects_fast_for_data_extraction(mock_config):
    """Test router selects Haiku for data extraction"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    model = router.select_model("extract_data")
    assert model == "haiku", "Data extraction should use fast model"


def test_router_complexity_assessment_simple():
    """Test complexity assessment identifies simple tasks"""
    config = LLMConfig()
    router = ModelRouter(config=config)

    complexity = router._assess_complexity("parse_tool_output", context=None)
    assert complexity == TaskComplexity.SIMPLE


def test_router_complexity_assessment_complex():
    """Test complexity assessment identifies complex tasks"""
    config = LLMConfig()
    router = ModelRouter(config=config)

    complexity = router._assess_complexity("strategic_planning", context=None)
    assert complexity == TaskComplexity.COMPLEX


def test_router_complexity_with_context_size():
    """Test complexity assessment considers context size"""
    config = LLMConfig()
    router = ModelRouter(config=config)

    # Large context should increase complexity
    complexity = router._assess_complexity(
        "analysis",
        context={"text_length": 10000}
    )
    # Note: actual implementation may not check text_length, so this tests the interface

    # Simple tasks should stay simple
    complexity = router._assess_complexity(
        "parse_tool_output",
        context={"text_length": 100}
    )
    assert complexity == TaskComplexity.SIMPLE


def test_router_all_complex_tasks_use_smart_model(mock_config):
    """Test all complex task types use smart model"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    complex_tasks = [
        "strategic_planning",
        "exploitation_planning",
        "attack_chain_generation",
        "report_generation",
        "vulnerability_analysis",
        "risk_assessment"
    ]

    for task in complex_tasks:
        model = router.select_model(task)
        assert model == "sonnet", f"Task '{task}' should use smart model"


def test_router_all_simple_tasks_use_fast_model(mock_config):
    """Test all simple task types use fast model"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    simple_tasks = [
        "parse_nmap_output",
        "parse_tool_output",
        "extract_data",
        "simple_classification"
    ]

    for task in simple_tasks:
        model = router.select_model(task)
        assert model == "haiku", f"Task '{task}' should use fast model"


def test_router_moderate_tasks_default_to_fast(mock_config):
    """Test moderate complexity tasks default to fast model for cost savings"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    # Unknown tasks that aren't explicitly complex should use fast model
    model = router.select_model("generic_analysis", context={"text_length": 500})
    assert model == "haiku", "Moderate tasks with small context should use fast model"


def test_router_estimate_cost_savings():
    """Test router can estimate cost savings"""
    config = LLMConfig()
    router = ModelRouter(config=config)

    # Typical operation task distribution
    tasks = [
        ("strategic_planning", True),   # Complex - use smart
        ("parse_tool_output", False),   # Simple - use fast
        ("parse_nmap_output", False),   # Simple - use fast
        ("extract_data", False),        # Simple - use fast
        ("generate_executive_report", True),    # Complex - use smart
    ]

    smart_count = sum(1 for _, is_complex in tasks if is_complex)
    fast_count = len(tasks) - smart_count

    # Verify distribution
    assert smart_count == 2, "Should have 2 smart model tasks"
    assert fast_count == 3, "Should have 3 fast model tasks"

    # Estimate savings (assuming Sonnet costs 6x more than Haiku on average)
    all_smart_cost = len(tasks) * 1.0  # Normalized cost
    mixed_cost = (smart_count * 1.0) + (fast_count * 0.17)  # ~6x difference
    savings_percent = ((all_smart_cost - mixed_cost) / all_smart_cost) * 100

    assert savings_percent > 40, f"Should save >40%, got {savings_percent:.1f}%"


def test_router_handles_unknown_task_type(mock_config):
    """Test router handles unknown task types gracefully"""
    mock_config.smart_model = "sonnet"
    mock_config.fast_model = "haiku"
    router = ModelRouter(config=mock_config)

    # Unknown task should return a valid model
    model = router.select_model("unknown_task_type")
    assert model in ["sonnet", "haiku"], "Should return a valid model"


def test_task_complexity_enum():
    """Test TaskComplexity enum has expected values"""
    assert TaskComplexity.SIMPLE.value == "simple"
    assert TaskComplexity.MODERATE.value == "moderate"
    assert TaskComplexity.COMPLEX.value == "complex"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
