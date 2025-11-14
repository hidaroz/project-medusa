"""
Unit tests for OperationCostTracker
Tests cost recording, aggregation, and reporting
"""

import pytest
from datetime import datetime
import json
import sys
from pathlib import Path
from unittest.mock import Mock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from medusa.core.cost_tracker import OperationCostTracker, CostEntry


def create_mock_llm_response(model="sonnet", input_tokens=1000, output_tokens=500, cost_usd=0.025, latency_ms=1200):
    """Create a mock LLMResponse object"""
    mock_response = Mock()
    mock_response.model = model
    mock_response.latency_ms = latency_ms
    mock_response.metadata = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_usd": cost_usd
    }
    return mock_response


def test_cost_tracker_initialization():
    """Test CostTracker initializes correctly"""
    tracker = OperationCostTracker(operation_id="TEST-001")
    assert tracker.operation_id == "TEST-001"
    assert len(tracker.entries) == 0
    assert tracker.start_time is not None
    assert tracker.end_time is None


def test_cost_entry_creation():
    """Test CostEntry dataclass works correctly"""
    entry = CostEntry(
        timestamp=datetime.now(),
        agent="orchestrator",
        task_type="planning",
        model="sonnet",
        input_tokens=1000,
        output_tokens=500,
        cost_usd=0.025,
        latency_ms=1200
    )

    assert entry.agent == "orchestrator"
    assert entry.task_type == "planning"
    assert entry.model == "sonnet"
    assert entry.input_tokens == 1000
    assert entry.output_tokens == 500
    assert entry.cost_usd == 0.025
    assert entry.latency_ms == 1200


def test_cost_tracker_record_entry():
    """Test recording cost entries"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    response = create_mock_llm_response(
        model="sonnet",
        input_tokens=1000,
        output_tokens=500,
        cost_usd=0.025,
        latency_ms=1200
    )

    tracker.record(
        agent="orchestrator",
        task_type="planning",
        response=response
    )

    assert len(tracker.entries) == 1
    entry = tracker.entries[0]
    assert entry.agent == "orchestrator"
    assert entry.task_type == "planning"
    assert entry.cost_usd == 0.025


def test_cost_tracker_multiple_entries():
    """Test recording multiple entries"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    # Record multiple entries
    tracker.record("orchestrator", "planning", create_mock_llm_response("sonnet", 1000, 500, 0.025, 1000))
    tracker.record("recon", "scanning", create_mock_llm_response("haiku", 500, 200, 0.005, 500))
    tracker.record("vuln", "analysis", create_mock_llm_response("haiku", 800, 300, 0.008, 700))

    assert len(tracker.entries) == 3


def test_cost_tracker_summary_total_cost():
    """Test cost summary calculates total correctly"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("orchestrator", "planning", create_mock_llm_response("sonnet", 1000, 500, 0.025, 1000))
    tracker.record("recon", "scanning", create_mock_llm_response("haiku", 500, 200, 0.005, 500))
    tracker.record("reporting", "generate", create_mock_llm_response("sonnet", 2000, 1000, 0.050, 2000))

    tracker.finalize()
    summary = tracker.get_summary()

    # Total cost should be sum of all entries
    assert summary["total_cost_usd"] == 0.080  # 0.025 + 0.005 + 0.050


def test_cost_tracker_summary_tokens():
    """Test cost summary calculates token totals correctly"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("orchestrator", "planning", create_mock_llm_response("sonnet", 1000, 500, 0.025, 1000))
    tracker.record("recon", "scanning", create_mock_llm_response("haiku", 500, 200, 0.005, 500))
    tracker.record("reporting", "generate", create_mock_llm_response("sonnet", 2000, 1000, 0.050, 2000))

    tracker.finalize()
    summary = tracker.get_summary()

    # Check token totals
    assert summary["input_tokens"] == 3500  # 1000 + 500 + 2000
    assert summary["output_tokens"] == 1700  # 500 + 200 + 1000
    assert summary["total_tokens"] == 5200  # 3500 + 1700


def test_cost_tracker_agent_breakdown():
    """Test cost summary includes per-agent breakdown"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("orchestrator", "planning", create_mock_llm_response("sonnet", 1000, 500, 0.025, 1000))
    tracker.record("recon", "scanning", create_mock_llm_response("haiku", 500, 200, 0.005, 500))
    tracker.record("recon", "probe", create_mock_llm_response("haiku", 600, 250, 0.006, 600))
    tracker.record("reporting", "generate", create_mock_llm_response("sonnet", 2000, 1000, 0.050, 2000))

    tracker.finalize()
    summary = tracker.get_summary()

    # Check agent breakdown exists
    assert "agent_breakdown" in summary
    assert "orchestrator" in summary["agent_breakdown"]
    assert "recon" in summary["agent_breakdown"]
    assert "reporting" in summary["agent_breakdown"]

    # Recon should have cost from 2 tasks
    recon_cost = summary["agent_breakdown"]["recon"]
    assert recon_cost == 0.011  # 0.005 + 0.006


def test_cost_tracker_model_breakdown():
    """Test cost summary includes per-model breakdown"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("orchestrator", "planning", create_mock_llm_response("sonnet", 1000, 500, 0.025, 1000))
    tracker.record("recon", "scanning", create_mock_llm_response("haiku", 500, 200, 0.005, 500))
    tracker.record("reporting", "generate", create_mock_llm_response("sonnet", 2000, 1000, 0.050, 2000))

    tracker.finalize()
    summary = tracker.get_summary()

    # Check model breakdown exists
    assert "model_breakdown" in summary
    assert "sonnet" in summary["model_breakdown"]
    assert "haiku" in summary["model_breakdown"]

    # Sonnet should have 2 calls
    sonnet_breakdown = summary["model_breakdown"]["sonnet"]
    assert sonnet_breakdown["calls"] == 2
    assert sonnet_breakdown["cost"] == 0.075  # 0.025 + 0.050


def test_cost_tracker_duration_calculation():
    """Test tracker calculates operation duration"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("recon", "scan", create_mock_llm_response("haiku", 500, 200, 0.005, 500))

    tracker.finalize()
    summary = tracker.get_summary()

    # Duration should be > 0
    assert "duration_seconds" in summary
    assert summary["duration_seconds"] >= 0


def test_cost_tracker_cost_per_minute():
    """Test tracker calculates cost per minute"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("recon", "scan", create_mock_llm_response("haiku", 500, 200, 0.060, 500))

    tracker.finalize()
    summary = tracker.get_summary()

    # Should have cost per minute calculation
    assert "cost_per_minute" in summary
    assert isinstance(summary["cost_per_minute"], (int, float))


def test_cost_tracker_export_detailed_entries():
    """Test get_detailed_entries returns list of dicts"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("recon", "scanning", create_mock_llm_response("haiku", 500, 200, 0.005, 500))
    tracker.finalize()

    entries = tracker.get_detailed_entries()

    # Verify it's a list of dicts
    assert isinstance(entries, list)
    assert len(entries) == 1
    assert isinstance(entries[0], dict)
    assert "agent" in entries[0]
    assert "task_type" in entries[0]
    assert "cost_usd" in entries[0]


def test_cost_tracker_empty_summary():
    """Test tracker handles empty state correctly"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    # No entries recorded
    tracker.finalize()
    summary = tracker.get_summary()

    assert summary["total_cost_usd"] == 0.0
    assert summary["input_tokens"] == 0
    assert summary["output_tokens"] == 0
    assert summary["total_calls"] == 0


def test_cost_tracker_average_latency():
    """Test tracker calculates average latency correctly"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("recon", "scan1", create_mock_llm_response("haiku", 500, 200, 0.005, 1000))
    tracker.record("recon", "scan2", create_mock_llm_response("haiku", 500, 200, 0.005, 2000))
    tracker.record("recon", "scan3", create_mock_llm_response("haiku", 500, 200, 0.005, 1500))

    tracker.finalize()
    summary = tracker.get_summary()

    # Average latency should be (1000 + 2000 + 1500) / 3 = 1500ms
    assert "average_latency_ms" in summary
    assert summary["average_latency_ms"] == 1500.0


def test_cost_tracker_total_calls():
    """Test tracker counts total calls correctly"""
    tracker = OperationCostTracker(operation_id="TEST-001")

    tracker.record("orchestrator", "planning", create_mock_llm_response("sonnet", 1000, 500, 0.025, 1000))
    tracker.record("recon", "scan", create_mock_llm_response("haiku", 500, 200, 0.005, 500))
    tracker.record("recon", "probe", create_mock_llm_response("haiku", 500, 200, 0.005, 500))

    tracker.finalize()
    summary = tracker.get_summary()

    assert summary["total_calls"] == 3


def test_cost_entry_to_dict():
    """Test CostEntry converts to dictionary correctly"""
    entry = CostEntry(
        timestamp=datetime(2025, 11, 14, 10, 30, 0),
        agent="test_agent",
        task_type="test_task",
        model="test_model",
        input_tokens=100,
        output_tokens=50,
        cost_usd=0.01,
        latency_ms=500,
        metadata={"key": "value"}
    )

    entry_dict = entry.to_dict()

    assert entry_dict["agent"] == "test_agent"
    assert entry_dict["task_type"] == "test_task"
    assert entry_dict["model"] == "test_model"
    assert entry_dict["input_tokens"] == 100
    assert entry_dict["output_tokens"] == 50
    assert entry_dict["cost_usd"] == 0.01
    assert entry_dict["latency_ms"] == 500
    assert entry_dict["metadata"] == {"key": "value"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])