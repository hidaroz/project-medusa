"""
Operation-level cost tracking and reporting
Tracks LLM usage, tokens, and costs per operation
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import json
from pathlib import Path


@dataclass
class CostEntry:
    """Single cost entry for an LLM call"""
    timestamp: datetime
    agent: str
    task_type: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert cost entry to dictionary"""
        return {
            "timestamp": self.timestamp.isoformat(),
            "agent": self.agent,
            "task_type": self.task_type,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": self.cost_usd,
            "latency_ms": self.latency_ms,
            "metadata": self.metadata
        }


class OperationCostTracker:
    """Track costs for entire operation"""

    def __init__(self, operation_id: str):
        self.operation_id = operation_id
        self.entries: List[CostEntry] = []
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None

    def record(
        self,
        agent: str,
        task_type: str,
        response: 'LLMResponse'
    ):
        """
        Record a cost entry from an LLM response

        Args:
            agent: Name of the agent making the request
            task_type: Type of task (e.g., "parse_nmap", "plan_attack")
            response: LLMResponse object from the LLM call
        """
        entry = CostEntry(
            timestamp=datetime.now(),
            agent=agent,
            task_type=task_type,
            model=response.model,
            input_tokens=response.metadata.get("input_tokens", 0),
            output_tokens=response.metadata.get("output_tokens", 0),
            cost_usd=response.metadata.get("cost_usd", 0.0),
            latency_ms=response.latency_ms,
            metadata=response.metadata
        )
        self.entries.append(entry)

    def finalize(self):
        """Mark operation as complete"""
        self.end_time = datetime.now()

    def get_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive cost summary

        Returns:
            Dict containing:
            - Total cost, tokens, and calls
            - Breakdown by agent
            - Breakdown by model
            - Average latency
            - Duration
        """
        total_cost = sum(e.cost_usd for e in self.entries)
        total_tokens = sum(e.input_tokens + e.output_tokens for e in self.entries)
        total_input = sum(e.input_tokens for e in self.entries)
        total_output = sum(e.output_tokens for e in self.entries)

        # Cost by agent
        agent_costs: Dict[str, float] = {}
        for entry in self.entries:
            if entry.agent not in agent_costs:
                agent_costs[entry.agent] = 0.0
            agent_costs[entry.agent] += entry.cost_usd

        # Cost by model
        model_costs: Dict[str, Dict[str, Any]] = {}
        for entry in self.entries:
            if entry.model not in model_costs:
                model_costs[entry.model] = {"calls": 0, "cost": 0.0, "tokens": 0}
            model_costs[entry.model]["calls"] += 1
            model_costs[entry.model]["cost"] += entry.cost_usd
            model_costs[entry.model]["tokens"] += entry.input_tokens + entry.output_tokens

        # Calculate duration
        if self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        else:
            duration = (datetime.now() - self.start_time).total_seconds()

        # Average latency
        avg_latency = sum(e.latency_ms for e in self.entries) / len(self.entries) if self.entries else 0

        return {
            "operation_id": self.operation_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": duration,
            "total_cost_usd": total_cost,
            "total_tokens": total_tokens,
            "input_tokens": total_input,
            "output_tokens": total_output,
            "total_calls": len(self.entries),
            "agent_breakdown": agent_costs,
            "model_breakdown": model_costs,
            "average_latency_ms": avg_latency,
            "cost_per_minute": (total_cost / duration * 60) if duration > 0 else 0
        }

    def get_detailed_entries(self) -> List[Dict[str, Any]]:
        """
        Get all cost entries as dictionaries

        Returns:
            List of cost entry dictionaries
        """
        return [entry.to_dict() for entry in self.entries]

    def export_json(self, filepath: str):
        """
        Export cost data to JSON file

        Args:
            filepath: Path to save the JSON file
        """
        data = {
            "summary": self.get_summary(),
            "entries": self.get_detailed_entries()
        }

        filepath_obj = Path(filepath)
        filepath_obj.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def print_summary(self):
        """Print a formatted summary to console"""
        summary = self.get_summary()

        print("\n" + "="*70)
        print(f"Operation Cost Summary: {self.operation_id}")
        print("="*70)
        print(f"Duration: {summary['duration_seconds']:.1f} seconds")
        print(f"Total Cost: ${summary['total_cost_usd']:.4f}")
        print(f"Total Tokens: {summary['total_tokens']:,} ({summary['input_tokens']:,} input + {summary['output_tokens']:,} output)")
        print(f"Total Calls: {summary['total_calls']}")
        print(f"Average Latency: {summary['average_latency_ms']:.0f}ms")
        print(f"Cost per Minute: ${summary['cost_per_minute']:.4f}/min")

        if summary['agent_breakdown']:
            print("\n" + "-"*70)
            print("Cost by Agent:")
            print("-"*70)
            for agent, cost in sorted(summary['agent_breakdown'].items(), key=lambda x: x[1], reverse=True):
                percentage = (cost / summary['total_cost_usd'] * 100) if summary['total_cost_usd'] > 0 else 0
                print(f"  {agent:30s} ${cost:8.4f}  ({percentage:5.1f}%)")

        if summary['model_breakdown']:
            print("\n" + "-"*70)
            print("Cost by Model:")
            print("-"*70)
            for model, stats in sorted(summary['model_breakdown'].items(), key=lambda x: x[1]['cost'], reverse=True):
                percentage = (stats['cost'] / summary['total_cost_usd'] * 100) if summary['total_cost_usd'] > 0 else 0
                print(f"  {model:50s}")
                print(f"    Calls: {stats['calls']}, Cost: ${stats['cost']:.4f} ({percentage:.1f}%), Tokens: {stats['tokens']:,}")

        print("="*70 + "\n")

    def get_cost_by_task_type(self) -> Dict[str, Dict[str, Any]]:
        """
        Get cost breakdown by task type

        Returns:
            Dict mapping task_type to cost statistics
        """
        task_costs: Dict[str, Dict[str, Any]] = {}

        for entry in self.entries:
            if entry.task_type not in task_costs:
                task_costs[entry.task_type] = {
                    "calls": 0,
                    "cost": 0.0,
                    "tokens": 0,
                    "avg_latency_ms": 0.0,
                    "latencies": []
                }

            task_costs[entry.task_type]["calls"] += 1
            task_costs[entry.task_type]["cost"] += entry.cost_usd
            task_costs[entry.task_type]["tokens"] += entry.input_tokens + entry.output_tokens
            task_costs[entry.task_type]["latencies"].append(entry.latency_ms)

        # Calculate average latencies
        for task_type, stats in task_costs.items():
            stats["avg_latency_ms"] = sum(stats["latencies"]) / len(stats["latencies"])
            del stats["latencies"]  # Remove raw latencies from output

        return task_costs
