"""
Data models for AI agents.
"""

from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime


class TaskPriority(str, Enum):
    """Task priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(str, Enum):
    """Task execution status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AgentTask:
    """
    Represents a task for an AI agent.

    Attributes:
        task_id: Unique task identifier
        task_type: Type of task (e.g., 'recommend_recon_strategy')
        description: Human-readable task description
        parameters: Task-specific parameters
        priority: Task priority level
        status: Current task status
        created_at: Task creation timestamp
        context: Additional context for task execution
    """
    task_id: str
    task_type: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    context: Optional[Dict[str, Any]] = None


@dataclass
class AgentResult:
    """
    Represents the result of an agent task execution.

    Attributes:
        task_id: Associated task ID
        status: Execution status
        data: Result data
        error: Error message if failed
        cost_usd: Cost in USD for LLM calls
        duration_seconds: Execution duration
        context_used: Context provided to LLM
        llm_response: Raw LLM response
    """
    task_id: str
    status: TaskStatus
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    cost_usd: float = 0.0
    duration_seconds: float = 0.0
    context_used: Optional[Dict[str, Any]] = None
    llm_response: Optional[str] = None
