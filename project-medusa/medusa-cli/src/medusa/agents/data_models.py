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


class AgentCapability(str, Enum):
    """Agent capability types."""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    PLANNING = "planning"
    REPORTING = "reporting"
    ORCHESTRATION = "orchestration"


class AgentStatus(str, Enum):
    """Agent execution status."""
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"


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
    parent_task_id: Optional[str] = None


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
    agent_name: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    cost_usd: float = 0.0
    tokens_used: int = 0
    duration_seconds: float = 0.0
    context_used: Optional[Dict[str, Any]] = None
    llm_response: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "data": self.data,
            "error": self.error,
            "cost_usd": self.cost_usd,
            "duration_seconds": self.duration_seconds,
            "context_used": self.context_used,
            "findings": self.findings,
            "recommendations": self.recommendations
        }


@dataclass
class AgentMessage:
    """
    Message for inter-agent communication.

    Attributes:
        sender: Name of sending agent
        recipient: Name of recipient agent (or "broadcast")
        message_type: Type of message (request, response, notification, error)
        content: Message payload
        timestamp: Message timestamp
        correlation_id: Optional ID for request-response correlation
    """
    sender: str
    recipient: str
    message_type: str
    content: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None
