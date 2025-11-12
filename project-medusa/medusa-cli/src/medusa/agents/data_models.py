"""
Data models for multi-agent system
Defines communication protocols and task structures
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum


class AgentStatus(Enum):
    """Agent execution status"""
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AgentMessage:
    """
    Message for inter-agent communication

    Used by agents to communicate findings, requests, and status updates
    """
    sender: str  # Agent name
    recipient: str  # Target agent name or "broadcast"
    message_type: str  # "request", "response", "notification", "error"
    content: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None  # For request-response correlation

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "message_type": self.message_type,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id
        }


@dataclass
class AgentTask:
    """
    Task assigned to an agent

    Contains all information needed for an agent to execute a task
    """
    task_id: str
    task_type: str  # "reconnaissance", "vulnerability_analysis", "planning", etc.
    description: str
    parameters: Dict[str, Any]
    priority: TaskPriority = TaskPriority.MEDIUM
    assigned_to: Optional[str] = None  # Agent name
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: AgentStatus = AgentStatus.IDLE
    parent_task_id: Optional[str] = None  # For subtasks
    dependencies: List[str] = field(default_factory=list)  # Task IDs that must complete first

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "description": self.description,
            "parameters": self.parameters,
            "priority": self.priority.value,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status.value,
            "parent_task_id": self.parent_task_id,
            "dependencies": self.dependencies
        }

    def duration_seconds(self) -> float:
        """Calculate task duration"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0


@dataclass
class AgentResult:
    """
    Result of agent task execution

    Contains findings, recommendations, and execution metadata
    """
    task_id: str
    agent_name: str
    status: AgentStatus
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time_seconds: float = 0.0
    tokens_used: int = 0
    cost_usd: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "status": self.status.value,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "metadata": self.metadata,
            "error": self.error,
            "execution_time_seconds": self.execution_time_seconds,
            "tokens_used": self.tokens_used,
            "cost_usd": self.cost_usd,
            "timestamp": self.timestamp.isoformat()
        }

    def success(self) -> bool:
        """Check if task was successful"""
        return self.status == AgentStatus.COMPLETED and self.error is None


@dataclass
class AgentMetrics:
    """
    Metrics for agent performance tracking
    """
    agent_name: str
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_execution_time: float = 0.0
    total_tokens_used: int = 0
    total_cost_usd: float = 0.0
    average_task_time: float = 0.0
    success_rate: float = 0.0

    def update(self, result: AgentResult):
        """Update metrics with new result"""
        if result.status == AgentStatus.COMPLETED:
            self.tasks_completed += 1
        elif result.status == AgentStatus.FAILED:
            self.tasks_failed += 1

        self.total_execution_time += result.execution_time_seconds
        self.total_tokens_used += result.tokens_used
        self.total_cost_usd += result.cost_usd

        # Recalculate averages
        total_tasks = self.tasks_completed + self.tasks_failed
        if total_tasks > 0:
            self.average_task_time = self.total_execution_time / total_tasks
            self.success_rate = self.tasks_completed / total_tasks

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "agent_name": self.agent_name,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "total_execution_time": self.total_execution_time,
            "total_tokens_used": self.total_tokens_used,
            "total_cost_usd": self.total_cost_usd,
            "average_task_time": self.average_task_time,
            "success_rate": self.success_rate
        }
