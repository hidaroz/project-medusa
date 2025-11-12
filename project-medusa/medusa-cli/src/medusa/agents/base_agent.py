"""
Base Agent Class
Abstract base for all specialized agents in the multi-agent system
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum
import logging
import time
from datetime import datetime

from medusa.core.llm.client import LLMClient
from medusa.context.fusion_engine import ContextFusionEngine
from .data_models import (
    AgentTask,
    AgentResult,
    AgentMessage,
    AgentStatus,
    AgentMetrics
)
from .message_bus import MessageBus


class AgentCapability(Enum):
    """Agent capabilities for task routing"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    PLANNING = "planning"
    REPORTING = "reporting"
    ORCHESTRATION = "orchestration"


class BaseAgent(ABC):
    """
    Abstract base class for all agents

    All specialized agents must:
    1. Define their capabilities
    2. Implement execute_task() method
    3. Use LLM with smart routing for decisions
    4. Report results through message bus
    """

    def __init__(
        self,
        name: str,
        capabilities: List[AgentCapability],
        llm_client: LLMClient,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        """
        Initialize base agent

        Args:
            name: Unique agent name
            capabilities: List of agent capabilities
            llm_client: LLM client for AI-powered decisions
            context_engine: Context fusion engine for rich context
            message_bus: Message bus for inter-agent communication
        """
        self.name = name
        self.capabilities = capabilities
        self.llm_client = llm_client
        self.context_engine = context_engine
        self.message_bus = message_bus

        self.status = AgentStatus.IDLE
        self.current_task: Optional[AgentTask] = None
        self.metrics = AgentMetrics(agent_name=name)

        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.logger.info(f"Agent '{name}' initialized with capabilities: {[c.value for c in capabilities]}")

        # Subscribe to message bus if provided
        if self.message_bus:
            self.message_bus.subscribe(self.name, self._handle_message)

    @abstractmethod
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """
        Execute assigned task

        Must be implemented by all specialized agents

        Args:
            task: Task to execute

        Returns:
            AgentResult with findings and recommendations
        """
        pass

    async def run_task(self, task: AgentTask) -> AgentResult:
        """
        Main task execution wrapper with metrics and error handling

        Args:
            task: Task to execute

        Returns:
            AgentResult with execution details
        """
        self.current_task = task
        self.status = AgentStatus.THINKING
        task.started_at = datetime.now()
        task.status = AgentStatus.EXECUTING

        start_time = time.time()
        result = None

        try:
            self.logger.info(f"Starting task: {task.task_id} - {task.description}")

            # Execute the task
            result = await self.execute_task(task)

            # Update timing
            execution_time = time.time() - start_time
            result.execution_time_seconds = execution_time

            # Mark task completed
            task.completed_at = datetime.now()
            task.status = AgentStatus.COMPLETED
            self.status = AgentStatus.COMPLETED

            # Update metrics
            self.metrics.update(result)

            self.logger.info(
                f"Task completed: {task.task_id} in {execution_time:.2f}s, "
                f"status={result.status.value}, findings={len(result.findings)}"
            )

            # Notify via message bus
            if self.message_bus:
                await self._send_completion_message(task, result)

            return result

        except Exception as e:
            self.logger.error(f"Task failed: {task.task_id} - {e}", exc_info=True)

            execution_time = time.time() - start_time
            result = AgentResult(
                task_id=task.task_id,
                agent_name=self.name,
                status=AgentStatus.FAILED,
                error=str(e),
                execution_time_seconds=execution_time
            )

            task.status = AgentStatus.FAILED
            self.status = AgentStatus.FAILED
            self.metrics.update(result)

            # Notify via message bus
            if self.message_bus:
                await self._send_error_message(task, str(e))

            return result

        finally:
            self.current_task = None
            if self.status != AgentStatus.FAILED:
                self.status = AgentStatus.IDLE

    async def _handle_message(self, message: AgentMessage):
        """
        Handle incoming messages from message bus

        Can be overridden by specialized agents

        Args:
            message: Incoming message
        """
        self.logger.debug(f"Received message from {message.sender}: {message.message_type}")

        # Default: log and ignore
        # Specialized agents can override to handle specific message types
        pass

    async def _send_completion_message(self, task: AgentTask, result: AgentResult):
        """Send task completion notification"""
        if not self.message_bus:
            return

        message = AgentMessage(
            sender=self.name,
            recipient="broadcast",
            message_type="task_completed",
            content={
                "task_id": task.task_id,
                "task_type": task.task_type,
                "status": result.status.value,
                "findings_count": len(result.findings),
                "recommendations_count": len(result.recommendations),
                "execution_time": result.execution_time_seconds
            }
        )
        await self.message_bus.publish(message)

    async def _send_error_message(self, task: AgentTask, error: str):
        """Send task error notification"""
        if not self.message_bus:
            return

        message = AgentMessage(
            sender=self.name,
            recipient="broadcast",
            message_type="task_failed",
            content={
                "task_id": task.task_id,
                "task_type": task.task_type,
                "error": error
            }
        )
        await self.message_bus.publish(message)

    async def send_message(
        self,
        recipient: str,
        message_type: str,
        content: Dict[str, Any],
        correlation_id: Optional[str] = None
    ):
        """
        Send message to another agent

        Args:
            recipient: Target agent name or "broadcast"
            message_type: Type of message
            content: Message content
            correlation_id: Optional correlation ID for request-response
        """
        if not self.message_bus:
            self.logger.warning("No message bus available, cannot send message")
            return

        message = AgentMessage(
            sender=self.name,
            recipient=recipient,
            message_type=message_type,
            content=content,
            correlation_id=correlation_id
        )
        await self.message_bus.publish(message)

    def can_handle(self, task: AgentTask) -> bool:
        """
        Check if agent can handle a task

        Args:
            task: Task to check

        Returns:
            True if agent has required capability
        """
        # Try to match task_type to capabilities
        for capability in self.capabilities:
            if capability.value in task.task_type.lower():
                return True
        return False

    def get_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        return self.metrics.to_dict()

    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "name": self.name,
            "status": self.status.value,
            "capabilities": [c.value for c in self.capabilities],
            "current_task": self.current_task.task_id if self.current_task else None,
            "metrics": self.get_metrics()
        }
