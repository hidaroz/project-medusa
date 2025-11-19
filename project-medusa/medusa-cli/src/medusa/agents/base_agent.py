"""
Base Agent Class

Foundation for all specialized penetration testing agents.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import time
import logging

from .data_models import AgentTask, AgentResult, TaskStatus, AgentCapability, AgentStatus


class BaseAgent(ABC):
    """
    Base class for all AI agents.

    Provides:
    - LLM client integration
    - Context fusion engine integration
    - Cost tracking
    - Error handling
    - Message bus integration
    """

    def __init__(
        self,
        llm_client: Any,
        context_engine: Optional[Any] = None,
        message_bus: Optional[Any] = None,
        name: Optional[str] = None,
        capabilities: Optional[List[AgentCapability]] = None
    ):
        """
        Initialize base agent.

        Args:
            llm_client: LLM client for generation
            context_engine: Optional context fusion engine
            message_bus: Optional message bus for inter-agent communication
            name: Agent name
            capabilities: List of agent capabilities
        """
        self.llm_client = llm_client
        self.context_engine = context_engine
        self.message_bus = message_bus
        self.name = name or self.__class__.__name__
        self.capabilities = capabilities or []
        self.status = AgentStatus.IDLE
        self.total_cost = 0.0
        self.logger = logging.getLogger(f"medusa.agents.{self.name}")

    async def run_task(self, task: AgentTask) -> AgentResult:
        """
        Execute a task.

        Args:
            task: Task to execute

        Returns:
            Task execution result
        """
        start_time = time.time()
        task.status = TaskStatus.IN_PROGRESS

        try:
            # Execute task
            result_data = await self._execute_task(task)

            # If _execute_task returned an AgentResult, use it
            if isinstance(result_data, AgentResult):
                result = result_data
                result.duration_seconds = time.time() - start_time
                return result

            # Create result
            result = AgentResult(
                task_id=task.task_id,
                status=TaskStatus.COMPLETED,
                data=result_data,
                duration_seconds=time.time() - start_time
            )

            return result

        except Exception as e:
            # Handle errors
            result = AgentResult(
                task_id=task.task_id,
                status=TaskStatus.FAILED,
                error=str(e),
                duration_seconds=time.time() - start_time
            )
            return result

    @abstractmethod
    async def _execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """
        Execute task logic (implemented by subclasses).

        Args:
            task: Task to execute

        Returns:
            Task result data
        """
        pass

    async def _get_context(
        self,
        query: str,
        operation_phase: str,
        operation_state: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get context from fusion engine if available.

        Args:
            query: Context query
            operation_phase: Current operation phase
            operation_state: Operation state

        Returns:
            Retrieved context or None
        """
        if not self.context_engine:
            return None

        try:
            recommendations = await self.context_engine.get_contextual_recommendations(
                query=query,
                operation_phase=operation_phase,
                operation_state=operation_state
            )
            return {
                'recommendations': recommendations,
                'count': len(recommendations)
            }
        except Exception:
            return None

    def _build_prompt(
        self,
        task: AgentTask,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Build prompt for LLM.

        Args:
            task: Task to build prompt for
            context: Optional context to include

        Returns:
            Formatted prompt
        """
        prompt_parts = []

        # Add task description
        prompt_parts.append(f"Task: {task.description}")

        # Add task parameters
        if task.parameters:
            prompt_parts.append("\nParameters:")
            for key, value in task.parameters.items():
                prompt_parts.append(f"- {key}: {value}")

        # Add context if available
        if context and context.get('recommendations'):
            prompt_parts.append("\nRelevant Context:")
            for rec in context['recommendations'][:3]:
                content = rec.get('content', '')
                if content:
                    prompt_parts.append(f"- {content[:200]}...")

        return "\n".join(prompt_parts)

    async def _call_llm(
        self,
        prompt: str,
        max_tokens: int = 1000
    ) -> Dict[str, Any]:
        """
        Call LLM with prompt.

        Args:
            prompt: Prompt to send
            max_tokens: Maximum tokens to generate

        Returns:
            LLM response with metadata
        """
        try:
            response = await self.llm_client.generate(
                prompt=prompt,
                max_tokens=max_tokens
            )

            self.total_cost += response.metadata.get('cost_usd', 0.0)

            return {
                'text': response.content,
                'tokens_used': response.tokens_used,
                'cost_usd': response.metadata.get('cost_usd', 0.0),
                'metadata': response.metadata
            }

        except Exception as e:
            self.logger.error(f"LLM call failed: {e}")
            raise Exception(f"LLM call failed: {str(e)}")
