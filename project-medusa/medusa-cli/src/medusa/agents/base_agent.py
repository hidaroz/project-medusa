"""
Base Agent Class

Foundation for all specialized penetration testing agents.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import time

from .data_models import AgentTask, AgentResult, TaskStatus


class BaseAgent(ABC):
    """
    Base class for all AI agents.

    Provides:
    - LLM client integration
    - Context fusion engine integration
    - Cost tracking
    - Error handling
    """

    def __init__(
        self,
        llm_client: Any,
        context_engine: Optional[Any] = None
    ):
        """
        Initialize base agent.

        Args:
            llm_client: LLM client for generation
            context_engine: Optional context fusion engine
        """
        self.llm_client = llm_client
        self.context_engine = context_engine
        self.total_cost = 0.0

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
            # This is a simplified version
            # Real implementation would use the actual LLM client
            response = {
                'text': f"Mock LLM response for: {prompt[:50]}...",
                'tokens_used': 100,
                'cost_usd': 0.001
            }

            self.total_cost += response['cost_usd']

            return response

        except Exception as e:
            raise Exception(f"LLM call failed: {str(e)}")
