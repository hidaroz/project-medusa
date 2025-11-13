"""
Orchestrator Agent
Supervisor agent that coordinates all specialist agents
"""

from typing import Dict, Any, List, Optional
import json
import uuid
from datetime import datetime

from .base_agent import BaseAgent, AgentCapability
from .data_models import (
    AgentTask,
    AgentResult,
    AgentStatus,
    AgentMessage,
    TaskPriority
)


class OrchestratorAgent(BaseAgent):
    """
    Orchestrator Agent (Supervisor)

    Responsibilities:
    - Coordinate specialist agents
    - Break down complex operations into tasks
    - Delegate tasks to appropriate agents
    - Aggregate results from multiple agents
    - Monitor overall operation progress
    - Make high-level strategic decisions

    This is the "brain" of the multi-agent system
    """

    def __init__(self, specialist_agents: Dict[str, BaseAgent], *args, **kwargs):
        """
        Initialize Orchestrator Agent

        Args:
            specialist_agents: Dictionary of specialist agents {name: agent}
            *args, **kwargs: BaseAgent arguments
        """
        super().__init__(
            name="Orchestrator",
            capabilities=[AgentCapability.ORCHESTRATION],
            *args,
            **kwargs
        )

        self.specialist_agents = specialist_agents
        self.active_tasks: Dict[str, AgentTask] = {}
        self.completed_tasks: Dict[str, AgentResult] = {}

        self.logger.info(
            f"Orchestrator initialized with {len(specialist_agents)} specialist agents: "
            f"{list(specialist_agents.keys())}"
        )

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """
        Execute orchestration task

        The orchestrator breaks down high-level operations into subtasks
        and delegates to specialist agents

        Task types:
        - run_operation: Execute complete operation
        - coordinate_phase: Coordinate a specific phase
        - aggregate_results: Aggregate results from specialists

        Args:
            task: Orchestration task

        Returns:
            AgentResult with aggregated findings
        """
        self.logger.info(f"Executing orchestration task: {task.task_type}")

        if task.task_type == "run_operation":
            return await self._run_operation(task)
        elif task.task_type == "coordinate_phase":
            return await self._coordinate_phase(task)
        elif task.task_type == "aggregate_results":
            return await self._aggregate_results(task)
        else:
            return AgentResult(
                task_id=task.task_id,
                agent_name=self.name,
                status=AgentStatus.FAILED,
                error=f"Unknown task type: {task.task_type}"
            )

    async def _run_operation(self, task: AgentTask) -> AgentResult:
        """
        Run complete operation with multiple phases

        Flow:
        1. Recon Agent: Gather information
        2. Vuln Analysis Agent: Find vulnerabilities
        3. Planning Agent: Create attack plan
        4. Execution: (simulated for now)
        """
        target = task.parameters.get("target")
        objectives = task.parameters.get("objectives", [])

        self.logger.info(f"Running operation against {target}")

        all_findings = []
        all_recommendations = []
        phase_results = {}

        # Phase 1: Reconnaissance
        self.logger.info("Phase 1: Reconnaissance")
        recon_task = AgentTask(
            task_id=self._generate_task_id(),
            task_type="recommend_recon_strategy",
            description=f"Recommend reconnaissance strategy for {target}",
            parameters={
                "target": target,
                "objectives": objectives
            },
            priority=TaskPriority.HIGH,
            parent_task_id=task.task_id
        )

        recon_result = await self._delegate_task(recon_task, "ReconAgent")
        if recon_result:
            phase_results["reconnaissance"] = recon_result.to_dict()
            all_findings.extend(recon_result.findings)
            all_recommendations.extend(recon_result.recommendations)

        # Phase 2: Vulnerability Analysis
        # Simulate some findings for analysis
        simulated_findings = [
            {"type": "open_port", "port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
            {"type": "open_port", "port": 80, "service": "http", "version": "Apache 2.4.6"},
            {"type": "open_port", "port": 3306, "service": "mysql", "version": "MySQL 5.7"}
        ]

        self.logger.info("Phase 2: Vulnerability Analysis")
        vuln_task = AgentTask(
            task_id=self._generate_task_id(),
            task_type="analyze_findings",
            description="Analyze findings for vulnerabilities",
            parameters={
                "findings": simulated_findings,
                "target": target
            },
            priority=TaskPriority.HIGH,
            parent_task_id=task.task_id
        )

        vuln_result = await self._delegate_task(vuln_task, "VulnAnalysisAgent")
        if vuln_result:
            phase_results["vulnerability_analysis"] = vuln_result.to_dict()
            all_findings.extend(vuln_result.findings)
            all_recommendations.extend(vuln_result.recommendations)

        # Phase 3: Strategic Planning
        self.logger.info("Phase 3: Strategic Planning")
        planning_task = AgentTask(
            task_id=self._generate_task_id(),
            task_type="create_operation_plan",
            description="Create comprehensive operation plan",
            parameters={
                "objectives": objectives,
                "findings": all_findings,
                "constraints": task.parameters.get("constraints", {})
            },
            priority=TaskPriority.CRITICAL,
            parent_task_id=task.task_id
        )

        planning_result = await self._delegate_task(planning_task, "PlanningAgent")
        if planning_result:
            phase_results["planning"] = planning_result.to_dict()
            all_findings.extend(planning_result.findings)
            all_recommendations.extend(planning_result.recommendations)

        # Aggregate all results
        total_cost = sum(
            result.cost_usd
            for result in [recon_result, vuln_result, planning_result]
            if result
        )

        total_tokens = sum(
            result.tokens_used
            for result in [recon_result, vuln_result, planning_result]
            if result
        )

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=all_findings,
            recommendations=all_recommendations,
            metadata={
                "target": target,
                "objectives": objectives,
                "phases_completed": list(phase_results.keys()),
                "phase_results": phase_results,
                "total_cost_usd": total_cost,
                "total_tokens": total_tokens
            },
            tokens_used=total_tokens,
            cost_usd=total_cost
        )

        return result

    async def _coordinate_phase(self, task: AgentTask) -> AgentResult:
        """Coordinate a specific operation phase"""
        phase_name = task.parameters.get("phase")
        phase_tasks = task.parameters.get("tasks", [])

        self.logger.info(f"Coordinating phase: {phase_name}")

        # Execute tasks in phase
        phase_results = []
        for task_spec in phase_tasks:
            subtask = AgentTask(
                task_id=self._generate_task_id(),
                task_type=task_spec["task_type"],
                description=task_spec["description"],
                parameters=task_spec.get("parameters", {}),
                priority=TaskPriority[task_spec.get("priority", "MEDIUM").upper()],
                parent_task_id=task.task_id
            )

            # Delegate to appropriate agent
            agent_name = self._select_agent(subtask)
            result = await self._delegate_task(subtask, agent_name)
            if result:
                phase_results.append(result)

        # Aggregate phase results
        total_findings = []
        total_recommendations = []
        for r in phase_results:
            total_findings.extend(r.findings)
            total_recommendations.extend(r.recommendations)

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=total_findings,
            recommendations=total_recommendations,
            metadata={
                "phase": phase_name,
                "tasks_completed": len(phase_results)
            }
        )

        return result

    async def _aggregate_results(self, task: AgentTask) -> AgentResult:
        """Aggregate results from multiple agents"""
        task_ids = task.parameters.get("task_ids", [])

        aggregated_findings = []
        aggregated_recommendations = []

        for task_id in task_ids:
            if task_id in self.completed_tasks:
                result = self.completed_tasks[task_id]
                aggregated_findings.extend(result.findings)
                aggregated_recommendations.extend(result.recommendations)

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=aggregated_findings,
            recommendations=aggregated_recommendations,
            metadata={
                "tasks_aggregated": len(task_ids)
            }
        )

        return result

    async def _delegate_task(
        self,
        task: AgentTask,
        agent_name: Optional[str] = None
    ) -> Optional[AgentResult]:
        """
        Delegate task to specialist agent

        Args:
            task: Task to delegate
            agent_name: Specific agent name, or None to auto-select

        Returns:
            AgentResult or None if failed
        """
        # Select agent if not specified
        if not agent_name:
            agent_name = self._select_agent(task)

        if agent_name not in self.specialist_agents:
            self.logger.error(f"Agent not found: {agent_name}")
            return None

        agent = self.specialist_agents[agent_name]

        self.logger.info(f"Delegating task {task.task_id} to {agent_name}")

        # Track active task
        self.active_tasks[task.task_id] = task

        try:
            # Execute task through agent
            result = await agent.run_task(task)

            # Store completed task
            self.completed_tasks[task.task_id] = result
            del self.active_tasks[task.task_id]

            self.logger.info(
                f"Task {task.task_id} completed by {agent_name}: "
                f"status={result.status.value}, findings={len(result.findings)}"
            )

            return result

        except Exception as e:
            self.logger.error(f"Task delegation failed: {e}", exc_info=True)
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]
            return None

    def _select_agent(self, task: AgentTask) -> str:
        """
        Select appropriate agent for task

        Args:
            task: Task to assign

        Returns:
            Agent name
        """
        # Try to find agent with matching capability
        for agent_name, agent in self.specialist_agents.items():
            if agent.can_handle(task):
                return agent_name

        # Default fallback
        if "recon" in task.task_type.lower():
            return "ReconAgent"
        elif "vuln" in task.task_type.lower() or "analysis" in task.task_type.lower():
            return "VulnAnalysisAgent"
        elif "plan" in task.task_type.lower():
            return "PlanningAgent"

        # Last resort: use first available agent
        return list(self.specialist_agents.keys())[0] if self.specialist_agents else "unknown"

    def _generate_task_id(self) -> str:
        """Generate unique task ID"""
        return f"task-{uuid.uuid4().hex[:8]}"

    def get_operation_status(self) -> Dict[str, Any]:
        """Get current operation status"""
        return {
            "orchestrator": self.name,
            "active_tasks": len(self.active_tasks),
            "completed_tasks": len(self.completed_tasks),
            "specialist_agents": {
                name: agent.get_status()
                for name, agent in self.specialist_agents.items()
            },
            "metrics": self.get_metrics()
        }

    async def _handle_message(self, message: AgentMessage):
        """Handle messages from specialist agents"""
        self.logger.debug(
            f"Orchestrator received message from {message.sender}: {message.message_type}"
        )

        # Log task completions and failures
        if message.message_type == "task_completed":
            self.logger.info(
                f"Task {message.content.get('task_id')} completed by {message.sender}"
            )
        elif message.message_type == "task_failed":
            self.logger.warning(
                f"Task {message.content.get('task_id')} failed: {message.content.get('error')}"
            )
