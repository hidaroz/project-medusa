"""
Reconnaissance Agent

Specialized agent for reconnaissance phase of penetration testing.
Provides tool recommendations, technique suggestions, and strategy planning.
"""

from typing import Dict, Any, Optional
from .base_agent import BaseAgent
from .data_models import AgentTask, TaskStatus


class ReconnaissanceAgent(BaseAgent):
    """
    Agent specialized for reconnaissance operations.

    Capabilities:
    - Recommend reconnaissance strategies
    - Suggest appropriate tools
    - Identify MITRE techniques
    - Prioritize targets
    """

    async def _execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """
        Execute reconnaissance task.

        Supported task types:
        - recommend_recon_strategy
        - suggest_tools
        - prioritize_targets
        """
        task_type = task.task_type

        if task_type == "recommend_recon_strategy":
            return await self._recommend_strategy(task)
        elif task_type == "suggest_tools":
            return await self._suggest_tools(task)
        elif task_type == "prioritize_targets":
            return await self._prioritize_targets(task)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _recommend_strategy(self, task: AgentTask) -> Dict[str, Any]:
        """
        Recommend reconnaissance strategy for target.

        Args:
            task: Task with target and objectives

        Returns:
            Recommended strategy with techniques and tools
        """
        target = task.parameters.get('target', 'unknown')
        objectives = task.parameters.get('objectives', [])

        # Get context from fusion engine if available
        context = None
        if self.context_engine:
            # Build context for reconnaissance
            context = self.context_engine.build_context_for_reconnaissance(
                target=target,
                existing_findings=[]
            )

        # Build prompt
        prompt = self._build_reconnaissance_prompt(target, objectives, context)

        # Call LLM
        llm_response = await self._call_llm(prompt, max_tokens=1500)

        # Parse response and structure results
        result = {
            'target': target,
            'recommendations': self._extract_recommendations(
                llm_response['text'],
                context
            ),
            'mitre_techniques': context.get('recommended_techniques', []) if context else [],
            'suggested_tools': context.get('tool_suggestions', []) if context else []
        }

        return result

    async def _suggest_tools(self, task: AgentTask) -> Dict[str, Any]:
        """Suggest tools for reconnaissance task."""
        task_desc = task.parameters.get('task_description', '')

        # Get context
        context = await self._get_context(
            query=f"tools for {task_desc}",
            operation_phase="reconnaissance",
            operation_state=task.context
        )

        # Build and execute prompt
        prompt = f"Suggest penetration testing tools for: {task_desc}"
        if context:
            prompt += "\n\nAvailable tools in knowledge base:"
            for rec in context.get('recommendations', [])[:5]:
                prompt += f"\n- {rec.get('content', '')[:100]}"

        llm_response = await self._call_llm(prompt, max_tokens=800)

        return {
            'tools': self._extract_tool_list(llm_response['text']),
            'context_used': bool(context)
        }

    async def _prioritize_targets(self, task: AgentTask) -> Dict[str, Any]:
        """Prioritize discovered targets."""
        targets = task.parameters.get('targets', [])

        prompt = f"Prioritize these targets for penetration testing: {targets}"
        llm_response = await self._call_llm(prompt, max_tokens=1000)

        return {
            'prioritized_targets': targets,  # Simplified for now
            'rationale': llm_response['text']
        }

    def _build_reconnaissance_prompt(
        self,
        target: str,
        objectives: list,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build prompt for reconnaissance strategy."""
        prompt = f"""You are a penetration testing expert. Recommend a reconnaissance strategy for:

Target: {target}
Objectives: {', '.join(objectives)}

"""

        if context:
            prompt += "\nRelevant MITRE ATT&CK Techniques:\n"
            for tech in context.get('recommended_techniques', [])[:3]:
                prompt += f"- {tech.get('technique_id')}: {tech.get('name')}\n"

            prompt += "\nRecommended Tools:\n"
            for tool in context.get('tool_suggestions', [])[:3]:
                prompt += f"- {tool.get('tool')}: {tool.get('description', '')[:100]}\n"

        prompt += "\nProvide a step-by-step reconnaissance strategy."

        return prompt

    def _extract_recommendations(
        self,
        llm_text: str,
        context: Optional[Dict[str, Any]]
    ) -> list:
        """Extract structured recommendations from LLM response."""
        # Simplified extraction
        recommendations = [
            "Perform passive reconnaissance using OSINT",
            "Conduct active scanning with appropriate tools",
            "Enumerate services and versions"
        ]

        # Add context-based recommendations
        if context:
            for tech in context.get('recommended_techniques', [])[:2]:
                recommendations.append(
                    f"Apply {tech.get('technique_id')}: {tech.get('name')}"
                )

        return recommendations

    def _extract_tool_list(self, llm_text: str) -> list:
        """Extract tool list from LLM response."""
        # Simplified extraction
        return ["nmap", "masscan", "amass", "subfinder"]
