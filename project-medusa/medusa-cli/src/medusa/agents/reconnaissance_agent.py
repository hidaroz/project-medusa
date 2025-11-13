"""
Reconnaissance Agent
Specializes in reconnaissance and information gathering tasks
"""

from typing import Dict, Any, List
import json

from .base_agent import BaseAgent, AgentCapability
from .data_models import AgentTask, AgentResult, AgentStatus


class ReconnaissanceAgent(BaseAgent):
    """
    Reconnaissance Agent

    Responsibilities:
    - Recommend reconnaissance strategies
    - Suggest appropriate tools (Nmap, Amass, etc.)
    - Analyze reconnaissance findings
    - Identify next reconnaissance steps
    """

    def __init__(self, *args, **kwargs):
        """Initialize Reconnaissance Agent"""
        super().__init__(
            name="ReconAgent",
            capabilities=[AgentCapability.RECONNAISSANCE],
            *args,
            **kwargs
        )

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """
        Execute reconnaissance task

        Task types:
        - recommend_recon_strategy: Recommend reconnaissance approach
        - analyze_scan_results: Analyze scan findings
        - suggest_next_steps: Suggest next reconnaissance actions

        Args:
            task: Reconnaissance task

        Returns:
            AgentResult with recommendations and findings
        """
        self.logger.info(f"Executing reconnaissance task: {task.task_type}")

        if task.task_type == "recommend_recon_strategy":
            return await self._recommend_strategy(task)
        elif task.task_type == "analyze_scan_results":
            return await self._analyze_results(task)
        elif task.task_type == "suggest_next_steps":
            return await self._suggest_next_steps(task)
        else:
            return AgentResult(
                task_id=task.task_id,
                agent_name=self.name,
                status=AgentStatus.FAILED,
                error=f"Unknown task type: {task.task_type}"
            )

    async def _recommend_strategy(self, task: AgentTask) -> AgentResult:
        """
        Recommend reconnaissance strategy for target

        Uses context fusion to provide:
        - Relevant MITRE ATT&CK techniques
        - Tool recommendations
        - Known infrastructure
        """
        target = task.parameters.get("target")
        objectives = task.parameters.get("objectives", [])

        # Build rich context
        context = {}
        if self.context_engine:
            try:
                context = self.context_engine.build_context_for_reconnaissance(
                    target=target,
                    existing_findings=task.parameters.get("existing_findings")
                )
            except Exception as e:
                self.logger.warning(f"Failed to build context: {e}")

        # Build prompt for LLM
        prompt = self._build_reconnaissance_prompt(target, objectives, context)

        # Use LLM with routing (this is a MODERATE task)
        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="recommend_recon_strategy",
            force_json=True
        )

        # Parse LLM response
        try:
            recommendations = json.loads(llm_response.content)
        except json.JSONDecodeError:
            # Try to extract JSON
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                recommendations = json.loads(json_match.group(0))
            else:
                recommendations = {"error": "Failed to parse LLM response"}

        # Build result
        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            recommendations=[recommendations],
            metadata={
                "target": target,
                "context_used": bool(context),
                "mitre_techniques": len(context.get("recommended_techniques", [])),
                "tool_suggestions": len(context.get("tool_suggestions", []))
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    async def _analyze_results(self, task: AgentTask) -> AgentResult:
        """
        Analyze reconnaissance scan results

        Identifies:
        - Interesting findings
        - Potential vulnerabilities
        - Services to investigate further
        """
        scan_data = task.parameters.get("scan_data", {})
        scan_type = task.parameters.get("scan_type", "unknown")

        # Build analysis prompt
        prompt = f"""Analyze these {scan_type} scan results and identify key findings:

Scan Data:
{json.dumps(scan_data, indent=2)}

Provide analysis in JSON format:
{{
    "key_findings": [
        {{
            "finding": "description",
            "severity": "high|medium|low",
            "service": "service name",
            "port": port_number,
            "reasoning": "why this is interesting"
        }}
    ],
    "interesting_services": ["service1", "service2"],
    "potential_vulnerabilities": ["vuln1", "vuln2"],
    "next_steps": ["action1", "action2"]
}}"""

        # Use LLM with routing (SIMPLE task - parsing/extraction)
        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="parse_tool_output",
            force_json=True
        )

        # Parse response
        try:
            analysis = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group(0))
            else:
                analysis = {"error": "Failed to parse analysis"}

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=analysis.get("key_findings", []),
            recommendations=analysis.get("next_steps", []),
            metadata={
                "scan_type": scan_type,
                "services_found": analysis.get("interesting_services", [])
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    async def _suggest_next_steps(self, task: AgentTask) -> AgentResult:
        """Suggest next reconnaissance steps based on current findings"""
        current_findings = task.parameters.get("findings", [])
        target = task.parameters.get("target")

        prompt = f"""Based on these reconnaissance findings for {target}, suggest next steps:

Current Findings:
{json.dumps(current_findings, indent=2)}

Provide suggestions in JSON format:
{{
    "next_actions": [
        {{
            "action": "action type",
            "tool": "recommended tool",
            "command": "specific command",
            "priority": "high|medium|low",
            "reasoning": "why to do this"
        }}
    ],
    "focus_areas": ["area1", "area2"]
}}"""

        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="recommend_recon_strategy",
            force_json=True
        )

        try:
            suggestions = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                suggestions = json.loads(json_match.group(0))
            else:
                suggestions = {"next_actions": []}

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            recommendations=suggestions.get("next_actions", []),
            metadata={
                "focus_areas": suggestions.get("focus_areas", [])
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    def _build_reconnaissance_prompt(
        self,
        target: str,
        objectives: List[str],
        context: Dict[str, Any]
    ) -> str:
        """Build comprehensive reconnaissance strategy prompt"""
        prompt = f"""You are a reconnaissance expert. Design a reconnaissance strategy for:

Target: {target}
Objectives: {', '.join(objectives) if objectives else 'General reconnaissance'}

"""

        # Add context if available
        if context.get("recommended_techniques"):
            prompt += "\nRelevant MITRE ATT&CK Techniques:\n"
            for tech in context["recommended_techniques"][:3]:
                prompt += f"- {tech['technique_id']}: {tech['technique_name']}\n"

        if context.get("tool_suggestions"):
            prompt += "\nSuggested Tools:\n"
            for tool in context["tool_suggestions"][:3]:
                prompt += f"- {tool['tool']}: {tool['command']}\n"

        prompt += """

Provide a reconnaissance strategy in JSON format:
{
    "strategy": {
        "approach": "passive|active|hybrid",
        "phases": ["phase1", "phase2", "phase3"],
        "tools": [
            {
                "tool": "tool name",
                "command": "specific command",
                "purpose": "why use this",
                "phase": "which phase",
                "priority": "high|medium|low"
            }
        ],
        "mitre_techniques": ["T1046", "T1595"],
        "expected_findings": ["finding type 1", "finding type 2"],
        "risk_level": "low|medium|high",
        "estimated_duration": "time estimate"
    }
}"""

        return prompt
