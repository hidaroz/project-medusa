"""
Planning Agent
Specializes in strategic planning and attack chain orchestration
"""

from typing import Dict, Any, List
import json

from .base_agent import BaseAgent, AgentCapability
from .data_models import AgentTask, AgentResult, AgentStatus


class PlanningAgent(BaseAgent):
    """
    Planning Agent

    Responsibilities:
    - Create comprehensive attack plans
    - Design attack chains based on findings
    - Prioritize actions based on risk/reward
    - Ensure operational safety and compliance
    - Provide strategic recommendations

    Uses Sonnet (smart model) for deep strategic reasoning
    """

    def __init__(self, *args, **kwargs):
        """Initialize Planning Agent"""
        super().__init__(
            name="PlanningAgent",
            capabilities=[AgentCapability.PLANNING],
            *args,
            **kwargs
        )

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """
        Execute planning task

        Task types:
        - create_operation_plan: Create comprehensive operation plan
        - design_attack_chain: Design attack chain from findings
        - prioritize_actions: Prioritize next actions
        - assess_risk: Assess operational risks

        Args:
            task: Planning task

        Returns:
            AgentResult with strategic plan
        """
        self.logger.info(f"Executing planning task: {task.task_type}")

        if task.task_type == "create_operation_plan":
            return await self._create_operation_plan(task)
        elif task.task_type == "design_attack_chain":
            return await self._design_attack_chain(task)
        elif task.task_type == "prioritize_actions":
            return await self._prioritize_actions(task)
        elif task.task_type == "assess_risk":
            return await self._assess_risk(task)
        else:
            return AgentResult(
                task_id=task.task_id,
                agent_name=self.name,
                status=AgentStatus.FAILED,
                error=f"Unknown task type: {task.task_type}"
            )

    async def _create_operation_plan(self, task: AgentTask) -> AgentResult:
        """
        Create comprehensive operation plan

        Uses full context fusion:
        - All findings from recon and analysis
        - Historical operation data
        - MITRE ATT&CK attack chain templates
        - Graph database attack surface
        """
        objectives = task.parameters.get("objectives", [])
        all_findings = task.parameters.get("findings", [])
        constraints = task.parameters.get("constraints", {})

        # Build comprehensive context
        context = {}
        if self.context_engine:
            try:
                context = self.context_engine.build_context_for_planning(
                    all_findings=all_findings,
                    objectives=objectives
                )
            except Exception as e:
                self.logger.warning(f"Failed to build planning context: {e}")

        # Build strategic planning prompt
        prompt = self._build_operation_plan_prompt(objectives, all_findings, constraints, context)

        # Use LLM with routing (COMPLEX task - uses Sonnet)
        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="plan_attack_strategy",
            force_json=True,
            temperature=0.7,  # Higher creativity for planning
            max_tokens=4096  # Longer output for comprehensive plan
        )

        # Parse response
        try:
            plan = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                plan = json.loads(json_match.group(0))
            else:
                plan = {"error": "Failed to parse plan"}

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[plan],  # The plan is the main finding
            recommendations=plan.get("phases", []),
            metadata={
                "objectives": objectives,
                "total_findings": len(all_findings),
                "context_sources": list(context.keys()),
                "phases_count": len(plan.get("phases", [])),
                "total_actions": sum(len(phase.get("actions", [])) for phase in plan.get("phases", []))
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    async def _design_attack_chain(self, task: AgentTask) -> AgentResult:
        """Design attack chain from initial access to objectives"""
        initial_access = task.parameters.get("initial_access", {})
        objective = task.parameters.get("objective", "")
        vulnerabilities = task.parameters.get("vulnerabilities", [])

        prompt = f"""Design an attack chain to achieve the objective:

Initial Access:
{json.dumps(initial_access, indent=2)}

Objective: {objective}

Available Vulnerabilities:
{json.dumps(vulnerabilities, indent=2)}

Design an attack chain using MITRE ATT&CK framework. Provide in JSON format:
{{
    "attack_chain": [
        {{
            "step": 1,
            "phase": "phase name",
            "mitre_technique": "T1234",
            "technique_name": "technique name",
            "action": "what to do",
            "tools": ["tool1", "tool2"],
            "expected_result": "what you get",
            "success_criteria": "how to know it worked",
            "risk_level": "low|medium|high",
            "detection_likelihood": "low|medium|high"
        }}
    ],
    "success_probability": 0.85,
    "estimated_duration": "time estimate",
    "risk_assessment": "overall risk",
    "alternative_paths": ["alternative 1", "alternative 2"]
}}"""

        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="design_attack_chain",
            force_json=True,
            max_tokens=3072
        )

        try:
            chain = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                chain = json.loads(json_match.group(0))
            else:
                chain = {"attack_chain": []}

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[chain],
            recommendations=chain.get("attack_chain", []),
            metadata={
                "chain_length": len(chain.get("attack_chain", [])),
                "success_probability": chain.get("success_probability", 0),
                "risk_assessment": chain.get("risk_assessment", "unknown")
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    async def _prioritize_actions(self, task: AgentTask) -> AgentResult:
        """Prioritize potential actions based on risk/reward"""
        possible_actions = task.parameters.get("actions", [])
        current_state = task.parameters.get("current_state", {})

        prompt = f"""Prioritize these actions based on risk/reward analysis:

Current State:
{json.dumps(current_state, indent=2)}

Possible Actions:
{json.dumps(possible_actions, indent=2)}

Prioritize and provide in JSON format:
{{
    "prioritized_actions": [
        {{
            "action": "action description",
            "priority": 1,
            "risk": "low|medium|high",
            "reward": "low|medium|high",
            "effort": "low|medium|high",
            "success_probability": 0.8,
            "reasoning": "why this priority",
            "dependencies": ["action1", "action2"],
            "estimated_time": "time estimate"
        }}
    ],
    "recommended_sequence": ["action1", "action2", "action3"]
}}"""

        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="prioritize_actions",
            force_json=True
        )

        try:
            prioritization = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                prioritization = json.loads(json_match.group(0))
            else:
                prioritization = {"prioritized_actions": possible_actions}

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            recommendations=prioritization.get("prioritized_actions", []),
            metadata={
                "actions_analyzed": len(possible_actions),
                "recommended_sequence": prioritization.get("recommended_sequence", [])
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    async def _assess_risk(self, task: AgentTask) -> AgentResult:
        """Assess operational risks"""
        proposed_action = task.parameters.get("action", {})
        current_context = task.parameters.get("context", {})

        prompt = f"""Assess the operational risk of this action:

Proposed Action:
{json.dumps(proposed_action, indent=2)}

Current Context:
{json.dumps(current_context, indent=2)}

Assess risks and provide in JSON format:
{{
    "risk_assessment": {{
        "overall_risk": "low|medium|high|critical",
        "detection_risk": "low|medium|high",
        "impact_risk": "low|medium|high",
        "legal_compliance": "compliant|review_needed|non_compliant",
        "safety_considerations": ["consideration1", "consideration2"]
    }},
    "risk_factors": [
        {{
            "factor": "factor name",
            "severity": "low|medium|high",
            "mitigation": "how to mitigate"
        }}
    ],
    "recommendation": "proceed|modify|abort",
    "modifications_suggested": ["suggestion1", "suggestion2"]
}}"""

        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="assess_risk_holistic",
            force_json=True
        )

        try:
            assessment = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                assessment = json.loads(json_match.group(0))
            else:
                assessment = {"risk_assessment": {"overall_risk": "high"}, "recommendation": "abort"}

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[assessment.get("risk_assessment", {})],
            recommendations=[{"recommendation": assessment.get("recommendation", "abort")}],
            metadata={
                "overall_risk": assessment.get("risk_assessment", {}).get("overall_risk", "unknown"),
                "risk_factors_count": len(assessment.get("risk_factors", []))
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    def _build_operation_plan_prompt(
        self,
        objectives: List[str],
        findings: List[Dict[str, Any]],
        constraints: Dict[str, Any],
        context: Dict[str, Any]
    ) -> str:
        """Build comprehensive operation planning prompt"""
        prompt = f"""You are a strategic planning expert. Create a comprehensive operation plan:

Objectives:
{json.dumps(objectives, indent=2)}

Current Findings:
{json.dumps(findings[:20], indent=2)}  # Limit to 20 for context window

Constraints:
{json.dumps(constraints, indent=2)}

"""

        # Add context from fusion engine
        if context.get("attack_surface"):
            prompt += f"\nAttack Surface: {json.dumps(context['attack_surface'], indent=2)}\n"

        if context.get("similar_past_operations"):
            prompt += "\nSimilar Past Operations:\n"
            for op in context["similar_past_operations"][:2]:
                prompt += f"- {op['operation_id']}: {op['summary'][:100]}...\n"

        if context.get("attack_chain_templates"):
            prompt += "\nRelevant MITRE Techniques:\n"
            for tech in context["attack_chain_templates"][:5]:
                prompt += f"- {tech['technique_id']}: {tech['technique_name']}\n"

        prompt += """

Create a comprehensive operation plan in JSON format:
{
    "operation_plan": {
        "name": "operation name",
        "objectives": ["objective1", "objective2"],
        "strategy": "overall strategy description",
        "phases": [
            {
                "phase_name": "phase name",
                "phase_number": 1,
                "objectives": ["phase objective1"],
                "actions": [
                    {
                        "action_id": "A1",
                        "action": "action description",
                        "tools": ["tool1", "tool2"],
                        "mitre_techniques": ["T1234"],
                        "estimated_duration": "time",
                        "success_criteria": "how to measure success",
                        "risk_level": "low|medium|high",
                        "dependencies": []
                    }
                ],
                "success_criteria": "phase success criteria",
                "rollback_plan": "what to do if fails"
            }
        ],
        "risk_assessment": {
            "overall_risk": "low|medium|high",
            "key_risks": ["risk1", "risk2"],
            "mitigation_strategies": ["strategy1", "strategy2"]
        },
        "resource_requirements": {
            "tools": ["tool1", "tool2"],
            "estimated_time": "total time",
            "skill_requirements": ["skill1", "skill2"]
        },
        "success_metrics": {
            "completion_criteria": ["criteria1", "criteria2"],
            "deliverables": ["deliverable1", "deliverable2"]
        }
    }
}"""

        return prompt
