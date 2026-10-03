"""
Reporting Agent
Specializes in generating comprehensive security assessment reports
"""

from typing import Dict, Any, List, Optional
import json
from datetime import datetime
from enum import Enum

from .base_agent import BaseAgent, AgentCapability
from .data_models import AgentTask, AgentResult, AgentStatus


class ReportFormat(Enum):
    """Report output formats"""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILED = "technical_detailed"
    COMPLIANCE = "compliance"
    REMEDIATION = "remediation"
    JSON = "json"
    MARKDOWN = "markdown"


class ReportingAgent(BaseAgent):
    """
    Reporting Agent

    Responsibilities:
    - Generate executive summaries
    - Create detailed technical reports
    - Aggregate findings from multiple agents
    - Provide remediation recommendations
    - Generate compliance-focused reports
    - Track metrics and statistics

    Uses Sonnet (smart model) for high-quality report generation
    """

    def __init__(self, *args, **kwargs):
        """Initialize Reporting Agent"""
        super().__init__(
            name="ReportingAgent",
            capabilities=[AgentCapability.REPORTING],
            *args,
            **kwargs
        )

        self.generated_reports: Dict[str, Dict[str, Any]] = {}

    async def _execute_task(self, task: AgentTask) -> AgentResult:
        """
        Execute reporting task

        Task types:
        - generate_executive_summary: High-level summary for executives
        - generate_technical_report: Detailed technical findings
        - generate_remediation_plan: Step-by-step remediation guide
        - aggregate_findings: Aggregate findings from multiple sources
        - generate_compliance_report: Compliance-focused assessment

        Args:
            task: Reporting task

        Returns:
            AgentResult with generated report
        """
        self.logger.info(f"Executing reporting task: {task.task_type}")

        if task.task_type == "generate_executive_summary":
            return await self._generate_executive_summary(task)
        elif task.task_type == "generate_technical_report":
            return await self._generate_technical_report(task)
        elif task.task_type == "generate_remediation_plan":
            return await self._generate_remediation_plan(task)
        elif task.task_type == "aggregate_findings":
            return await self._aggregate_findings(task)
        elif task.task_type == "generate_compliance_report":
            return await self._generate_compliance_report(task)
        else:
            return AgentResult(
                task_id=task.task_id,
                agent_name=self.name,
                status=AgentStatus.FAILED,
                error=f"Unknown task type: {task.task_type}"
            )

    async def _generate_executive_summary(self, task: AgentTask) -> AgentResult:
        """
        Generate executive summary report

        Non-technical, high-level overview for business stakeholders
        """
        operation_data = task.parameters.get("operation_data", {})
        findings = task.parameters.get("findings", [])
        target = task.parameters.get("target")
        operation_name = task.parameters.get("operation_name", "Security Assessment")

        # Calculate summary statistics
        stats = self._calculate_statistics(findings)

        # Build prompt for executive summary
        prompt = self._build_executive_summary_prompt(
            operation_name, target, findings, stats, operation_data
        )

        # Use LLM with routing (COMPLEX task - use Sonnet for quality)
        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="generate_executive_report",
            force_json=True,
            temperature=0.7,  # Slightly creative for readability
            max_tokens=4096
        )

        # Parse response
        try:
            report = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                report = json.loads(json_match.group(0))
            else:
                report = {"executive_summary": {"title": "Report Generation Failed"}}

        # Store generated report
        report_id = f"exec-{task.task_id}"
        self.generated_reports[report_id] = {
            "report_id": report_id,
            "report_type": "executive_summary",
            "generated_at": datetime.now().isoformat(),
            "content": report
        }

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[report],
            metadata={
                "report_id": report_id,
                "report_type": "executive_summary",
                "target": target,
                "total_findings": len(findings),
                "critical_count": stats["critical_count"],
                "high_count": stats["high_count"],
                "pages_estimated": report.get("executive_summary", {}).get("estimated_pages", 0)
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    async def _generate_technical_report(self, task: AgentTask) -> AgentResult:
        """
        Generate detailed technical report

        Comprehensive technical documentation for security teams
        """
        operation_data = task.parameters.get("operation_data", {})
        findings = task.parameters.get("findings", [])
        target = task.parameters.get("target")
        operation_name = task.parameters.get("operation_name", "Security Assessment")
        include_evidence = task.parameters.get("include_evidence", True)

        # Calculate statistics
        stats = self._calculate_statistics(findings)

        # Build prompt
        prompt = self._build_technical_report_prompt(
            operation_name, target, findings, stats, operation_data, include_evidence
        )

        # Use LLM with routing (COMPLEX task - use Sonnet)
        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="generate_technical_documentation",
            force_json=True,
            temperature=0.5,  # More factual
            max_tokens=8192  # Long detailed report
        )

        # Parse response
        try:
            report = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                report = json.loads(json_match.group(0))
            else:
                report = {"technical_report": {"sections": []}}

        # Store report
        report_id = f"tech-{task.task_id}"
        self.generated_reports[report_id] = {
            "report_id": report_id,
            "report_type": "technical_detailed",
            "generated_at": datetime.now().isoformat(),
            "content": report
        }

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[report],
            metadata={
                "report_id": report_id,
                "report_type": "technical_detailed",
                "target": target,
                "total_findings": len(findings),
                "vulnerabilities_documented": stats["vulnerability_count"],
                "sections": len(report.get("technical_report", {}).get("sections", []))
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    async def _generate_remediation_plan(self, task: AgentTask) -> AgentResult:
        """
        Generate remediation plan

        Step-by-step plan to fix identified vulnerabilities
        """
        findings = task.parameters.get("findings", [])
        target = task.parameters.get("target")
        prioritize_by = task.parameters.get("prioritize_by", "risk")  # risk, ease, compliance

        # Calculate statistics
        stats = self._calculate_statistics(findings)

        prompt = f"""Generate a comprehensive remediation plan for these security findings:

Target: {target}
Prioritization Strategy: {prioritize_by}

Findings Summary:
- Total Findings: {len(findings)}
- Critical: {stats['critical_count']}
- High: {stats['high_count']}
- Medium: {stats['medium_count']}
- Low: {stats['low_count']}

Detailed Findings:
{json.dumps(findings[:30], indent=2)}

Generate a remediation plan in JSON format:
{{
    "remediation_plan": {{
        "summary": {{
            "total_vulnerabilities": {len(findings)},
            "estimated_remediation_time": "time estimate",
            "recommended_priority_order": ["vulnerability1", "vulnerability2"],
            "quick_wins": ["easy fix 1", "easy fix 2"],
            "long_term_improvements": ["improvement1", "improvement2"]
        }},
        "remediation_items": [
            {{
                "item_id": "REM-001",
                "vulnerability": "vulnerability name/id",
                "severity": "critical|high|medium|low",
                "priority": 1,
                "title": "remediation title",
                "description": "what needs to be fixed",
                "affected_systems": ["system1", "system2"],
                "remediation_steps": [
                    {{
                        "step": 1,
                        "action": "action to take",
                        "commands": ["command1"],
                        "expected_result": "result",
                        "validation": "how to verify"
                    }}
                ],
                "estimated_effort": "hours/days/weeks",
                "difficulty": "easy|medium|hard",
                "required_skills": ["skill1", "skill2"],
                "required_resources": ["resource1", "resource2"],
                "business_impact": "impact of remediation",
                "alternative_solutions": [
                    {{
                        "solution": "alternative approach",
                        "pros": ["pro1"],
                        "cons": ["con1"]
                    }}
                ],
                "verification_procedure": "how to verify fix worked",
                "rollback_plan": "what if something goes wrong"
            }}
        ],
        "timeline": {{
            "immediate": ["action1", "action2"],
            "short_term": ["action3"],
            "medium_term": ["action4"],
            "long_term": ["action5"]
        }},
        "resource_requirements": {{
            "personnel": ["role1", "role2"],
            "tools": ["tool1", "tool2"],
            "budget_estimate": "cost estimate"
        }},
        "risk_mitigation": {{
            "temporary_mitigations": [
                {{
                    "vulnerability": "vuln name",
                    "temporary_fix": "quick fix until proper remediation",
                    "limitations": "what this doesn't cover"
                }}
            ]
        }}
    }}
}}"""

        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="generate_remediation_guidance",
            force_json=True,
            temperature=0.6,
            max_tokens=6144
        )

        try:
            plan = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                plan = json.loads(json_match.group(0))
            else:
                plan = {"remediation_plan": {"remediation_items": []}}

        # Store report
        report_id = f"remed-{task.task_id}"
        self.generated_reports[report_id] = {
            "report_id": report_id,
            "report_type": "remediation",
            "generated_at": datetime.now().isoformat(),
            "content": plan
        }

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[plan],
            recommendations=plan.get("remediation_plan", {}).get("remediation_items", []),
            metadata={
                "report_id": report_id,
                "report_type": "remediation",
                "target": target,
                "remediation_items": len(plan.get("remediation_plan", {}).get("remediation_items", [])),
                "quick_wins": len(plan.get("remediation_plan", {}).get("summary", {}).get("quick_wins", []))
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    async def _aggregate_findings(self, task: AgentTask) -> AgentResult:
        """
        Aggregate findings from multiple sources

        Combines findings from different agents/phases
        """
        findings_by_agent = task.parameters.get("findings_by_agent", {})
        operation_data = task.parameters.get("operation_data", {})

        # Flatten all findings
        all_findings = []
        for agent_name, agent_findings in findings_by_agent.items():
            for finding in agent_findings:
                finding["source_agent"] = agent_name
                all_findings.append(finding)

        # Calculate statistics
        stats = self._calculate_statistics(all_findings)
        stats["agents_involved"] = len(findings_by_agent)
        stats["findings_by_agent"] = {
            agent: len(findings) for agent, findings in findings_by_agent.items()
        }

        # Build aggregation prompt
        prompt = f"""Aggregate and analyze these security findings from multiple agents:

Operation Summary:
{json.dumps(operation_data, indent=2)}

Findings by Agent:
{json.dumps(findings_by_agent, indent=2)}

Statistics:
- Total Findings: {len(all_findings)}
- Agents Involved: {stats['agents_involved']}
- Critical: {stats['critical_count']}
- High: {stats['high_count']}

Provide aggregated analysis in JSON format:
{{
    "aggregated_findings": {{
        "summary": {{
            "total_findings": {len(all_findings)},
            "unique_vulnerabilities": 0,
            "duplicate_findings": [],
            "finding_categories": {{}},
            "attack_surface_summary": "description",
            "overall_risk_level": "critical|high|medium|low"
        }},
        "key_findings": [
            {{
                "finding_id": "FIND-001",
                "title": "finding title",
                "severity": "critical|high|medium|low",
                "category": "category",
                "description": "description",
                "affected_assets": ["asset1"],
                "discovered_by": ["agent1", "agent2"],
                "corroborated": true,
                "confidence": "high|medium|low",
                "business_impact": "impact description"
            }}
        ],
        "patterns_identified": [
            {{
                "pattern": "pattern description",
                "occurrences": 3,
                "significance": "why this matters"
            }}
        ],
        "attack_chains_identified": [
            {{
                "chain_id": "CHAIN-001",
                "description": "attack chain description",
                "steps": ["step1", "step2"],
                "risk": "critical|high|medium|low",
                "mitre_tactics": ["TA0001"]
            }}
        ],
        "coverage_analysis": {{
            "areas_assessed": ["area1", "area2"],
            "areas_not_covered": ["area3"],
            "assessment_completeness": "percentage or description"
        }}
    }}
}}"""

        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="aggregate_security_findings",
            force_json=True,
            temperature=0.5,
            max_tokens=4096
        )

        try:
            aggregation = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                aggregation = json.loads(json_match.group(0))
            else:
                aggregation = {"aggregated_findings": {"summary": {}, "key_findings": all_findings}}

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[aggregation],
            metadata={
                "total_findings": len(all_findings),
                "agents_involved": stats["agents_involved"],
                "unique_vulnerabilities": aggregation.get("aggregated_findings", {}).get("summary", {}).get("unique_vulnerabilities", 0),
                "attack_chains": len(aggregation.get("aggregated_findings", {}).get("attack_chains_identified", []))
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    async def _generate_compliance_report(self, task: AgentTask) -> AgentResult:
        """
        Generate compliance-focused report

        Maps findings to compliance frameworks (PCI-DSS, HIPAA, etc.)
        """
        findings = task.parameters.get("findings", [])
        framework = task.parameters.get("framework", "general")  # pci-dss, hipaa, gdpr, etc.
        target = task.parameters.get("target")

        stats = self._calculate_statistics(findings)

        prompt = f"""Generate a compliance-focused security report:

Target: {target}
Compliance Framework: {framework}

Findings:
{json.dumps(findings[:20], indent=2)}

Statistics:
- Total Findings: {len(findings)}
- Critical: {stats['critical_count']}
- High: {stats['high_count']}

Generate compliance report in JSON format:
{{
    "compliance_report": {{
        "framework": "{framework}",
        "assessment_date": "{datetime.now().isoformat()}",
        "target": "{target}",
        "compliance_status": {{
            "overall_status": "compliant|non_compliant|partial_compliance",
            "compliance_score": 75,
            "critical_gaps": ["gap1", "gap2"],
            "areas_of_concern": ["concern1"]
        }},
        "control_assessment": [
            {{
                "control_id": "CTRL-001",
                "control_name": "control name",
                "requirement": "what is required",
                "status": "pass|fail|partial|not_applicable",
                "findings": ["finding1"],
                "evidence": "evidence of compliance or non-compliance",
                "risk_rating": "critical|high|medium|low",
                "remediation_priority": "immediate|short_term|long_term"
            }}
        ],
        "recommendations": [
            {{
                "priority": "high|medium|low",
                "control_area": "area",
                "recommendation": "what to do",
                "compliance_impact": "impact on compliance status"
            }}
        ],
        "audit_trail": {{
            "assessment_methodology": "methodology used",
            "tools_used": ["tool1", "tool2"],
            "limitations": ["limitation1"],
            "assessor_notes": "additional notes"
        }}
    }}
}}"""

        llm_response = await self.llm_client.generate_with_routing(
            prompt=prompt,
            task_type="generate_compliance_assessment",
            force_json=True,
            temperature=0.4,  # Very factual for compliance
            max_tokens=5120
        )

        try:
            report = json.loads(llm_response.content)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'\{.*\}', llm_response.content, re.DOTALL)
            if json_match:
                report = json.loads(json_match.group(0))
            else:
                report = {"compliance_report": {"compliance_status": {}}}

        # Store report
        report_id = f"comp-{task.task_id}"
        self.generated_reports[report_id] = {
            "report_id": report_id,
            "report_type": "compliance",
            "generated_at": datetime.now().isoformat(),
            "content": report
        }

        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[report],
            recommendations=report.get("compliance_report", {}).get("recommendations", []),
            metadata={
                "report_id": report_id,
                "report_type": "compliance",
                "framework": framework,
                "target": target,
                "compliance_status": report.get("compliance_report", {}).get("compliance_status", {}).get("overall_status", "unknown"),
                "controls_assessed": len(report.get("compliance_report", {}).get("control_assessment", []))
            },
            tokens_used=llm_response.tokens_used,
            cost_usd=llm_response.metadata.get("cost_usd", 0.0)
        )

        return result

    def _calculate_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from findings"""
        stats = {
            "total_count": len(findings),
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "vulnerability_count": 0,
            "categories": {}
        }

        for finding in findings:
            # Count by severity
            severity = finding.get("severity", "unknown").lower()
            if severity == "critical":
                stats["critical_count"] += 1
            elif severity == "high":
                stats["high_count"] += 1
            elif severity == "medium":
                stats["medium_count"] += 1
            elif severity == "low":
                stats["low_count"] += 1

            # Count vulnerabilities
            if "vulnerability" in str(finding).lower() or "cve" in str(finding).lower():
                stats["vulnerability_count"] += 1

            # Count by category
            category = finding.get("category", finding.get("type", "other"))
            stats["categories"][category] = stats["categories"].get(category, 0) + 1

        return stats

    def _build_executive_summary_prompt(
        self,
        operation_name: str,
        target: str,
        findings: List[Dict[str, Any]],
        stats: Dict[str, Any],
        operation_data: Dict[str, Any]
    ) -> str:
        """Build executive summary prompt"""
        prompt = f"""Generate an executive summary for a security assessment:

Operation: {operation_name}
Target: {target}
Assessment Date: {datetime.now().strftime('%Y-%m-%d')}

Statistics:
- Total Findings: {stats['total_count']}
- Critical: {stats['critical_count']}
- High: {stats['high_count']}
- Medium: {stats['medium_count']}
- Low: {stats['low_count']}

Key Findings (sample):
{json.dumps(findings[:10], indent=2)}

Operation Details:
{json.dumps(operation_data, indent=2)}

Generate an executive summary in JSON format:
{{
    "executive_summary": {{
        "title": "{operation_name} - Executive Summary",
        "date": "{datetime.now().strftime('%Y-%m-%d')}",
        "target": "{target}",
        "assessment_overview": {{
            "scope": "what was assessed",
            "methodology": "how it was assessed",
            "duration": "assessment duration",
            "key_objectives": ["objective1", "objective2"]
        }},
        "executive_overview": "2-3 paragraph non-technical summary of findings and business impact",
        "risk_rating": {{
            "overall_risk": "critical|high|medium|low",
            "risk_score": 75,
            "risk_factors": [
                "factor 1",
                "factor 2"
            ],
            "trend": "improving|stable|deteriorating"
        }},
        "key_findings_summary": [
            {{
                "finding": "non-technical finding description",
                "business_impact": "impact on business",
                "urgency": "immediate|short_term|long_term"
            }}
        ],
        "business_impact": {{
            "financial_risk": "description",
            "operational_risk": "description",
            "reputational_risk": "description",
            "regulatory_risk": "description"
        }},
        "recommendations": [
            {{
                "priority": "high|medium|low",
                "recommendation": "what to do",
                "business_benefit": "benefit",
                "estimated_effort": "effort level",
                "estimated_cost": "cost range"
            }}
        ],
        "conclusion": "concluding paragraph with next steps",
        "estimated_pages": 2
    }}
}}"""

        return prompt

    def _build_technical_report_prompt(
        self,
        operation_name: str,
        target: str,
        findings: List[Dict[str, Any]],
        stats: Dict[str, Any],
        operation_data: Dict[str, Any],
        include_evidence: bool
    ) -> str:
        """Build technical report prompt"""
        prompt = f"""Generate a detailed technical security report:

Operation: {operation_name}
Target: {target}
Assessment Date: {datetime.now().strftime('%Y-%m-%d')}
Include Evidence: {include_evidence}

Statistics:
{json.dumps(stats, indent=2)}

Detailed Findings:
{json.dumps(findings[:25], indent=2)}

Generate technical report in JSON format:
{{
    "technical_report": {{
        "title": "{operation_name} - Technical Assessment Report",
        "metadata": {{
            "report_version": "1.0",
            "date": "{datetime.now().strftime('%Y-%m-%d')}",
            "target": "{target}",
            "classification": "confidential"
        }},
        "sections": [
            {{
                "section_number": "1",
                "title": "Executive Summary",
                "content": "technical executive summary"
            }},
            {{
                "section_number": "2",
                "title": "Methodology",
                "content": "assessment methodology",
                "subsections": [
                    {{
                        "title": "Tools Used",
                        "content": "list of tools and techniques"
                    }},
                    {{
                        "title": "Scope",
                        "content": "assessment scope details"
                    }}
                ]
            }},
            {{
                "section_number": "3",
                "title": "Findings",
                "findings": [
                    {{
                        "finding_id": "FIND-001",
                        "title": "finding title",
                        "severity": "critical|high|medium|low",
                        "cvss_score": 9.8,
                        "affected_systems": ["system1"],
                        "description": "technical description",
                        "technical_details": "deep technical analysis",
                        "proof_of_concept": "PoC or reproduction steps",
                        "evidence": "evidence if include_evidence=true",
                        "impact": "technical impact",
                        "likelihood": "likelihood assessment",
                        "mitigation": "how to fix",
                        "references": ["ref1", "ref2"]
                    }}
                ]
            }},
            {{
                "section_number": "4",
                "title": "Risk Analysis",
                "content": "comprehensive risk analysis"
            }},
            {{
                "section_number": "5",
                "title": "Recommendations",
                "recommendations": [
                    {{
                        "rec_id": "REC-001",
                        "title": "recommendation title",
                        "priority": "high|medium|low",
                        "description": "detailed recommendation",
                        "implementation_steps": ["step1", "step2"],
                        "effort": "effort estimate",
                        "impact": "expected impact"
                    }}
                ]
            }},
            {{
                "section_number": "6",
                "title": "Conclusion",
                "content": "technical conclusion"
            }}
        ],
        "appendices": [
            {{
                "appendix": "A",
                "title": "Technical Details",
                "content": "additional technical information"
            }}
        ]
    }}
}}"""

        return prompt

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve generated report by ID"""
        return self.generated_reports.get(report_id)

    def list_reports(self) -> List[Dict[str, Any]]:
        """List all generated reports"""
        return [
            {
                "report_id": report_id,
                "report_type": report["report_type"],
                "generated_at": report["generated_at"]
            }
            for report_id, report in self.generated_reports.items()
        ]
