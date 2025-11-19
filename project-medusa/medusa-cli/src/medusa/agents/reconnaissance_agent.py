"""
Reconnaissance Agent

Specialized agent for reconnaissance phase of penetration testing.
Provides tool recommendations, technique suggestions, and strategy planning.
"""

from typing import Dict, Any, Optional, List
import subprocess
import shutil
import xml.etree.ElementTree as ET
import asyncio
import json
from .base_agent import BaseAgent
from .data_models import AgentTask, TaskStatus, AgentResult


class ReconnaissanceAgent(BaseAgent):
    """
    Agent specialized for reconnaissance operations.

    Capabilities:
    - Recommend reconnaissance strategies
    - Suggest appropriate tools
    - Identify MITRE techniques
    - Prioritize targets
    - Execute Nmap scans
    """

    async def _execute_task(self, task: AgentTask) -> Any:
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
        elif task_type == "run_scan":
            return await self._run_scan(task)
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

    async def _run_scan(self, task: AgentTask) -> AgentResult:
        """Execute Nmap scan."""
        target = task.parameters.get('target')
        scan_type = task.parameters.get('scan_type', 'fast')
        
        if not target:
            raise ValueError("Target is required for scan")
            
        self.logger.info(f"Starting {scan_type} scan against {target}")
        
        try:
            scan_results = await self._execute_nmap_scan(target, scan_type)
            
            return AgentResult(
                task_id=task.task_id,
                status=TaskStatus.COMPLETED,
                findings=scan_results,
                data={
                    'target': target,
                    'scan_type': scan_type
                }
            )
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise

    async def _execute_nmap_scan(self, target: str, scan_type: str) -> List[Dict[str, Any]]:
        """Run Nmap command and parse results."""
        if not shutil.which("nmap"):
            raise RuntimeError("nmap is not installed")

        # Build command
        cmd = ["nmap", "-oX", "-"]
        
        if scan_type == "fast":
            cmd.extend(["-F", "-T4"])
        elif scan_type == "comprehensive":
            cmd.extend(["-sV", "-sC", "-p-", "-T4"])
        else:
            cmd.extend(["-sV", "-T4"])
            
        cmd.append(target)
        
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        
        # Execute
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            self.logger.error(f"Nmap failed: {stderr.decode()}")
            return []
            
        xml_content = stdout.decode()
        self.logger.info(f"Nmap output length: {len(xml_content)}")
        
        findings = self._parse_nmap_xml(xml_content)
        self.logger.info(f"Parsed {len(findings)} findings from Nmap XML")
        return findings

    def _parse_nmap_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output into structured findings."""
        findings = []
        try:
            root = ET.fromstring(xml_content)
            
            for host in root.findall("host"):
                address = host.find("address").get("addr")
                ports = host.find("ports")
                
                if ports:
                    for port in ports.findall("port"):
                        state = port.find("state").get("state")
                        if state == "open":
                            port_id = port.get("portid")
                            protocol = port.get("protocol")
                            service = port.find("service")
                            service_name = service.get("name") if service is not None else "unknown"
                            product = service.get("product") if service is not None else ""
                            version = service.get("version") if service is not None else ""
                            
                            findings.append({
                                "type": "open_port",
                                "ip": address,
                                "port": int(port_id),
                                "protocol": protocol,
                                "service": service_name,
                                "version": f"{product} {version}".strip(),
                                "state": state
                            })
        except Exception as e:
            self.logger.error(f"Failed to parse Nmap XML: {e}")
            
        return findings

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
