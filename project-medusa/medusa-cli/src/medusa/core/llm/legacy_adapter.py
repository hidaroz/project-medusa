"""
Legacy adapter layer for backward compatibility with existing code.

This adapter bridges the old monolithic LLMClient/LocalLLMClient/MockLLMClient
interface with the new provider-based architecture.

This allows gradual migration of existing code without breaking changes.
Existing code can continue to use the old interface while new code uses
the new cleaner provider architecture.

Usage:
    # Old interface (still works):
    from medusa.core.llm import LocalLLMClient, MockLLMClient
    client = LocalLLMClient(config)

    # New interface (recommended):
    from medusa.core.llm import LLMClient, create_llm_client
    client = create_llm_client(config)
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional

from .config import LLMConfig
from .client import LLMClient
from .providers.base import LLMResponse
from .exceptions import LLMError


logger = logging.getLogger(__name__)


class LocalLLMClient:
    """
    Legacy interface for local LLM client using Ollama.

    This class maintains the old interface while using the new
    provider-based architecture internally.

    New code should use LLMClient with LocalProvider instead.
    """

    def __init__(self, config: LLMConfig):
        """Initialize Local LLM client with legacy interface"""
        # Ensure we use local provider
        config.provider = "local"
        config.mock_mode = False

        self.config = config
        self.logger = logging.getLogger(__name__)

        # Create new-style LLMClient internally
        try:
            from .factory import create_llm_client
            self._client = create_llm_client(config)
        except Exception as e:
            self.logger.error(f"Failed to create LLM client: {e}")
            raise

    # Delegate all high-level methods to the new client
    async def get_reconnaissance_recommendation(
        self,
        target: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Get AI recommendation for reconnaissance phase"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.reconnaissance_strategy(target, context)
        try:
            response = await self._client.generate(
                prompt=prompt,
                force_json=True
            )
            result = self._extract_json_from_response(response.content)
            self.logger.info(f"Reconnaissance recommendation generated for {target}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to get reconnaissance recommendation: {e}")
            return self._get_fallback_reconnaissance()

    async def get_enumeration_recommendation(
        self,
        target: str,
        reconnaissance_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Get AI recommendation for enumeration phase"""
        from medusa.core.prompts import PromptTemplates
        import os

        # Get objective from environment variable if available
        objective = os.getenv('MEDUSA_OBJECTIVE', '')
        prompt = PromptTemplates.enumeration_strategy(target, reconnaissance_findings, objective=objective if objective else None)
        try:
            response = await self._client.generate(
                prompt=prompt,
                force_json=True
            )
            result = self._extract_json_from_response(response.content)
            self.logger.info(f"Enumeration recommendation generated for {target}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to get enumeration recommendation: {e}")
            return self._get_fallback_enumeration()

    async def assess_vulnerability_risk(
        self,
        vulnerability: Dict[str, Any],
        target_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Assess risk level of a discovered vulnerability"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.vulnerability_risk_assessment(
            vulnerability, target_context
        )
        try:
            response = await self._client.generate(
                prompt=prompt,
                force_json=False
            )
            risk_level = response.content.strip().upper()

            # Validate response
            for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if level in risk_level:
                    risk_level = level
                    break

            if risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                self.logger.info(
                    f"Risk assessed as {risk_level} for {vulnerability.get('type', 'unknown')}"
                )
                return risk_level
            else:
                self.logger.warning(f"Invalid risk level from LLM: {risk_level}")
                return "MEDIUM"
        except Exception as e:
            self.logger.error(f"Failed to assess vulnerability risk: {e}")
            return self._get_fallback_risk_assessment(vulnerability)

    async def plan_attack_strategy(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        objectives: List[str]
    ) -> Dict[str, Any]:
        """Generate overall attack strategy based on all findings"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.attack_strategy_planning(
            target, findings, objectives
        )
        try:
            response = await self._client.generate(
                prompt=prompt,
                force_json=True
            )
            result = self._extract_json_from_response(response.content)
            self.logger.info(f"Attack strategy generated for {target}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to plan attack strategy: {e}")
            return self._get_fallback_attack_plan()

    async def get_next_action_recommendation(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Get recommendation for the next action to take"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.next_action_recommendation(context)
        try:
            response = await self._client.generate(
                prompt=prompt,
                force_json=True
            )
            result = self._extract_json_from_response(response.content)
            self.logger.info("Next action recommendation generated")
            return result
        except Exception as e:
            self.logger.error(f"Failed to get next action recommendation: {e}")
            return self._get_fallback_next_action()

    async def prioritize_reconnaissance_targets(
        self,
        amass_findings: List[Dict[str, Any]],
        httpx_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Prioritize targets from reconnaissance for efficient scanning"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.prioritize_targets(amass_findings, httpx_findings)
        try:
            response = await self._client.generate(
                prompt=prompt,
                force_json=True
            )
            result = self._extract_json_from_response(response.content)
            self.logger.info(
                f"Target prioritization generated for {len(amass_findings)} subdomains"
            )
            return result
        except Exception as e:
            self.logger.error(f"Failed to prioritize reconnaissance targets: {e}")
            return self._get_fallback_target_prioritization(
                amass_findings, httpx_findings
            )

    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from LLM response"""
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            import re
            json_match = re.search(
                r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL
            )
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            self.logger.error(f"Could not extract JSON from response: {response[:200]}")
            raise ValueError("Invalid JSON response from LLM")

    # Fallback methods (same as in original implementation)
    def _get_fallback_reconnaissance(self) -> Dict[str, Any]:
        """Safe fallback for reconnaissance"""
        return {
            "recommended_actions": [{
                "action": "port_scan",
                "command": "nmap -sV",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "priority": "high",
                "reasoning": "Basic port scan to discover services"
            }],
            "focus_areas": ["web_services"],
            "risk_assessment": "LOW",
            "estimated_duration": 60
        }

    def _get_fallback_enumeration(self) -> Dict[str, Any]:
        """Safe fallback for enumeration"""
        return {
            "recommended_actions": [{
                "action": "enumerate_web_paths",
                "technique_id": "T1590",
                "priority": "medium",
                "reasoning": "Enumerate common web paths"
            }],
            "services_to_probe": ["http", "https"],
            "risk_assessment": "LOW",
            "potential_vulnerabilities": ["information_disclosure"]
        }

    def _get_fallback_risk_assessment(self, vulnerability: Dict[str, Any]) -> str:
        """Safe fallback for risk assessment"""
        severity = vulnerability.get("severity", "").upper()
        risk_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW"
        }
        return risk_map.get(severity, "MEDIUM")

    def _get_fallback_attack_plan(self) -> Dict[str, Any]:
        """Safe fallback for attack planning"""
        return {
            "strategy_overview": "Conservative approach focusing on information gathering",
            "attack_chain": [{
                "step": 1,
                "action": "enumerate_endpoints",
                "technique_id": "T1590",
                "expected_outcome": "Discover API endpoints",
                "risk_level": "LOW",
                "prerequisites": []
            }],
            "success_probability": 0.6,
            "estimated_duration": 180,
            "risks": ["minimal"]
        }

    def _get_fallback_next_action(self) -> Dict[str, Any]:
        """Safe fallback for next action"""
        return {
            "recommendations": [{
                "action": "continue_enumeration",
                "confidence": 0.7,
                "reasoning": "Continue systematic enumeration",
                "technique": "T1590",
                "risk_level": "LOW"
            }],
            "context_analysis": "Continuing with safe reconnaissance activities",
            "suggested_next_phase": "enumeration"
        }

    def _get_fallback_target_prioritization(
        self,
        amass_findings: List[Dict[str, Any]],
        httpx_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Safe fallback for target prioritization"""
        high_priority_keywords = [
            "admin", "api", "database", "internal", "management", "backend"
        ]
        medium_priority_keywords = ["app", "service", "test", "staging", "dev"]

        prioritized = []
        for finding in amass_findings:
            subdomain = finding.get("subdomain", "").lower()
            priority = "LOW"

            for keyword in high_priority_keywords:
                if keyword in subdomain:
                    priority = "HIGH"
                    break

            if priority == "LOW":
                for keyword in medium_priority_keywords:
                    if keyword in subdomain:
                        priority = "MEDIUM"
                        break

            if httpx_findings and priority != "HIGH":
                for http_finding in httpx_findings:
                    if finding.get("subdomain") in http_finding.get("url", ""):
                        if priority == "LOW":
                            priority = "MEDIUM"
                        elif priority == "MEDIUM":
                            priority = "HIGH"
                        break

            prioritized.append({
                "target": finding.get("subdomain"),
                "priority": priority,
                "rationale": "Heuristic prioritization based on subdomain characteristics",
                "confidence": 0.6,
                "recommended_actions": [{
                    "action": "port_scan",
                    "technique_id": "T1046"
                }],
                "attack_vectors": ["sql_injection", "authentication_bypass"],
                "estimated_effort_seconds": (
                    300 if priority == "HIGH" else (200 if priority == "MEDIUM" else 100)
                )
            })

        priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        prioritized.sort(key=lambda x: priority_order.get(x["priority"], 3))

        return {
            "prioritized_targets": prioritized[:20],
            "scan_strategy": (
                "Scan HIGH priority first (admin/api panels), then MEDIUM "
                "(other live services), finally LOW priority"
            ),
            "total_estimated_effort": sum(
                t["estimated_effort_seconds"] for t in prioritized[:20]
            ),
            "risk_level": "LOW",
            "early_wins": [
                "Admin panels often have default credentials",
                "API endpoints frequently have information disclosure"
            ]
        }

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if hasattr(self._client, 'close'):
            await self._client.close()


class MockLLMClient:
    """
    Legacy interface for mock LLM client.

    Provides realistic but deterministic responses without API calls.
    Perfect for testing, CI/CD, and development.

    This class maintains the old interface while using the new
    provider-based architecture internally.

    New code should use LLMClient with MockProvider instead.
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        """Initialize Mock LLM client with legacy interface"""
        config = config or LLMConfig(provider="mock", mock_mode=True)
        config.provider = "mock"
        config.mock_mode = True

        self.config = config
        self.logger = logging.getLogger(__name__)

        # Create new-style LLMClient internally
        try:
            from .factory import create_llm_client
            self._client = create_llm_client(config)
        except Exception as e:
            self.logger.error(f"Failed to create mock LLM client: {e}")
            raise

    # Delegate all methods to the new client
    async def get_reconnaissance_recommendation(
        self,
        target: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Mock reconnaissance recommendation"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.reconnaissance_strategy(target, context)
        response = await self._client.generate(prompt=prompt, force_json=True)
        return self._extract_json_from_response(response.content)

    async def get_enumeration_recommendation(
        self,
        target: str,
        reconnaissance_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Mock enumeration recommendation"""
        from medusa.core.prompts import PromptTemplates
        import os

        # Get objective from environment variable if available
        objective = os.getenv('MEDUSA_OBJECTIVE', '')
        prompt = PromptTemplates.enumeration_strategy(target, reconnaissance_findings, objective=objective if objective else None)
        response = await self._client.generate(prompt=prompt, force_json=True)
        return self._extract_json_from_response(response.content)

    async def assess_vulnerability_risk(
        self,
        vulnerability: Dict[str, Any],
        target_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Mock vulnerability risk assessment"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.vulnerability_risk_assessment(
            vulnerability, target_context
        )
        response = await self._client.generate(prompt=prompt, force_json=False)
        return response.content.strip().upper()

    async def plan_attack_strategy(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        objectives: List[str]
    ) -> Dict[str, Any]:
        """Mock attack strategy"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.attack_strategy_planning(
            target, findings, objectives
        )
        response = await self._client.generate(prompt=prompt, force_json=True)
        return self._extract_json_from_response(response.content)

    async def prioritize_reconnaissance_targets(
        self,
        amass_findings: List[Dict[str, Any]],
        httpx_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Mock target prioritization"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.prioritize_targets(amass_findings, httpx_findings)
        response = await self._client.generate(prompt=prompt, force_json=True)
        return self._extract_json_from_response(response.content)

    async def get_next_action_recommendation(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Mock next action recommendation"""
        from medusa.core.prompts import PromptTemplates

        prompt = PromptTemplates.next_action_recommendation(context)
        response = await self._client.generate(prompt=prompt, force_json=True)
        return self._extract_json_from_response(response.content)

    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from LLM response"""
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            import re
            json_match = re.search(
                r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL
            )
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            raise ValueError("Invalid JSON response from LLM")

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if hasattr(self._client, 'close'):
            await self._client.close()

