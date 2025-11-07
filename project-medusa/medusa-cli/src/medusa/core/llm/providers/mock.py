"""
Mock LLM provider for testing and development.

Provides realistic but deterministic responses without making
actual API calls. Perfect for CI/CD, testing, and development.
"""

import asyncio
import random
import time
import logging
from typing import Dict, Optional, Any

from .base import BaseLLMProvider, LLMResponse
from ..exceptions import LLMError


logger = logging.getLogger(__name__)


class MockProvider(BaseLLMProvider):
    """
    Mock LLM provider for testing without API calls.

    Provides realistic but deterministic responses for:
    - Unit testing
    - Integration testing
    - CI/CD pipelines
    - Development without LLM access
    """

    PROVIDER_NAME = "mock"

    def __init__(self, deterministic: bool = False):
        """
        Initialize Mock Provider.

        Args:
            deterministic: If True, always return the same responses
        """
        self.deterministic = deterministic
        logger.info("MockProvider initialized (no API calls)")

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        force_json: bool = False
    ) -> LLMResponse:
        """
        Generate mock completion.

        Args:
            prompt: User prompt
            system_prompt: System instructions (ignored)
            temperature: Sampling temperature (ignored)
            max_tokens: Maximum tokens (ignored)
            force_json: Whether to return JSON

        Returns:
            LLMResponse with mock content
        """
        start_time = time.time()

        # Simulate API delay
        await asyncio.sleep(random.uniform(0.1, 0.5) if not self.deterministic else 0.3)

        # Generate mock response based on prompt content
        content = self._generate_mock_content(prompt, force_json)

        latency_ms = (time.time() - start_time) * 1000

        return LLMResponse(
            content=content,
            provider=self.PROVIDER_NAME,
            model="mock-model",
            tokens_used=len(content.split()) * 2,  # Rough token estimate
            latency_ms=latency_ms,
            metadata={
                "mock": True,
                "deterministic": self.deterministic
            }
        )

    async def health_check(self) -> bool:
        """Mock provider is always healthy"""
        return True

    async def get_model_info(self) -> Dict[str, Any]:
        """Get mock model information"""
        return {
            "name": "mock-model",
            "provider": "mock",
            "version": "1.0.0",
            "parameters": "N/A",
            "capabilities": ["text-generation", "json-mode"],
            "mock": True
        }

    def _generate_mock_content(self, prompt: str, force_json: bool) -> str:
        """
        Generate mock content based on prompt.

        Uses keyword matching to provide contextually appropriate responses.
        """
        prompt_lower = prompt.lower()

        # Reconnaissance responses
        if "reconnaissance" in prompt_lower or "recon" in prompt_lower:
            if force_json:
                return """{
    "recommended_actions": [
        {
            "action": "port_scan",
            "command": "nmap -sV target",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "priority": "high",
            "reasoning": "Comprehensive port scan to discover all exposed services"
        },
        {
            "action": "web_discovery",
            "command": "whatweb target",
            "technique_id": "T1595",
            "technique_name": "Active Scanning",
            "priority": "medium",
            "reasoning": "Identify web technologies and frameworks"
        }
    ],
    "focus_areas": ["web_services", "api_endpoints", "authentication"],
    "risk_assessment": "LOW",
    "estimated_duration": 90
}"""
            else:
                return "Recommend starting with port scanning and web discovery."

        # Enumeration responses
        elif "enumeration" in prompt_lower or "enumerate" in prompt_lower:
            if force_json:
                return """{
    "recommended_actions": [
        {
            "action": "enumerate_api_endpoints",
            "technique_id": "T1590",
            "priority": "high",
            "reasoning": "Discovered REST API, enumerate all endpoints and methods"
        },
        {
            "action": "test_authentication",
            "technique_id": "T1110",
            "priority": "medium",
            "reasoning": "Test authentication mechanisms for weaknesses"
        }
    ],
    "services_to_probe": ["http", "https", "api", "database"],
    "risk_assessment": "LOW",
    "potential_vulnerabilities": ["authentication_bypass", "information_disclosure", "api_abuse"]
}"""
            else:
                return "Focus on API endpoint enumeration and authentication testing."

        # Vulnerability assessment responses
        elif "vulnerability" in prompt_lower or "risk" in prompt_lower:
            if "sql" in prompt_lower or "injection" in prompt_lower:
                return "HIGH"
            elif "xss" in prompt_lower or "csrf" in prompt_lower:
                return "MEDIUM"
            else:
                return "LOW"

        # Attack strategy responses
        elif "attack" in prompt_lower or "strategy" in prompt_lower:
            if force_json:
                return """{
    "strategy_overview": "Multi-stage attack targeting API vulnerabilities for data access",
    "attack_chain": [
        {
            "step": 1,
            "action": "exploit_authentication_bypass",
            "target_vulnerability": "Unauthenticated API endpoints",
            "technique_id": "T1078",
            "expected_outcome": "Gain authenticated session",
            "risk_level": "MEDIUM",
            "prerequisites": []
        },
        {
            "step": 2,
            "action": "exploit_sql_injection",
            "target_vulnerability": "SQL Injection in search parameter",
            "technique_id": "T1190",
            "expected_outcome": "Database access and data extraction",
            "risk_level": "MEDIUM",
            "prerequisites": ["authenticated_session"]
        }
    ],
    "success_probability": 0.78,
    "estimated_duration": 420,
    "risks": ["IDS/IPS detection", "Account lockout after failed attempts"]
}"""
            else:
                return "Recommend multi-stage attack focusing on authentication bypass followed by SQL injection."

        # Target prioritization responses
        elif "prioritize" in prompt_lower or "target" in prompt_lower:
            if force_json:
                return """{
    "prioritized_targets": [
        {
            "target": "admin.example.com",
            "priority": "HIGH",
            "rationale": "Admin panels are typically high-value targets with significant attack surface",
            "confidence": 0.9,
            "recommended_actions": [
                {
                    "action": "deep_port_scan",
                    "technique_id": "T1046",
                    "reasoning": "Discover all open ports and services"
                }
            ],
            "attack_vectors": ["sql_injection", "authentication_bypass", "api_abuse"],
            "estimated_effort_seconds": 300
        },
        {
            "target": "api.example.com",
            "priority": "HIGH",
            "rationale": "API endpoints often expose sensitive functionality",
            "confidence": 0.85,
            "recommended_actions": [
                {
                    "action": "web_app_scan",
                    "technique_id": "T1595.002",
                    "reasoning": "Test for common web vulnerabilities"
                }
            ],
            "attack_vectors": ["api_abuse", "authentication_bypass"],
            "estimated_effort_seconds": 250
        }
    ],
    "scan_strategy": "Start with HIGH priority targets on ports 80,443,8080-8090. Then move to MEDIUM priority.",
    "total_estimated_effort": 1500,
    "risk_level": "LOW",
    "early_wins": ["Look for default credentials on admin panels", "Test for information disclosure on API endpoints"]
}"""
            else:
                return "Prioritize admin panels and API endpoints as HIGH priority targets."

        # Next action responses
        elif "next action" in prompt_lower or "recommend" in prompt_lower:
            if force_json:
                return """{
    "recommendations": [
        {
            "action": "exploit_sql_injection",
            "confidence": 0.85,
            "reasoning": "Detected SQL injection vulnerability with high success probability",
            "technique": "T1190",
            "risk_level": "MEDIUM"
        }
    ],
    "context_analysis": "Target appears to be a healthcare application with multiple security weaknesses",
    "suggested_next_phase": "exploitation"
}"""
            else:
                return "Recommend proceeding with SQL injection exploitation."

        # Default response
        else:
            if force_json:
                return """{
    "response": "Mock response for testing",
    "success": true,
    "mock": true
}"""
            else:
                return "This is a mock response for testing purposes."

    async def close(self):
        """No cleanup needed for mock provider"""
        pass
