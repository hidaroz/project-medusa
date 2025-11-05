"""
LLM Integration for MEDUSA AI Pentesting
Provides real AI decision-making via Google Gemini API with fallback to mock responses
"""

import asyncio
import logging
import random
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import json

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    logging.warning("google-generativeai not installed. Install with: pip install google-generativeai")


class RiskLevel(str, Enum):
    """Risk levels for pentesting actions"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class LLMConfig:
    """Configuration for LLM client"""
    api_key: str
    model: str = "gemini-pro"
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout: int = 30
    max_retries: int = 3
    mock_mode: bool = False


class LLMClient:
    """
    Real LLM client using Google Gemini API for AI-powered pentesting decisions
    """

    def __init__(self, config: LLMConfig):
        """Initialize LLM client with configuration"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        if not GEMINI_AVAILABLE:
            self.logger.error("google-generativeai package not installed")
            raise ImportError(
                "google-generativeai is required. Install with: pip install google-generativeai"
            )
        
        # Configure Gemini
        genai.configure(api_key=config.api_key)
        
        # Initialize model with generation config
        generation_config = {
            "temperature": config.temperature,
            "max_output_tokens": config.max_tokens,
        }
        
        self.model = genai.GenerativeModel(
            model_name=config.model,
            generation_config=generation_config
        )
        
        self.logger.info(f"Initialized LLM client with model: {config.model}")

    async def _generate_with_retry(self, prompt: str) -> str:
        """Generate response with retry logic"""
        last_error = None
        
        for attempt in range(self.config.max_retries):
            try:
                self.logger.debug(f"LLM request attempt {attempt + 1}/{self.config.max_retries}")
                
                # Run synchronous Gemini call in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, self.model.generate_content, prompt),
                    timeout=self.config.timeout
                )
                
                if response:
                    # Handle multi-part responses properly
                    try:
                        # Try simple text accessor first (for backwards compatibility)
                        text = self._extract_text_from_response(response)
                        if text:
                            self.logger.debug(f"LLM response received: {len(text)} chars")
                            return text
                        else:
                            self.logger.warning("Empty response from LLM")
                            last_error = "Empty response"
                    except Exception as e:
                        last_error = f"Error parsing response: {str(e)}"
                        self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                        await asyncio.sleep(2 ** attempt)
                        continue
                else:
                    self.logger.warning("No response from LLM")
                    last_error = "No response"
                    
            except asyncio.TimeoutError:
                last_error = f"Request timeout after {self.config.timeout}s"
                self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                
            except Exception as e:
                last_error = str(e)
                self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                await asyncio.sleep(2 ** attempt)
        
        raise Exception(f"LLM request failed after {self.config.max_retries} attempts: {last_error}")

    def _extract_text_from_response(self, response) -> str:
        """
        Extract text from Gemini response, handling both simple and complex responses.

        Args:
            response: Gemini API response object

        Returns:
            Extracted text string

        Raises:
            ValueError: If response cannot be parsed
        """
        # Try the simple text accessor first (for single-part responses)
        try:
            if hasattr(response, 'text') and response.text:
                return response.text
        except ValueError as e:
            # This is expected for multi-part responses
            self.logger.debug(f"Simple text accessor failed (expected for multi-part): {e}")

        # Handle multi-part responses
        if not hasattr(response, 'candidates') or not response.candidates:
            raise ValueError("Response has no candidates")

        if len(response.candidates) == 0:
            raise ValueError("Response candidates list is empty")

        candidate = response.candidates[0]

        # Check if response was blocked by safety filters
        if hasattr(candidate, 'finish_reason'):
            try:
                from google.generativeai.types import FinishReason
                if candidate.finish_reason == FinishReason.SAFETY:
                    self.logger.warning("Response blocked by safety filters")
                    raise ValueError("Response blocked by safety filters")
                elif candidate.finish_reason == FinishReason.RECITATION:
                    self.logger.warning("Response blocked due to recitation")
                    raise ValueError("Response blocked due to recitation")
            except (ImportError, AttributeError):
                # If FinishReason enum not available, continue
                pass

        # Extract text from all parts
        if not hasattr(candidate, 'content') or not candidate.content:
            raise ValueError("Candidate has no content")

        if not hasattr(candidate.content, 'parts') or not candidate.content.parts:
            raise ValueError("Content has no parts")

        # Concatenate all text parts
        text_parts = []
        for part in candidate.content.parts:
            if hasattr(part, 'text') and part.text:
                text_parts.append(part.text)

        if not text_parts:
            raise ValueError("No text found in response parts")

        return ''.join(text_parts)

    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from LLM response, handling markdown code blocks"""
        try:
            # Try direct JSON parse first
            return json.loads(response)
        except json.JSONDecodeError:
            # Look for JSON in markdown code blocks
            import re
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # Look for raw JSON objects
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            self.logger.error(f"Could not extract JSON from response: {response[:200]}")
            raise ValueError("Invalid JSON response from LLM")

    async def get_reconnaissance_recommendation(
        self, 
        target: str, 
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get AI recommendation for reconnaissance phase
        
        Args:
            target: Target URL or IP
            context: Additional context (previous findings, target info)
            
        Returns:
            Dict with recommended actions, techniques, and reasoning
        """
        prompt = f"""You are an AI penetration testing assistant. Analyze the target and recommend reconnaissance actions.

Target: {target}
Context: {json.dumps(context, indent=2)}

Provide a reconnaissance strategy in JSON format:
{{
    "recommended_actions": [
        {{
            "action": "port_scan",
            "command": "nmap -sV target",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "priority": "high",
            "reasoning": "Discover exposed services"
        }}
    ],
    "focus_areas": ["web_services", "databases", "authentication"],
    "risk_assessment": "LOW",
    "estimated_duration": 60
}}

Return ONLY valid JSON, no additional text."""

        try:
            response = await self._generate_with_retry(prompt)
            result = self._extract_json_from_response(response)
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
        """
        Get AI recommendation for enumeration phase
        
        Args:
            target: Target URL or IP
            reconnaissance_findings: Findings from reconnaissance phase
            
        Returns:
            Dict with recommended enumeration actions
        """
        prompt = f"""You are an AI penetration testing assistant. Based on reconnaissance findings, recommend enumeration actions.

Target: {target}
Reconnaissance Findings:
{json.dumps(reconnaissance_findings, indent=2)}

Provide an enumeration strategy in JSON format:
{{
    "recommended_actions": [
        {{
            "action": "enumerate_api_endpoints",
            "technique_id": "T1590",
            "priority": "high",
            "reasoning": "Discovered web API, enumerate endpoints"
        }}
    ],
    "services_to_probe": ["http", "https", "api"],
    "risk_assessment": "LOW",
    "potential_vulnerabilities": ["authentication_bypass", "information_disclosure"]
}}

Return ONLY valid JSON, no additional text."""

        try:
            response = await self._generate_with_retry(prompt)
            result = self._extract_json_from_response(response)
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
        """
        Assess risk level of a discovered vulnerability
        
        Args:
            vulnerability: Vulnerability details (type, severity, description)
            target_context: Additional context about the target environment
            
        Returns:
            Risk level: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
        """
        context_str = json.dumps(target_context, indent=2) if target_context else "None"
        
        prompt = f"""You are a cybersecurity risk assessment expert. Evaluate this vulnerability.

Vulnerability:
{json.dumps(vulnerability, indent=2)}

Target Context:
{context_str}

Consider:
- Exploitability
- Impact on confidentiality, integrity, availability
- Target environment (healthcare, finance, etc.)
- Presence of compensating controls

Respond with ONLY one word: LOW, MEDIUM, HIGH, or CRITICAL"""

        try:
            response = await self._generate_with_retry(prompt)
            risk_level = response.strip().upper()
            
            # Validate response
            if risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                self.logger.info(f"Risk assessed as {risk_level} for {vulnerability.get('type', 'unknown')}")
                return risk_level
            else:
                self.logger.warning(f"Invalid risk level from LLM: {risk_level}")
                return "MEDIUM"  # Safe default
                
        except Exception as e:
            self.logger.error(f"Failed to assess vulnerability risk: {e}")
            return self._get_fallback_risk_assessment(vulnerability)

    async def plan_attack_strategy(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        objectives: List[str]
    ) -> Dict[str, Any]:
        """
        Generate overall attack strategy based on all findings
        
        Args:
            target: Target URL or IP
            findings: All findings from reconnaissance and enumeration
            objectives: Pentesting objectives (e.g., "data_exfiltration", "privilege_escalation")
            
        Returns:
            Dict with attack plan, priorities, and risk assessment
        """
        prompt = f"""You are an expert penetration tester. Create an attack strategy based on findings.

Target: {target}
Objectives: {', '.join(objectives)}

Findings:
{json.dumps(findings[:10], indent=2)}  # Limit to avoid token overflow

Create an attack plan in JSON format:
{{
    "strategy_overview": "Brief description of approach",
    "attack_chain": [
        {{
            "step": 1,
            "action": "exploit_sql_injection",
            "target_vulnerability": "SQL Injection in /api/search",
            "technique_id": "T1190",
            "expected_outcome": "Database access",
            "risk_level": "MEDIUM",
            "prerequisites": []
        }}
    ],
    "success_probability": 0.75,
    "estimated_duration": 300,
    "risks": ["detection by IDS", "account lockout"]
}}

Return ONLY valid JSON, no additional text."""

        try:
            response = await self._generate_with_retry(prompt)
            result = self._extract_json_from_response(response)
            self.logger.info(f"Attack strategy generated for {target}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to plan attack strategy: {e}")
            return self._get_fallback_attack_plan()

    async def get_next_action_recommendation(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get recommendation for the next action to take
        
        Args:
            context: Full operation context (phase, findings, history)
            
        Returns:
            Dict with recommended next action
        """
        prompt = f"""You are an AI penetration testing assistant. Based on the current operation state, recommend the next action.

Operation Context:
{json.dumps(context, indent=2)}

Provide recommendation in JSON format:
{{
    "recommendations": [
        {{
            "action": "exploit_sql_injection",
            "confidence": 0.85,
            "reasoning": "High-confidence SQL injection detected, exploit to gain data access",
            "technique": "T1190",
            "risk_level": "MEDIUM"
        }}
    ],
    "context_analysis": "Brief analysis of current situation",
    "suggested_next_phase": "exploitation"
}}

Return ONLY valid JSON, no additional text."""

        try:
            response = await self._generate_with_retry(prompt)
            result = self._extract_json_from_response(response)
            self.logger.info("Next action recommendation generated")
            return result
        except Exception as e:
            self.logger.error(f"Failed to get next action recommendation: {e}")
            return self._get_fallback_next_action()

    # Fallback methods for when LLM fails
    def _get_fallback_reconnaissance(self) -> Dict[str, Any]:
        """Safe fallback for reconnaissance"""
        return {
            "recommended_actions": [
                {
                    "action": "port_scan",
                    "command": "nmap -sV",
                    "technique_id": "T1046",
                    "technique_name": "Network Service Discovery",
                    "priority": "high",
                    "reasoning": "Basic port scan to discover services"
                }
            ],
            "focus_areas": ["web_services"],
            "risk_assessment": "LOW",
            "estimated_duration": 60
        }

    def _get_fallback_enumeration(self) -> Dict[str, Any]:
        """Safe fallback for enumeration"""
        return {
            "recommended_actions": [
                {
                    "action": "enumerate_web_paths",
                    "technique_id": "T1590",
                    "priority": "medium",
                    "reasoning": "Enumerate common web paths"
                }
            ],
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
            "attack_chain": [
                {
                    "step": 1,
                    "action": "enumerate_endpoints",
                    "technique_id": "T1590",
                    "expected_outcome": "Discover API endpoints",
                    "risk_level": "LOW",
                    "prerequisites": []
                }
            ],
            "success_probability": 0.6,
            "estimated_duration": 180,
            "risks": ["minimal"]
        }

    def _get_fallback_next_action(self) -> Dict[str, Any]:
        """Safe fallback for next action"""
        return {
            "recommendations": [
                {
                    "action": "continue_enumeration",
                    "confidence": 0.7,
                    "reasoning": "Continue systematic enumeration",
                    "technique": "T1590",
                    "risk_level": "LOW"
                }
            ],
            "context_analysis": "Continuing with safe reconnaissance activities",
            "suggested_next_phase": "enumeration"
        }


class MockLLMClient:
    """
    Mock LLM client for testing and development without API calls
    Provides realistic but deterministic responses
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        """Initialize mock LLM client"""
        self.config = config or LLMConfig(api_key="mock", mock_mode=True)
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initialized Mock LLM client (no API calls)")

    async def get_reconnaissance_recommendation(
        self, 
        target: str, 
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Mock reconnaissance recommendation"""
        await asyncio.sleep(0.5)  # Simulate API delay
        return {
            "recommended_actions": [
                {
                    "action": "port_scan",
                    "command": f"nmap -sV {target}",
                    "technique_id": "T1046",
                    "technique_name": "Network Service Discovery",
                    "priority": "high",
                    "reasoning": "Comprehensive port scan to discover all exposed services"
                },
                {
                    "action": "web_discovery",
                    "command": f"whatweb {target}",
                    "technique_id": "T1595",
                    "technique_name": "Active Scanning",
                    "priority": "medium",
                    "reasoning": "Identify web technologies and frameworks"
                }
            ],
            "focus_areas": ["web_services", "api_endpoints", "authentication"],
            "risk_assessment": "LOW",
            "estimated_duration": 90
        }

    async def get_enumeration_recommendation(
        self,
        target: str,
        reconnaissance_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Mock enumeration recommendation"""
        await asyncio.sleep(0.5)
        return {
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
            "potential_vulnerabilities": [
                "authentication_bypass",
                "information_disclosure",
                "api_abuse"
            ]
        }

    async def assess_vulnerability_risk(
        self,
        vulnerability: Dict[str, Any],
        target_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Mock vulnerability risk assessment"""
        await asyncio.sleep(0.3)
        
        # Simple mock logic based on vulnerability type
        vuln_type = vulnerability.get("type", "").lower()
        severity = vulnerability.get("severity", "").upper()
        
        risk_keywords = {
            "sql": "HIGH",
            "injection": "HIGH",
            "authentication": "MEDIUM",
            "xss": "MEDIUM",
            "csrf": "MEDIUM",
            "disclosure": "LOW"
        }
        
        for keyword, risk in risk_keywords.items():
            if keyword in vuln_type:
                return risk
        
        # Fallback to severity mapping
        return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(
            severity, "MEDIUM"
        )

    async def plan_attack_strategy(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        objectives: List[str]
    ) -> Dict[str, Any]:
        """Mock attack strategy"""
        await asyncio.sleep(0.7)
        return {
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
                },
                {
                    "step": 3,
                    "action": "exfiltrate_sensitive_data",
                    "target_vulnerability": "Insufficient access controls",
                    "technique_id": "T1041",
                    "expected_outcome": "Extract patient records",
                    "risk_level": "HIGH",
                    "prerequisites": ["database_access"]
                }
            ],
            "success_probability": 0.78,
            "estimated_duration": 420,
            "risks": [
                "IDS/IPS detection",
                "Account lockout after failed attempts",
                "Incomplete data extraction"
            ]
        }

    async def get_next_action_recommendation(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Mock next action recommendation"""
        await asyncio.sleep(0.4)
        
        recommendations_pool = [
            {
                "action": "exploit_sql_injection",
                "confidence": 0.85,
                "reasoning": "Detected SQL injection vulnerability with high success probability",
                "technique": "T1190",
                "risk_level": "MEDIUM",
            },
            {
                "action": "enumerate_databases",
                "confidence": 0.92,
                "reasoning": "Successful authentication allows database enumeration",
                "technique": "T1046",
                "risk_level": "LOW",
            },
            {
                "action": "test_api_authentication",
                "confidence": 0.88,
                "reasoning": "Multiple API endpoints lack proper authentication",
                "technique": "T1110",
                "risk_level": "LOW",
            },
            {
                "action": "exfiltrate_patient_data",
                "confidence": 0.78,
                "reasoning": "Unauthenticated access to patient records API",
                "technique": "T1041",
                "risk_level": "HIGH",
            },
        ]
        
        return {
            "recommendations": random.sample(recommendations_pool, k=min(2, len(recommendations_pool))),
            "context_analysis": "Target appears to be a healthcare application with multiple security weaknesses",
            "suggested_next_phase": context.get("current_phase", "enumeration")
        }


def create_llm_client(config: LLMConfig) -> LLMClient | MockLLMClient:
    """
    Factory function to create appropriate LLM client
    
    Args:
        config: LLM configuration
        
    Returns:
        LLMClient or MockLLMClient based on configuration and availability
    """
    logger = logging.getLogger(__name__)
    
    if config.mock_mode:
        logger.info("Creating Mock LLM client")
        return MockLLMClient(config)
    
    if not GEMINI_AVAILABLE:
        logger.warning("google-generativeai not available, using Mock LLM client")
        return MockLLMClient(config)
    
    try:
        logger.info(f"Creating real LLM client with model: {config.model}")
        return LLMClient(config)
    except Exception as e:
        logger.error(f"Failed to create real LLM client: {e}")
        logger.warning("Falling back to Mock LLM client")
        return MockLLMClient(config)

