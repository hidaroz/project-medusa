"""
LLM Integration for MEDUSA AI Pentesting
Provides real AI decision-making via Google Gemini API with fallback to mock responses
"""

import asyncio
import logging
import random
import time
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
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
    """
    Configuration for LLM client.
    
    Supports multiple providers:
    - local: Ollama-hosted models (Mistral, Llama, Phi, etc.)
    - gemini: Google Gemini API
    - mock: Testing mode with deterministic responses
    - auto: Auto-detect best available option
    """
    
    # Provider selection
    provider: str = "auto"  # "local", "gemini", "mock", or "auto"
    
    # Local LLM settings (Ollama)
    ollama_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434")
    )
    model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "mistral:7b-instruct")
    )
    
    # Gemini API settings (optional)
    api_key: str = field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "")
    )
    gemini_model: str = "gemini-pro-latest"
    
    # Generation parameters
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout: int = 60  # Increased for local models
    max_retries: int = 3
    retry_delay: int = 2
    
    # Testing mode
    mock_mode: bool = False
    
    def __post_init__(self):
        """Validate configuration after initialization"""
        valid_providers = ["local", "gemini", "mock", "auto"]
        if self.provider not in valid_providers:
            raise ValueError(
                f"Invalid provider '{self.provider}'. "
                f"Must be one of: {valid_providers}"
            )
        
        if self.temperature < 0.0 or self.temperature > 1.0:
            raise ValueError("temperature must be between 0.0 and 1.0")
        
        if self.max_tokens < 1:
            raise ValueError("max_tokens must be positive")


class LLMMetrics:
    """Track LLM performance metrics"""

    def __init__(self):
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_tokens_used = 0
        self.total_response_time = 0.0
        self.errors: List[Dict[str, Any]] = []

    def record_request(
        self,
        success: bool,
        response_time: float,
        tokens_used: int = 0,
        error: Optional[str] = None
    ):
        """Record metrics for a request"""
        self.total_requests += 1

        if success:
            self.successful_requests += 1
            self.total_tokens_used += tokens_used
            self.total_response_time += response_time
        else:
            self.failed_requests += 1
            self.errors.append({
                "timestamp": datetime.now().isoformat(),
                "error": error,
                "response_time": response_time
            })

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics"""
        avg_response_time = (
            self.total_response_time / self.successful_requests
            if self.successful_requests > 0 else 0
        )

        success_rate = (
            self.successful_requests / self.total_requests * 100
            if self.total_requests > 0 else 0
        )

        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": f"{success_rate:.2f}%",
            "total_tokens_used": self.total_tokens_used,
            "avg_response_time": f"{avg_response_time:.2f}s",
            "recent_errors": self.errors[-5:]  # Last 5 errors
        }


class LLMError(Exception):
    """Custom exception for LLM errors"""
    pass


class LLMClient:
    """
    Real LLM client using Google Gemini API for AI-powered pentesting decisions
    """

    def __init__(self, config: LLMConfig):
        """Initialize LLM client with configuration"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.metrics = LLMMetrics()

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
        """Generate response with retry logic and metrics tracking"""
        start_time = time.time()
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

                if response and response.text:
                    response_time = time.time() - start_time
                    tokens_used = len(response.text.split())  # Approximate token count

                    # Record successful request
                    self.metrics.record_request(
                        success=True,
                        response_time=response_time,
                        tokens_used=tokens_used
                    )

                    self.logger.debug(f"LLM response received: {len(response.text)} chars in {response_time:.2f}s")
                    return response.text
                else:
                    self.logger.warning("Empty response from LLM")
                    last_error = "Empty response"

            except asyncio.TimeoutError:
                last_error = f"Request timeout after {self.config.timeout}s"
                self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")

            except Exception as e:
                last_error = str(e)
                error_lower = str(e).lower()

                # Check for specific errors that shouldn't be retried
                if "quota" in error_lower or "rate" in error_lower:
                    response_time = time.time() - start_time
                    self.metrics.record_request(
                        success=False,
                        response_time=response_time,
                        error="API quota exceeded"
                    )
                    raise LLMError(
                        "API quota exceeded. Please check your usage at: https://aistudio.google.com/"
                    )
                elif "invalid" in error_lower and "key" in error_lower:
                    response_time = time.time() - start_time
                    self.metrics.record_request(
                        success=False,
                        response_time=response_time,
                        error="Invalid API key"
                    )
                    raise LLMError(
                        "Invalid API key. Please run 'medusa setup --force' to reconfigure"
                    )

                self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")

            # Wait before retry (exponential backoff)
            if attempt < self.config.max_retries - 1:
                delay = self.config.retry_delay * (2 ** attempt)
                self.logger.debug(f"Waiting {delay}s before retry...")
                await asyncio.sleep(delay)

        # All retries failed
        response_time = time.time() - start_time
        self.metrics.record_request(
            success=False,
            response_time=response_time,
            error=last_error
        )

        raise LLMError(
            f"LLM request failed after {self.config.max_retries} attempts. Last error: {last_error}"
        )

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

    async def parse_natural_language_command(
        self,
        user_input: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Parse natural language command from interactive mode

        Args:
            user_input: The user's natural language input
            context: Current operation context

        Returns:
            Dict with parsed command and parameters
        """
        prompt = f"""You are an AI assistant that translates natural language commands into structured pentesting actions.

User Command: "{user_input}"
Current Context: {json.dumps(context, indent=2)}

Parse the command and respond with JSON:
{{
    "understanding": "Brief explanation of what the user wants",
    "confidence": 0.90,
    "action": "port_scan",
    "parameters": {{
        "target": "localhost",
        "ports": "1-1000"
    }},
    "risk_level": "LOW",
    "needs_approval": false,
    "clarification_needed": false,
    "clarification_question": null
}}

If the command is ambiguous (confidence < 0.7), set clarification_needed=true and provide a question.

Supported actions:
- port_scan: Scan for open ports
- web_scan: Scan web application
- test_sqli: Test for SQL injection
- test_xss: Test for XSS
- enumerate_dirs: Enumerate directories
- show_findings: Display findings
- help: Show help
- status: Show status

IMPORTANT: Respond ONLY with valid JSON, no additional text."""

        try:
            response = await self._generate_with_retry(prompt)
            result = self._extract_json_from_response(response)
            self.logger.info(f"Parsed command: {user_input} -> {result.get('action', 'unknown')}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to parse command: {e}")
            return {
                "understanding": f"Failed to parse: {user_input}",
                "confidence": 0.0,
                "action": "unknown",
                "parameters": {},
                "risk_level": "LOW",
                "needs_approval": True,
                "clarification_needed": True,
                "clarification_question": "I couldn't understand that command. Could you please rephrase it?"
            }

    def get_metrics(self) -> Dict[str, Any]:
        """Get LLM performance metrics"""
        return self.metrics.get_stats()


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


class LocalLLMClient:
    """
    Local LLM client using Ollama for offline inference.
    
    Provides unlimited inference with zero API costs by running
    quantized models (Mistral-7B-Instruct) locally via Ollama.
    
    Advantages over Gemini API:
    - No rate limits or daily quotas
    - Zero ongoing costs
    - Complete data privacy
    - Offline capability
    - Predictable performance
    
    Trade-offs:
    - Slower inference (5-20s vs 1-2s for Gemini)
    - Slightly lower quality responses (acceptable for pentesting)
    - Requires local installation (Ollama)
    """
    
    def __init__(self, config: LLMConfig):
        """Initialize LocalLLMClient with configuration"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.metrics = LLMMetrics()
        self.base_url = config.ollama_url
        self.model = config.model
        
        # Import httpx only when needed (already in requirements)
        try:
            import httpx
            self.client = httpx.AsyncClient(
                timeout=config.timeout,
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
            )
        except ImportError:
            raise ImportError(
                "httpx is required for LocalLLMClient. "
                "Install with: pip install httpx"
            )
        
        self.logger.info(f"Initialized LocalLLMClient with model: {self.model}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup"""
        await self.client.aclose()
    
    async def _check_ollama_health(self) -> bool:
        """
        Check if Ollama server is running and responsive.
        
        Returns:
            bool: True if Ollama is healthy and model is available, False otherwise
        """
        try:
            response = await self.client.get(f"{self.base_url}/api/tags", timeout=5.0)
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m['name'] for m in models]
                
                # Check if our model is available
                if self.model not in model_names:
                    self.logger.warning(
                        f"Model '{self.model}' not found in Ollama. "
                        f"Available models: {model_names}"
                    )
                    return False
                
                return True
            return False
        except Exception as e:
            self.logger.debug(f"Ollama health check failed: {e}")
            return False
    
    async def _generate_with_retry(
        self,
        prompt: str,
        force_json: bool = True,
        temperature_override: Optional[float] = None
    ) -> str:
        """
        Generate response using local Ollama API with retry logic.
        
        Args:
            prompt: The prompt to send to the model
            force_json: Enable JSON mode (constrains output to valid JSON)
            temperature_override: Override config temperature for this request
        
        Returns:
            str: Generated text response
        
        Raises:
            LLMError: If generation fails after all retries
        """
        
        # Build Ollama API payload
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,  # Get complete response (not streaming)
            "options": {
                "temperature": temperature_override or self.config.temperature,
                "num_predict": self.config.max_tokens,
                "top_p": 0.9,
                "top_k": 40,
                "repeat_penalty": 1.1,  # Reduce repetition
            }
        }
        
        # Enable JSON mode if requested (guarantees valid JSON output)
        if force_json:
            payload["format"] = "json"
        
        last_error = None
        
        for attempt in range(self.config.max_retries):
            start_time = time.time()
            
            try:
                import httpx
                response = await self.client.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                )
                response.raise_for_status()
                
                result = response.json()
                response_text = result.get("response", "")
                
                if not response_text:
                    raise LLMError("Ollama returned empty response")
                
                # Update metrics
                duration = time.time() - start_time
                self.metrics.total_requests += 1
                self.metrics.successful_requests += 1
                self.metrics.total_response_time += duration
                
                # Estimate token usage (Ollama doesn't provide exact counts)
                # Rough estimate: ~4 characters per token
                estimated_tokens = (len(prompt) + len(response_text)) // 4
                self.metrics.total_tokens_used += estimated_tokens
                
                self.logger.debug(
                    f"LLM generation completed in {duration:.2f}s "
                    f"(~{estimated_tokens} tokens)"
                )
                
                return response_text
                
            except httpx.TimeoutException:
                last_error = f"Request timeout after {self.config.timeout}s"
                self.logger.warning(f"Attempt {attempt + 1}/{self.config.max_retries}: {last_error}")
                
                if attempt == self.config.max_retries - 1:
                    self.metrics.failed_requests += 1
                    self.metrics.errors.append({
                        "timestamp": datetime.now().isoformat(),
                        "error": last_error,
                        "attempt": attempt + 1
                    })
                    raise LLMError(
                        f"Local LLM timeout after {self.config.max_retries} attempts. "
                        f"Try increasing timeout in config or using a smaller/faster model."
                    )
                
                # Exponential backoff
                await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
                
            except httpx.HTTPStatusError as e:
                error_msg = f"HTTP {e.response.status_code}"
                
                # Try to get detailed error message
                try:
                    error_detail = e.response.json().get('error', '')
                    error_msg = f"{error_msg}: {error_detail}"
                except:
                    error_msg = f"{error_msg}: {e.response.text[:200]}"
                
                # Ollama not running
                if e.response.status_code == 404 or "connection" in error_msg.lower():
                    raise LLMError(
                        "Cannot connect to Ollama server. "
                        "Ensure Ollama is running:\n"
                        "  Linux/Mac: 'ollama serve'\n"
                        "  Windows: Ollama should start automatically\n"
                        f"  Expected URL: {self.base_url}"
                    )
                
                # Model not found
                if "model" in error_msg.lower() and "not found" in error_msg.lower():
                    raise LLMError(
                        f"Model '{self.model}' not found in Ollama.\n"
                        f"Pull it first: 'ollama pull {self.model}'\n"
                        f"Or check available models: 'ollama list'"
                    )
                
                last_error = error_msg
                self.logger.error(f"Ollama API error: {error_msg}")
                
                self.metrics.failed_requests += 1
                self.metrics.errors.append({
                    "timestamp": datetime.now().isoformat(),
                    "error": error_msg,
                    "attempt": attempt + 1
                })
                
                raise LLMError(f"Local LLM API error: {error_msg}")
                
            except Exception as e:
                last_error = str(e)
                self.logger.error(f"Unexpected error in LLM generation: {e}", exc_info=True)
                
                self.metrics.failed_requests += 1
                self.metrics.errors.append({
                    "timestamp": datetime.now().isoformat(),
                    "error": last_error,
                    "attempt": attempt + 1
                })
                
                if attempt == self.config.max_retries - 1:
                    raise LLMError(f"Local LLM unexpected error: {e}")
                
                await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
    
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
        Generate AI-powered reconnaissance strategy for target.
        
        Returns JSON with recommended_actions, focus_areas, risk_assessment.
        """
        from medusa.core.prompts import MistralPrompts
        
        prompt = MistralPrompts.reconnaissance_strategy(target, context)
        response = await self._generate_with_retry(prompt, force_json=True)
        return self._extract_json_from_response(response)
    
    async def get_enumeration_recommendation(
        self,
        target: str,
        reconnaissance_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate enumeration strategy based on reconnaissance results.
        
        Returns JSON with enumeration actions prioritized by findings.
        """
        from medusa.core.prompts import MistralPrompts
        
        prompt = MistralPrompts.enumeration_strategy(target, reconnaissance_findings)
        response = await self._generate_with_retry(prompt, force_json=True)
        return self._extract_json_from_response(response)
    
    async def assess_vulnerability_risk(
        self,
        vulnerability: Dict[str, Any],
        target_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Assess risk level of a vulnerability: LOW, MEDIUM, HIGH, or CRITICAL.
        
        Considers exploitability, impact, and target environment context.
        """
        from medusa.core.prompts import MistralPrompts
        
        prompt = MistralPrompts.vulnerability_risk_assessment(vulnerability, target_context)
        
        # Don't force JSON for this one - we want a single word response
        response = await self._generate_with_retry(prompt, force_json=False, temperature_override=0.3)
        
        # Extract risk level
        risk_level = response.strip().upper()
        
        # Validate it's a known risk level
        valid_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for level in valid_levels:
            if level in risk_level:
                return level
        
        # Default to MEDIUM if unclear
        self.logger.warning(f"Could not parse risk level from: {response}. Defaulting to MEDIUM")
        return "MEDIUM"
    
    async def plan_attack_strategy(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        objectives: List[str]
    ) -> Dict[str, Any]:
        """
        Generate multi-step attack chain strategy.
        
        Returns JSON with strategy_overview and attack_chain steps.
        """
        from medusa.core.prompts import MistralPrompts
        
        prompt = MistralPrompts.attack_strategy_planning(target, findings, objectives)
        response = await self._generate_with_retry(prompt, force_json=True)
        return self._extract_json_from_response(response)
    
    async def parse_natural_language_command(
        self,
        user_input: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Parse natural language command into structured action.
        
        Example: "scan the web server" -> {"action": "web_scan", "target": "..."}
        """
        from medusa.core.prompts import MistralPrompts
        
        prompt = MistralPrompts.natural_language_command_parsing(user_input, context)
        response = await self._generate_with_retry(prompt, force_json=True)
        return self._extract_json_from_response(response)
    
    async def get_next_action_recommendation(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get recommendation for the next action to take.
        
        Args:
            context: Full operation context (phase, findings, history)
            
        Returns:
            Dict with recommended next action
        """
        from medusa.core.prompts import MistralPrompts
        
        prompt = MistralPrompts.next_action_recommendation(context)
        response = await self._generate_with_retry(prompt, force_json=True)
        return self._extract_json_from_response(response)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get LLM performance metrics"""
        return self.metrics.get_stats()


def create_llm_client(config: LLMConfig) -> LLMClient | MockLLMClient | LocalLLMClient:
    """
    Factory function to create appropriate LLM client based on configuration.
    
    Priority order:
    1. Mock mode (if explicitly enabled) - for testing
    2. User-specified provider - honor user's explicit choice
    3. Auto-detect - try local first, then Gemini, then mock
    
    Args:
        config: LLM configuration
    
    Returns:
        BaseLLMClient instance (LocalLLMClient, LLMClient, or MockLLMClient)
    
    Raises:
        LLMError: If specified provider unavailable
    """
    
    logger = logging.getLogger(__name__)
    
    # Mock mode for testing
    if config.mock_mode:
        logger.info("Using MockLLMClient (testing mode)")
        return MockLLMClient(config)
    
    # User explicitly specified provider
    if config.provider == "local":
        logger.info(f"Using LocalLLMClient with model: {config.model}")
        client = LocalLLMClient(config)
        
        # Verify Ollama is available
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        try:
            is_healthy = loop.run_until_complete(client._check_ollama_health())
            if not is_healthy:
                raise LLMError(
                    f"Ollama server not available or model '{config.model}' not found.\n"
                    f"Please ensure:\n"
                    f"  1. Ollama is running: 'ollama serve'\n"
                    f"  2. Model is pulled: 'ollama pull {config.model}'\n"
                    f"  3. Server is accessible at: {config.ollama_url}"
                )
        except Exception as e:
            if isinstance(e, LLMError):
                raise
            raise LLMError(f"Local LLM initialization failed: {e}")
        
        return client
    
    elif config.provider == "gemini":
        if not GEMINI_AVAILABLE:
            raise LLMError(
                "Gemini API requested but google-generativeai not installed.\n"
                "Install with: pip install google-generativeai"
            )
        if not config.api_key:
            raise LLMError(
                "Gemini API key required.\n"
                "Set GEMINI_API_KEY environment variable or provide in config."
            )
        logger.info(f"Using GeminiClient (Google Gemini API): {config.gemini_model}")
        return LLMClient(config)
    
    elif config.provider == "mock":
        logger.info("Using MockLLMClient (explicit mock mode)")
        return MockLLMClient(config)
    
    # Auto-detect best available option
    elif config.provider == "auto":
        logger.info("Auto-detecting best available LLM provider...")
        
        # Try local first (preferred for unlimited usage)
        try:
            client = LocalLLMClient(config)
            
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            if loop.run_until_complete(client._check_ollama_health()):
                logger.info("✅ Auto-detected: Using LocalLLMClient (Ollama)")
                return client
            else:
                logger.debug("Local LLM not available, trying Gemini...")
        except Exception as e:
            logger.debug(f"Local LLM check failed: {e}")
        
        # Fall back to Gemini (if API key available)
        if GEMINI_AVAILABLE and config.api_key:
            logger.info("✅ Auto-detected: Using GeminiClient (Google Gemini API)")
            logger.warning(
                "Using Gemini API. Note: Free tier has rate limits.\n"
                "Consider installing Ollama for unlimited usage: https://ollama.com"
            )
            return LLMClient(config)
        
        # Last resort: Mock mode
        logger.warning(
            "⚠️  No LLM available. Using MockLLMClient.\n"
            "For real AI capabilities, either:\n"
            "  - Install Ollama: curl -fsSL https://ollama.com/install.sh | sh\n"
            "  - Or set GEMINI_API_KEY environment variable"
        )
        return MockLLMClient(config)
    
    else:
        raise LLMError(f"Unknown provider: {config.provider}")

