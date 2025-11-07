"""
LLM Integration for MEDUSA AI Pentesting
Provides real AI decision-making via Google Gemini API with fallback to mock responses
"""

import asyncio
import logging
import random
import time
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import json

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    logging.warning("httpx not installed. Install with: pip install httpx")

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    logging.warning("google-generativeai not installed. Install with: pip install google-generativeai")

# Import prompt templates
from .prompts import PromptTemplates


class RiskLevel(str, Enum):
    """Risk levels for pentesting actions"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class LLMConfig:
    """Configuration for LLM client"""
    # Provider selection: "local", "gemini", "mock", or "auto"
    provider: str = "auto"
    
    # API key (for Gemini)
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("GEMINI_API_KEY"))
    
    # Model selection
    model: str = field(default_factory=lambda: os.getenv("MEDUSA_LLM_MODEL", "mistral:7b-instruct"))
    
    # Local LLM settings (Ollama)
    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434"))
    
    # Generation parameters
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout: int = 60  # Increased for local inference
    max_retries: int = 3
    retry_delay: int = 2
    
    # Testing mode
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
                
                if response and response.text:
                    self.logger.debug(f"LLM response received: {len(response.text)} chars")
                    return response.text
                else:
                    self.logger.warning("Empty response from LLM")
                    last_error = "Empty response"
                    
            except asyncio.TimeoutError:
                last_error = f"Request timeout after {self.config.timeout}s"
                self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                
            except Exception as e:
                last_error = str(e)
                self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                await asyncio.sleep(2 ** attempt)
        
        raise Exception(f"LLM request failed after {self.config.max_retries} attempts: {last_error}")

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

    async def prioritize_reconnaissance_targets(
        self,
        amass_findings: List[Dict[str, Any]],
        httpx_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Prioritize targets from reconnaissance for efficient scanning
        
        Integrates Amass subdomain enumeration results with httpx validation
        to build an intelligent prioritized target list for further exploitation.
        
        Args:
            amass_findings: List of findings from Amass subdomain enumeration
            httpx_findings: Optional list of findings from httpx validation
            
        Returns:
            Dict with prioritized targets:
            {
                "prioritized_targets": [
                    {
                        "target": "admin.example.com",
                        "priority": "HIGH|MEDIUM|LOW",
                        "rationale": "Admin panel typically high-value target",
                        "recommended_actions": [
                            {
                                "action": "deep_port_scan",
                                "technique_id": "T1046"
                            }
                        ],
                        "attack_vectors": ["sql_injection", "authentication_bypass"]
                    }
                ],
                "scan_strategy": "Focus areas and approach",
                "estimated_effort": 500,
                "risk_level": "LOW|MEDIUM|HIGH"
            }
        """
        # Combine findings for context
        combined_context = {
            "amass_findings": amass_findings,
            "httpx_findings": httpx_findings or [],
            "total_subdomains": len(amass_findings),
            "live_servers": len(httpx_findings) if httpx_findings else 0,
        }

        prompt = f"""You are an expert penetration tester analyzing reconnaissance data. Your task is to prioritize targets for exploitation based on value and exploitability.

Reconnaissance Data:
{json.dumps(combined_context, indent=2)}

Analyze the targets and provide a prioritization strategy in JSON format:
{{
    "prioritized_targets": [
        {{
            "target": "admin.example.com",
            "priority": "HIGH|MEDIUM|LOW",
            "rationale": "Admin panels are typically high-value targets with significant attack surface",
            "confidence": 0.9,
            "recommended_actions": [
                {{
                    "action": "deep_port_scan",
                    "technique_id": "T1046",
                    "reasoning": "Discover all open ports and services"
                }},
                {{
                    "action": "web_app_scan",
                    "technique_id": "T1595.002",
                    "reasoning": "Test for common web vulnerabilities"
                }}
            ],
            "attack_vectors": ["sql_injection", "authentication_bypass", "api_abuse"],
            "estimated_effort_seconds": 300
        }}
    ],
    "scan_strategy": "Start with HIGH priority targets on ports 80,443,8080-8090. Then move to MEDIUM priority. Save LOW priority for last.",
    "total_estimated_effort": 1500,
    "risk_level": "LOW",
    "early_wins": ["Look for default credentials on admin panels", "Test for information disclosure on API endpoints"]
}}

Prioritization Criteria:
1. Subdomains with "admin", "api", "database", "internal" in name = HIGH
2. Live web servers (especially API endpoints) = MEDIUM
3. Obscure subdomains = LOW
4. Apply risk/effort calculation: High-value targets that are easy to exploit first

Return ONLY valid JSON, no additional text."""

        try:
            response = await self._generate_with_retry(prompt)
            result = self._extract_json_from_response(response)
            self.logger.info(f"Target prioritization generated for {len(amass_findings)} subdomains")
            return result
        except Exception as e:
            self.logger.error(f"Failed to prioritize reconnaissance targets: {e}")
            return self._get_fallback_target_prioritization(amass_findings, httpx_findings)

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

    def _get_fallback_target_prioritization(
        self,
        amass_findings: List[Dict[str, Any]],
        httpx_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Safe fallback for target prioritization using heuristics"""
        # Simple prioritization logic without LLM
        prioritized = []

        # Keywords for HIGH priority
        high_priority_keywords = ["admin", "api", "database", "internal", "management", "backend"]
        # Keywords for MEDIUM priority  
        medium_priority_keywords = ["app", "service", "test", "staging", "dev"]

        for finding in amass_findings:
            subdomain = finding.get("subdomain", "").lower()
            priority = "LOW"

            # Check for HIGH priority keywords
            for keyword in high_priority_keywords:
                if keyword in subdomain:
                    priority = "HIGH"
                    break

            # Check for MEDIUM priority keywords (if not already HIGH)
            if priority == "LOW":
                for keyword in medium_priority_keywords:
                    if keyword in subdomain:
                        priority = "MEDIUM"
                        break

            # If it's a live server (in httpx_findings), boost priority
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
                "rationale": f"Heuristic prioritization based on subdomain characteristics",
                "confidence": 0.6,
                "recommended_actions": [
                    {
                        "action": "port_scan",
                        "technique_id": "T1046"
                    }
                ],
                "attack_vectors": ["sql_injection", "authentication_bypass"],
                "estimated_effort_seconds": 300 if priority == "HIGH" else (200 if priority == "MEDIUM" else 100)
            })

        # Sort by priority
        priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        prioritized.sort(key=lambda x: priority_order.get(x["priority"], 3))

        return {
            "prioritized_targets": prioritized[:20],  # Limit to top 20
            "scan_strategy": "Scan HIGH priority first (admin/api panels), then MEDIUM (other live services), finally LOW priority",
            "total_estimated_effort": sum(t["estimated_effort_seconds"] for t in prioritized[:20]),
            "risk_level": "LOW",
            "early_wins": ["Admin panels often have default credentials", "API endpoints frequently have information disclosure"]
        }


class LocalLLMClient:
    """
    Local LLM client using Ollama for inference
    
    Provides unlimited, private AI decision-making with no API costs.
    Supports Mistral-7B-Instruct and other Ollama models.
    """
    
    def __init__(self, config: LLMConfig):
        """Initialize Local LLM client with Ollama"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        if not HTTPX_AVAILABLE:
            self.logger.error("httpx package not installed")
            raise ImportError(
                "httpx is required for LocalLLMClient. Install with: pip install httpx"
            )
        
        self.base_url = config.ollama_url
        self.model = config.model
        
        # Initialize HTTP client
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout, connect=10.0),
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )
        
        self.logger.info(f"Initialized Local LLM client with model: {self.model} at {self.base_url}")
    
    async def _check_ollama_health(self) -> bool:
        """Check if Ollama server is running and responsive"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/tags",
                timeout=5.0
            )
            return response.status_code == 200
        except Exception as e:
            self.logger.debug(f"Ollama health check failed: {e}")
            return False
    
    async def _generate_with_retry(self, prompt: str, force_json: bool = True) -> str:
        """Generate response using local Ollama API with retry logic"""
        last_error = None
        
        for attempt in range(self.config.max_retries):
            start_time = time.time()
            
            try:
                self.logger.debug(f"Local LLM request attempt {attempt + 1}/{self.config.max_retries}")
                
                # Build Ollama API payload
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.config.temperature,
                        "num_predict": self.config.max_tokens,
                        "top_p": 0.9,
                        "top_k": 40,
                    }
                }
                
                # Enable JSON mode if requested
                if force_json:
                    payload["format"] = "json"
                
                # Make request to Ollama
                response = await self.client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=self.config.timeout
                )
                response.raise_for_status()
                
                result = response.json()
                response_text = result.get("response", "")
                
                if not response_text:
                    last_error = "Empty response from Ollama"
                    self.logger.warning(last_error)
                    continue
                
                duration = time.time() - start_time
                self.logger.debug(f"Local LLM response received: {len(response_text)} chars in {duration:.2f}s")
                
                return response_text
                
            except httpx.TimeoutException:
                last_error = f"Request timeout after {self.config.timeout}s"
                self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
                    
            except httpx.HTTPStatusError as e:
                error_msg = f"HTTP {e.response.status_code}"
                try:
                    error_details = e.response.json()
                    error_msg += f": {error_details.get('error', e.response.text)}"
                except:
                    error_msg += f": {e.response.text[:200]}"
                
                if e.response.status_code in [404, 502]:
                    last_error = "Ollama server not reachable. Ensure Ollama is running: 'ollama serve'"
                    self.logger.error(last_error)
                    raise Exception(last_error)
                
                if "model" in error_msg.lower() and "not found" in error_msg.lower():
                    last_error = f"Model '{self.model}' not found. Pull it first: 'ollama pull {self.model}'"
                    self.logger.error(last_error)
                    raise Exception(last_error)
                
                last_error = f"Local LLM error: {error_msg}"
                self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
                    
            except Exception as e:
                last_error = f"Local LLM unexpected error: {str(e)}"
                self.logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
        
        raise Exception(f"Local LLM request failed after {self.config.max_retries} attempts: {last_error}")
    
    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from LLM response"""
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
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
            raise ValueError("Invalid JSON response from Local LLM")
    
    async def get_reconnaissance_recommendation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get AI recommendation for reconnaissance phase"""
        prompt = PromptTemplates.reconnaissance_strategy(target, context)
        try:
            response = await self._generate_with_retry(prompt, force_json=True)
            result = self._extract_json_from_response(response)
            self.logger.info(f"Reconnaissance recommendation generated for {target}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to get reconnaissance recommendation: {e}")
            return self._get_fallback_reconnaissance()
    
    async def get_enumeration_recommendation(self, target: str, reconnaissance_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get AI recommendation for enumeration phase"""
        prompt = PromptTemplates.enumeration_strategy(target, reconnaissance_findings)
        try:
            response = await self._generate_with_retry(prompt, force_json=True)
            result = self._extract_json_from_response(response)
            self.logger.info(f"Enumeration recommendation generated for {target}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to get enumeration recommendation: {e}")
            return self._get_fallback_enumeration()
    
    async def assess_vulnerability_risk(self, vulnerability: Dict[str, Any], target_context: Optional[Dict[str, Any]] = None) -> str:
        """Assess risk level of a discovered vulnerability"""
        prompt = PromptTemplates.vulnerability_risk_assessment(vulnerability, target_context)
        try:
            response = await self._generate_with_retry(prompt, force_json=False)
            risk_level = response.strip().upper()
            for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if level in risk_level:
                    risk_level = level
                    break
            if risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                self.logger.info(f"Risk assessed as {risk_level} for {vulnerability.get('type', 'unknown')}")
                return risk_level
            else:
                self.logger.warning(f"Invalid risk level from LLM: {risk_level}")
                return "MEDIUM"
        except Exception as e:
            self.logger.error(f"Failed to assess vulnerability risk: {e}")
            return self._get_fallback_risk_assessment(vulnerability)
    
    async def plan_attack_strategy(self, target: str, findings: List[Dict[str, Any]], objectives: List[str]) -> Dict[str, Any]:
        """Generate overall attack strategy based on all findings"""
        prompt = PromptTemplates.attack_strategy_planning(target, findings, objectives)
        try:
            response = await self._generate_with_retry(prompt, force_json=True)
            result = self._extract_json_from_response(response)
            self.logger.info(f"Attack strategy generated for {target}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to plan attack strategy: {e}")
            return self._get_fallback_attack_plan()
    
    async def get_next_action_recommendation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get recommendation for the next action to take"""
        prompt = PromptTemplates.next_action_recommendation(context)
        try:
            response = await self._generate_with_retry(prompt, force_json=True)
            result = self._extract_json_from_response(response)
            self.logger.info("Next action recommendation generated")
            return result
        except Exception as e:
            self.logger.error(f"Failed to get next action recommendation: {e}")
            return self._get_fallback_next_action()
    
    def _get_fallback_reconnaissance(self) -> Dict[str, Any]:
        """Safe fallback for reconnaissance"""
        return {
            "recommended_actions": [{
                "action": "port_scan", "command": "nmap -sV",
                "technique_id": "T1046", "technique_name": "Network Service Discovery",
                "priority": "high", "reasoning": "Basic port scan to discover services"
            }],
            "focus_areas": ["web_services"], "risk_assessment": "LOW", "estimated_duration": 60
        }
    
    def _get_fallback_enumeration(self) -> Dict[str, Any]:
        """Safe fallback for enumeration"""
        return {
            "recommended_actions": [{
                "action": "enumerate_web_paths", "technique_id": "T1590",
                "priority": "medium", "reasoning": "Enumerate common web paths"
            }],
            "services_to_probe": ["http", "https"], "risk_assessment": "LOW",
            "potential_vulnerabilities": ["information_disclosure"]
        }
    
    def _get_fallback_risk_assessment(self, vulnerability: Dict[str, Any]) -> str:
        """Safe fallback for risk assessment"""
        severity = vulnerability.get("severity", "").upper()
        risk_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        return risk_map.get(severity, "MEDIUM")
    
    def _get_fallback_attack_plan(self) -> Dict[str, Any]:
        """Safe fallback for attack planning"""
        return {
            "strategy_overview": "Conservative approach focusing on information gathering",
            "attack_chain": [{
                "step": 1, "action": "enumerate_endpoints", "technique_id": "T1590",
                "expected_outcome": "Discover API endpoints", "risk_level": "LOW", "prerequisites": []
            }],
            "success_probability": 0.6, "estimated_duration": 180, "risks": ["minimal"]
        }
    
    def _get_fallback_next_action(self) -> Dict[str, Any]:
        """Safe fallback for next action"""
        return {
            "recommendations": [{
                "action": "continue_enumeration", "confidence": 0.7,
                "reasoning": "Continue systematic enumeration", "technique": "T1590", "risk_level": "LOW"
            }],
            "context_analysis": "Continuing with safe reconnaissance activities",
            "suggested_next_phase": "enumeration"
        }
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()



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

    async def prioritize_reconnaissance_targets(
        self,
        amass_findings: List[Dict[str, Any]],
        httpx_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Prioritize targets from reconnaissance for efficient scanning
        
        Mock implementation using heuristic prioritization
        
        Args:
            amass_findings: List of findings from Amass subdomain enumeration
            httpx_findings: Optional list of findings from httpx validation
            
        Returns:
            Dict with prioritized targets
        """
        await asyncio.sleep(0.3)  # Simulate processing delay
        
        # Use heuristic prioritization (same as fallback)
        prioritized = []
        
        # Keywords for HIGH priority
        high_priority_keywords = ["admin", "api", "database", "internal", "management", "backend"]
        # Keywords for MEDIUM priority  
        medium_priority_keywords = ["app", "service", "test", "staging", "dev"]
        
        for finding in amass_findings:
            subdomain = finding.get("subdomain", "").lower()
            priority = "LOW"
            
            # Check for HIGH priority keywords
            for keyword in high_priority_keywords:
                if keyword in subdomain:
                    priority = "HIGH"
                    break
            
            # Check for MEDIUM priority keywords (if not already HIGH)
            if priority == "LOW":
                for keyword in medium_priority_keywords:
                    if keyword in subdomain:
                        priority = "MEDIUM"
                        break
            
            # If it's a live server (in httpx_findings), boost priority
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
                "rationale": f"Heuristic prioritization based on subdomain characteristics",
                "confidence": 0.6,
                "recommended_actions": [
                    {
                        "action": "port_scan",
                        "technique_id": "T1046"
                    }
                ],
                "attack_vectors": ["sql_injection", "authentication_bypass"],
                "estimated_effort_seconds": 300 if priority == "HIGH" else (200 if priority == "MEDIUM" else 100)
            })
        
        # Sort by priority
        priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        prioritized.sort(key=lambda x: priority_order.get(x["priority"], 3))
        
        return {
            "prioritized_targets": prioritized[:20],  # Limit to top 20
            "scan_strategy": "Scan HIGH priority first (admin/api panels), then MEDIUM (other live services), finally LOW priority",
            "total_estimated_effort": sum(t["estimated_effort_seconds"] for t in prioritized[:20]),
            "risk_level": "LOW",
            "early_wins": ["Admin panels often have default credentials", "API endpoints frequently have information disclosure"]
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


def create_llm_client(config: LLMConfig):
    """
    Factory function to create appropriate LLM client

    Priority order:
    1. Mock mode (for testing)
    2. User-specified provider
    3. Auto-detect: Local (Ollama) -> Gemini -> Mock

    Args:
        config: LLM configuration

    Returns:
        LLMClient, LocalLLMClient, or MockLLMClient based on configuration
    """
    logger = logging.getLogger(__name__)

    # Mock mode for testing
    if config.mock_mode:
        logger.info("Using MockLLMClient (testing mode)")
        return MockLLMClient(config)

    # User explicitly specified provider
    if config.provider == "local":
        if not HTTPX_AVAILABLE:
            logger.error("httpx not installed, required for local LLM")
            logger.warning("Falling back to Mock LLM client")
            return MockLLMClient(config)

        try:
            logger.info(f"Using LocalLLMClient with model: {config.model}")
            return LocalLLMClient(config)
        except Exception as e:
            logger.error(f"Failed to create Local LLM client: {e}")
            logger.warning("Falling back to Mock LLM client")
            return MockLLMClient(config)

    elif config.provider == "gemini":
        if not GEMINI_AVAILABLE:
            logger.error("Gemini API requested but google-generativeai not installed")
            logger.warning("Install with: pip install google-generativeai")
            logger.warning("Falling back to Mock LLM client")
            return MockLLMClient(config)

        if not config.api_key:
            logger.error("Gemini API key required")
            logger.warning("Set GEMINI_API_KEY environment variable")
            logger.warning("Falling back to Mock LLM client")
            return MockLLMClient(config)

        try:
            logger.info("Using GeminiClient (Google Gemini API)")
            return LLMClient(config)
        except Exception as e:
            logger.error(f"Failed to create Gemini client: {e}")
            logger.warning("Falling back to Mock LLM client")
            return MockLLMClient(config)

    # Auto-detect best available option
    elif config.provider == "auto":
        # Try local first (if Ollama is available)
        if HTTPX_AVAILABLE:
            try:
                local_client = LocalLLMClient(config)
                # Quick health check
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                try:
                    is_healthy = loop.run_until_complete(local_client._check_ollama_health())
                    if is_healthy:
                        logger.info("Auto-detected: Using LocalLLMClient (Ollama running)")
                        return local_client
                except:
                    pass
            except Exception as e:
                logger.debug(f"Local LLM unavailable: {e}")

        # Fall back to Gemini
        if GEMINI_AVAILABLE and config.api_key:
            try:
                logger.info("Auto-detected: Using GeminiClient")
                return LLMClient(config)
            except Exception as e:
                logger.debug(f"Gemini client failed: {e}")

        # Last resort: Mock mode
        logger.warning(
            "No LLM available. Using MockLLMClient.\n"
            "To use real AI:\n"
            "  1. Install Ollama: curl -fsSL https://ollama.com/install.sh | sh\n"
            "  2. Pull model: ollama pull mistral:7b-instruct\n"
            "  3. Or set GEMINI_API_KEY for Google Gemini"
        )
        return MockLLMClient(config)

    else:
        logger.error(f"Unknown provider: {config.provider}")
        logger.warning("Valid providers: 'local', 'gemini', 'mock', 'auto'")
        return MockLLMClient(config)

