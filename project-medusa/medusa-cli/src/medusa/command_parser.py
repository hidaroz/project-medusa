"""
Command Parser for MEDUSA Interactive Shell
Parses natural language commands using LLM and maintains context
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from medusa.core.llm import LLMClient

logger = logging.getLogger(__name__)


class CommandParser:
    """
    Parse natural language commands using LLM

    Examples:
    - "scan the target for open ports" → {action: "port_scan", target: "..."}
    - "check for SQL injection in the login form" → {action: "sqli_test", target: "...", param: "..."}
    - "what vulnerabilities did we find?" → {action: "show_findings", filter: "vulnerabilities"}
    """

    def __init__(self, llm_client: LLMClient, target: Optional[str] = None):
        """
        Initialize command parser

        Args:
            llm_client: LLM client for parsing commands
            target: Default target for operations
        """
        self.llm_client = llm_client
        self.command_history: List[Dict[str, Any]] = []
        self.context: Dict[str, Any] = {
            "target": target,
            "phase": "reconnaissance",
            "findings": [],
            "last_action": None,
            "session_start": datetime.now().isoformat()
        }

    async def parse(self, user_input: str) -> Dict[str, Any]:
        """
        Parse user input into structured command

        Args:
            user_input: Natural language command from user

        Returns:
            {
                "action": str,  # e.g., "port_scan", "sqli_test", "show_findings"
                "target": str,
                "parameters": Dict,
                "confidence": float,
                "needs_approval": bool,
                "clarification": Optional[str]
            }
        """
        try:
            logger.debug(f"Parsing command: {user_input}")

            # Build prompt with context
            prompt = self._build_parse_prompt(user_input)

            # Get LLM to parse command (use internal method to get raw response)
            response = await self._parse_with_llm(prompt)

            # Parse JSON response
            try:
                parsed = self._extract_json(response)
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(f"Failed to parse LLM response as JSON: {e}")
                # Return a fallback response
                return self._get_fallback_parse(user_input)

            # Validate parsed command
            parsed = self._validate_and_enrich(parsed, user_input)

            # Update context
            self._update_context(parsed)

            # Add to history
            self.command_history.append({
                "timestamp": datetime.now().isoformat(),
                "input": user_input,
                "parsed": parsed
            })

            logger.info(f"Parsed command: {parsed.get('action')} (confidence: {parsed.get('confidence', 0):.2f})")
            return parsed

        except Exception as e:
            logger.error(f"Error parsing command: {e}", exc_info=True)
            return self._get_fallback_parse(user_input)

    def _build_parse_prompt(self, user_input: str) -> str:
        """Build LLM prompt with current context"""
        recent_actions = [h["parsed"]["action"] for h in self.command_history[-5:]] if self.command_history else []
        findings_count = len(self.context.get("findings", []))

        return f"""You are a command parser for a penetration testing tool. Parse this user command into structured format.

Current context:
- Target: {self.context.get('target', 'unknown')}
- Phase: {self.context.get('phase', 'reconnaissance')}
- Recent findings: {findings_count} items
- Last action: {self.context.get('last_action', 'none')}
- Recent commands: {recent_actions}

User command: "{user_input}"

Parse the command and return ONLY a JSON object with this structure:
{{
    "action": "port_scan|enumerate_services|sqli_test|xss_test|exploit|show_findings|show_context|help|what_next",
    "target": "target_url_or_ip_or_current",
    "parameters": {{}},
    "confidence": 0.0-1.0,
    "needs_approval": true|false,
    "clarification": "optional question if unclear"
}}

Available actions:
- port_scan: Scan for open ports and services
- enumerate_services: Enumerate API endpoints and services
- scan_vulnerabilities: Scan for security vulnerabilities
- sqli_test: Test for SQL injection
- xss_test: Test for XSS vulnerabilities
- exploit: Attempt exploitation
- exfiltrate_data: Extract data
- show_findings: Display findings
- show_context: Display session context
- what_next: Get AI suggestions for next steps
- help: Show help

Guidelines:
- If command is clear and unambiguous, set confidence > 0.8
- If command is somewhat unclear, set confidence 0.5-0.8 and add clarification question
- If command is very unclear, set confidence < 0.5 and ask for clarification
- Set needs_approval=true for actions that modify the target (MEDIUM+ risk)
- Set needs_approval=false for read-only operations (LOW risk)
- If target is not specified in command, use "current" to indicate using context target

Return ONLY valid JSON, no additional text or markdown."""

    async def _parse_with_llm(self, prompt: str) -> str:
        """Call LLM to parse command"""
        # Use the LLM client's internal method to get raw response
        if hasattr(self.llm_client, '_generate_with_retry'):
            return await self.llm_client._generate_with_retry(prompt)
        else:
            # For MockLLMClient, we need to create a custom prompt
            # We'll simulate by creating a structured response
            return await self._mock_parse_response(prompt)

    async def _mock_parse_response(self, prompt: str) -> str:
        """Generate mock parse response for testing"""
        # Extract the user command from the prompt
        import re
        match = re.search(r'User command: "(.*?)"', prompt)
        if match:
            user_input = match.group(1).lower()
        else:
            user_input = ""

        # Simple keyword-based parsing for mock mode
        if any(word in user_input for word in ["scan", "port", "nmap", "network"]):
            action = "port_scan"
            needs_approval = False
        elif any(word in user_input for word in ["enumerate", "services", "endpoints", "api"]):
            action = "enumerate_services"
            needs_approval = False
        elif any(word in user_input for word in ["vuln", "vulnerability", "weakness", "find"]):
            action = "scan_vulnerabilities"
            needs_approval = False
        elif any(word in user_input for word in ["sql", "injection", "sqli"]):
            action = "sqli_test"
            needs_approval = True
        elif any(word in user_input for word in ["xss", "cross-site"]):
            action = "xss_test"
            needs_approval = True
        elif any(word in user_input for word in ["exploit", "attack", "hack"]):
            action = "exploit"
            needs_approval = True
        elif any(word in user_input for word in ["exfiltrate", "extract", "steal", "data"]):
            action = "exfiltrate_data"
            needs_approval = True
        elif any(word in user_input for word in ["finding", "results", "discovered"]):
            action = "show_findings"
            needs_approval = False
        elif any(word in user_input for word in ["context", "session", "state"]):
            action = "show_context"
            needs_approval = False
        elif any(word in user_input for word in ["next", "suggest", "recommend", "what"]):
            action = "what_next"
            needs_approval = False
        elif any(word in user_input for word in ["help"]):
            action = "help"
            needs_approval = False
        else:
            action = "unknown"
            needs_approval = False

        response = {
            "action": action,
            "target": "current",
            "parameters": {},
            "confidence": 0.85 if action != "unknown" else 0.3,
            "needs_approval": needs_approval,
            "clarification": "Command unclear, please rephrase" if action == "unknown" else None
        }

        return json.dumps(response)

    def _extract_json(self, response: str) -> Dict[str, Any]:
        """Extract JSON from LLM response"""
        try:
            # Try direct JSON parse first
            return json.loads(response)
        except json.JSONDecodeError:
            # Look for JSON in markdown code blocks
            import re
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))

            # Look for raw JSON objects
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))

            raise ValueError("No valid JSON found in response")

    def _validate_and_enrich(self, parsed: Dict[str, Any], user_input: str) -> Dict[str, Any]:
        """Validate and enrich parsed command"""
        # Ensure required fields exist
        if "action" not in parsed:
            parsed["action"] = "unknown"
        if "target" not in parsed:
            parsed["target"] = "current"
        if "parameters" not in parsed:
            parsed["parameters"] = {}
        if "confidence" not in parsed:
            parsed["confidence"] = 0.5
        if "needs_approval" not in parsed:
            # Default: actions that modify target need approval
            parsed["needs_approval"] = parsed["action"] in [
                "exploit", "sqli_test", "xss_test", "exfiltrate_data"
            ]

        # Resolve "current" target to actual target
        if parsed["target"] == "current":
            parsed["target"] = self.context.get("target", "unknown")

        # Store original input
        parsed["original_input"] = user_input

        return parsed

    def _update_context(self, parsed: Dict[str, Any]):
        """Update session context based on parsed command"""
        self.context["last_action"] = parsed.get("action")

        # Update phase based on action
        action = parsed.get("action")
        if action in ["port_scan", "enumerate_services"]:
            self.context["phase"] = "reconnaissance"
        elif action in ["scan_vulnerabilities", "sqli_test", "xss_test"]:
            self.context["phase"] = "vulnerability_scan"
        elif action in ["exploit", "exfiltrate_data"]:
            self.context["phase"] = "exploitation"

        # Update target if specified and different
        if parsed.get("target") and parsed["target"] != "current":
            self.context["target"] = parsed["target"]

    def _get_fallback_parse(self, user_input: str) -> Dict[str, Any]:
        """Fallback parsing when LLM fails"""
        return {
            "action": "unknown",
            "target": self.context.get("target", "unknown"),
            "parameters": {},
            "confidence": 0.0,
            "needs_approval": False,
            "clarification": "I couldn't understand that command. Type 'help' for available commands.",
            "original_input": user_input
        }

    def add_finding(self, finding: Dict[str, Any]):
        """Add a finding to context"""
        self.context["findings"].append({
            "timestamp": datetime.now().isoformat(),
            "finding": finding
        })

    def get_context(self) -> Dict[str, Any]:
        """Get current context"""
        return self.context.copy()

    def get_command_history(self) -> List[Dict[str, Any]]:
        """Get command history"""
        return self.command_history.copy()

    def clear_history(self):
        """Clear command history"""
        self.command_history.clear()
        logger.info("Command history cleared")
