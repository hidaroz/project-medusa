"""
Optimized prompts for local Mistral-7B-Instruct model.

These prompts are specifically tuned for smaller models (<10B parameters) and emphasize:
- Clear, concise instructions
- Explicit output format with examples
- Structured constraints
- Minimal verbosity
"""

import json
from typing import Dict, Any, List, Optional


class MistralPrompts:
    """Prompt templates optimized for Mistral-7B-Instruct"""
    
    @staticmethod
    def reconnaissance_strategy(target: str, context: Dict[str, Any]) -> str:
        """
        Generate reconnaissance prompt.
        
        Optimizations:
        - Clear task definition
        - Explicit JSON structure shown
        - Numbered rules for clarity
        - Example output included
        """
        context_str = json.dumps(context, indent=2) if context else '{"environment": "unknown"}'
        
        return f"""Task: Generate reconnaissance strategy for penetration test.

TARGET: {target}
CONTEXT: {context_str}

Output a JSON object with this structure:

{{
  "recommended_actions": [
    {{
      "action": "port_scan",
      "command": "nmap -sV target",
      "technique_id": "T1046",
      "technique_name": "Network Service Discovery",
      "priority": "high",
      "reasoning": "Identify open services and potential entry points"
    }},
    {{
      "action": "web_fingerprint",
      "command": "whatweb target",
      "technique_id": "T1595.002",
      "technique_name": "Active Scanning",
      "priority": "medium",
      "reasoning": "Identify web technologies and versions"
    }}
  ],
  "focus_areas": ["network_services", "web_applications"],
  "risk_assessment": "LOW",
  "estimated_duration": 60
}}

RULES:
1. Include 2-5 recommended_actions
2. Use valid MITRE ATT&CK IDs (format: T####.### or T####)
3. priority: low, medium, or high
4. risk_assessment: LOW, MEDIUM, HIGH, or CRITICAL
5. Prioritize non-intrusive reconnaissance first
6. Each action needs clear rationale

JSON:"""
    
    @staticmethod
    def enumeration_strategy(
        target: str,
        reconnaissance_findings: List[Dict[str, Any]]
    ) -> str:
        """Generate enumeration strategy based on recon findings."""
        
        # Limit findings to prevent context overflow
        findings_sample = reconnaissance_findings[:10]
        findings_str = json.dumps(findings_sample, indent=2)
        
        return f"""Task: Generate enumeration strategy based on reconnaissance findings.

TARGET: {target}

RECONNAISSANCE FINDINGS:
{findings_str}

Output a JSON object:

{{
  "recommended_actions": [
    {{
      "action": "enumerate_api_endpoints",
      "technique_id": "T1590",
      "priority": "high",
      "reasoning": "Discovered REST API, enumerate all endpoints and methods"
    }}
  ],
  "services_to_probe": ["http", "https", "api"],
  "risk_assessment": "LOW",
  "potential_vulnerabilities": ["authentication_bypass", "information_disclosure"]
}}

RULES:
1. Base actions on discovered services
2. Include 2-5 recommended_actions
3. priority: low, medium, high
4. risk_assessment: LOW, MEDIUM, HIGH, CRITICAL
5. Target specific services found in reconnaissance

JSON:"""
    
    @staticmethod
    def vulnerability_risk_assessment(
        vulnerability: Dict[str, Any],
        target_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Risk assessment prompt (single-word output).
        
        Note: This doesn't use JSON mode since we want a single word.
        """
        
        vuln_str = json.dumps(vulnerability, indent=2)
        context_str = json.dumps(target_context, indent=2) if target_context else '{}'
        
        return f"""Assess vulnerability risk level.

VULNERABILITY:
{vuln_str}

TARGET CONTEXT:
{context_str}

Consider:
- Exploitability (ease of exploitation)
- Impact (data breach, system compromise, DoS)
- Target environment (healthcare/finance = higher risk)

Risk levels:
- CRITICAL: Remote code execution, easy to exploit, severe impact
- HIGH: Significant security impact, moderate difficulty
- MEDIUM: Limited impact OR difficult to exploit
- LOW: Information disclosure, requires user interaction

Respond with ONE WORD ONLY: LOW, MEDIUM, HIGH, or CRITICAL

RISK:"""
    
    @staticmethod
    def attack_strategy_planning(
        target: str,
        findings: List[Dict[str, Any]],
        objectives: List[str]
    ) -> str:
        """Generate attack chain strategy."""
        
        # Limit findings to prevent overwhelming the model
        findings_sample = findings[:10]
        findings_str = json.dumps(findings_sample, indent=2)
        objectives_str = json.dumps(objectives)
        
        return f"""Task: Create attack chain for penetration test.

TARGET: {target}
OBJECTIVES: {objectives_str}

VULNERABILITIES:
{findings_str}

Output a JSON object:

{{
  "strategy_overview": "Multi-stage attack: exploit SQLi for DB access, then privilege escalation",
  "attack_chain": [
    {{
      "step": 1,
      "action": "exploit_sql_injection",
      "target_vulnerability": "SQL Injection in /api/search?q=",
      "technique_id": "T1190",
      "expected_outcome": "Database access",
      "risk_level": "MEDIUM",
      "prerequisites": []
    }},
    {{
      "step": 2,
      "action": "extract_credentials",
      "target_vulnerability": "User credentials in database",
      "technique_id": "T1555",
      "expected_outcome": "User credentials from database",
      "risk_level": "HIGH",
      "prerequisites": ["Database access"]
    }}
  ],
  "success_probability": 0.75,
  "estimated_duration": 300
}}

RULES:
1. Order steps logically (check prerequisites)
2. Use MITRE ATT&CK technique IDs
3. risk_level: LOW, MEDIUM, HIGH, CRITICAL
4. success_probability: 0.0 to 1.0
5. Include 2-5 steps maximum
6. Each step builds on previous steps

JSON:"""
    
    @staticmethod
    def natural_language_command_parsing(
        user_input: str,
        context: Dict[str, Any]
    ) -> str:
        """Parse natural language into structured command."""
        
        context_str = json.dumps(context, indent=2)
        
        return f"""Task: Parse user command into structured action.

USER INPUT: "{user_input}"
CONTEXT: {context_str}

Output a JSON object:

{{
  "understanding": "User wants to scan ports on the target",
  "confidence": 0.95,
  "action": "port_scan",
  "parameters": {{
    "target": "192.168.1.1",
    "ports": "1-1000"
  }},
  "risk_level": "LOW",
  "needs_approval": false,
  "clarification_needed": false,
  "clarification_question": null
}}

Common actions:
- port_scan, web_scan, vuln_scan, directory_enum
- sql_injection_test, exploit, credential_check
- show_findings, status, help

RULES:
1. Extract target from user input or context
2. confidence: 0.0 to 1.0
3. needs_approval: true if risky action
4. If unclear, set confidence < 0.7 and clarification_needed=true

JSON:"""
    
    @staticmethod
    def next_action_recommendation(
        context: Dict[str, Any]
    ) -> str:
        """Analyze context and recommend next action."""
        
        context_str = json.dumps(context, indent=2)
        
        return f"""Task: Recommend next action based on operation state.

OPERATION CONTEXT:
{context_str}

Output a JSON object:

{{
  "recommendations": [
    {{
      "action": "enumerate_endpoints",
      "confidence": 0.90,
      "reasoning": "Web API discovered, enumerate endpoints before exploitation",
      "technique": "T1590",
      "risk_level": "LOW"
    }}
  ],
  "context_analysis": "Target is web application with potential API endpoints",
  "suggested_next_phase": "enumeration"
}}

RULES:
1. Provide 1-3 recommendations
2. confidence: 0.0 to 1.0
3. reasoning: explain why this action
4. risk_level: LOW, MEDIUM, HIGH, CRITICAL
5. suggested_next_phase: reconnaissance, enumeration, exploitation, post_exploitation

JSON:"""

