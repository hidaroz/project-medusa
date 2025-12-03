"""
Optimized prompt templates for local Mistral-7B-Instruct model

These prompts are specifically designed for smaller language models:
- Clear task definitions
- Explicit JSON structure with examples
- Concise instructions
- Rule-based constraints
- Reduced verbosity compared to Gemini prompts
- Enhanced with feedback from past operations for continuous learning
"""

import json
from typing import Dict, Any, List, Optional
from medusa.core.feedback import get_feedback_tracker
from medusa.core.strategy_selector import StrategySelector
from medusa.core.objective_parser import ObjectiveParser


class PromptTemplates:
    """
    Prompt templates optimized for Mistral-7B-Instruct

    Key optimizations:
    1. Structured format with clear sections
    2. Explicit JSON examples to guide output format
    3. Concise language (smaller context window)
    4. Rule-based constraints to ensure valid responses
    5. Focus on actionable, specific outputs
    """

    @staticmethod
    def reconnaissance_strategy(target: str, context: Dict[str, Any]) -> str:
        """Generate reconnaissance prompt for Mistral-7B with feedback integration"""
        context_str = json.dumps(context, indent=2) if context else "{}"

        # Get feedback from past operations
        feedback = get_feedback_tracker()
        successful_techniques = feedback.get_successful_techniques(min_success_rate=0.5)
        failed_techniques = feedback.get_failed_techniques()
        best_paths = feedback.get_best_attack_paths(limit=3)

        # Use strategy selector for objective-specific recommendations
        objective_strategy = None
        if context and context.get('objective'):
            parser = ObjectiveParser()
            objective_strategy = parser.parse(context.get('objective'))
            selector = StrategySelector()
            recommended_techniques = selector.select_techniques(objective_strategy, limit=5)
        else:
            recommended_techniques = []

        # Build feedback context with strategy selector recommendations
        feedback_context = ""
        if recommended_techniques:
            feedback_context += "\n\nRECOMMENDED TECHNIQUES (based on objective and past performance):\n"
            for rec in recommended_techniques[:3]:  # Top 3
                feedback_context += f"- {rec.technique_id}: {rec.success_rate:.0%} success rate ({rec.reason})\n"

        if successful_techniques and not recommended_techniques:
            feedback_context += "\n\nPAST SUCCESSES (use these techniques):\n"
            for tech in successful_techniques[:3]:  # Top 3
                feedback_context += f"- {tech['technique_id']}: {tech['success_rate']:.0%} success rate"
                if tech.get('best_payloads'):
                    feedback_context += f", best payload: {tech['best_payloads'][0]}"
                feedback_context += "\n"

        if failed_techniques:
            feedback_context += "\nPAST FAILURES (avoid these):\n"
            for tech_id in failed_techniques[:3]:  # Top 3
                # Check if should avoid based on strategy selector
                if objective_strategy:
                    selector = StrategySelector()
                    should_avoid, reason = selector.should_avoid_technique(tech_id, objective_strategy)
                    if should_avoid:
                        feedback_context += f"- {tech_id}: {reason}\n"
                else:
                    feedback_context += f"- {tech_id}: Failed previously\n"

        if best_paths:
            feedback_context += "\nBEST ATTACK PATHS (consider this sequence):\n"
            for path in best_paths[:2]:  # Top 2
                feedback_context += f"- {' → '.join(path['sequence'][:3])}: {path['success_rate']:.0%} success\n"

        # Extract objective from context if provided
        objective_text = ""
        if context and context.get('objective'):
            objective = context.get('objective')
            objective_text = f"\n\nOBJECTIVE: {objective}\nFocus the reconnaissance on finding: {objective}\n"

        return f"""You are a penetration testing AI assistant. Generate a reconnaissance strategy for the target.
{feedback_context}

TARGET: {target}
CONTEXT: {context_str}{objective_text}

TASK: Output a JSON object with reconnaissance recommendations.

EXAMPLE OUTPUT FORMAT:
{{
  "recommended_actions": [
    {{
      "action": "port_scan",
      "command": "nmap -sV -p- {target}",
      "technique_id": "T1046",
      "technique_name": "Network Service Discovery",
      "priority": "high",
      "reasoning": "Discover open services and potential entry points"
    }},
    {{
      "action": "web_fingerprint",
      "command": "whatweb {target}",
      "technique_id": "T1595.002",
      "technique_name": "Active Scanning",
      "priority": "high",
      "reasoning": "Identify web technologies and versions"
    }}
  ],
  "focus_areas": ["web_services", "network_services", "authentication"],
  "risk_assessment": "LOW",
  "estimated_duration": 90
}}

RULES:
1. Include 2-4 recommended_actions (not more)
2. Use valid MITRE ATT&CK technique IDs (format: T####.### or T####)
3. priority must be: "high", "medium", or "low"
4. risk_assessment must be: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
5. Focus on non-intrusive reconnaissance first
6. Each action must have clear reasoning
7. Commands should be practical and safe

OUTPUT (JSON only, no explanations):"""

    @staticmethod
    def enumeration_strategy(target: str, reconnaissance_findings: List[Dict[str, Any]], objective: Optional[str] = None) -> str:
        """Generate enumeration prompt with feedback integration"""
        findings_str = json.dumps(reconnaissance_findings[:5], indent=2)

        # Get feedback
        feedback = get_feedback_tracker()
        working_creds = feedback.get_working_credentials()
        successful_techniques = feedback.get_successful_techniques(min_success_rate=0.5)

        # Use strategy selector for objective-specific recommendations
        objective_strategy = None
        if objective:
            parser = ObjectiveParser()
            objective_strategy = parser.parse(objective)
            selector = StrategySelector()
            recommended_techniques = selector.select_techniques(objective_strategy, limit=5)
        else:
            recommended_techniques = []

        feedback_context = ""
        if working_creds:
            feedback_context += "\n\nKNOWN WORKING CREDENTIALS (try these first):\n"
            for cred in working_creds[:3]:  # Top 3
                feedback_context += f"- {cred['service']}: {cred['username']} / {cred['password']}\n"

        if recommended_techniques:
            feedback_context += "\nRECOMMENDED TECHNIQUES (for this objective):\n"
            for rec in recommended_techniques[:3]:
                feedback_context += f"- {rec.technique_id}: {rec.success_rate:.0%} success ({rec.reason})\n"
        elif successful_techniques:
            feedback_context += "\nSUCCESSFUL TECHNIQUES:\n"
            for tech in successful_techniques[:2]:
                feedback_context += f"- {tech['technique_id']}: {tech['success_rate']:.0%} success\n"

        # Include objective if provided
        objective_text = ""
        if objective:
            objective_text = f"\n\nOBJECTIVE: {objective}\nFocus enumeration on finding: {objective}\n"

        return f"""You are a penetration testing AI assistant. Based on reconnaissance findings, recommend enumeration actions.
{feedback_context}

TARGET: {target}{objective_text}

RECONNAISSANCE FINDINGS:
{findings_str}

TASK: Generate enumeration strategy in JSON format.

EXAMPLE OUTPUT:
{{
  "recommended_actions": [
    {{
      "action": "enumerate_api_endpoints",
      "technique_id": "T1590",
      "technique_name": "Gather Victim Network Information",
      "priority": "high",
      "reasoning": "Discovered REST API, enumerate endpoints and methods"
    }},
    {{
      "action": "test_authentication",
      "technique_id": "T1110",
      "technique_name": "Brute Force",
      "priority": "medium",
      "reasoning": "Test authentication mechanisms for weaknesses"
    }}
  ],
  "services_to_probe": ["http", "https", "api"],
  "risk_assessment": "LOW",
  "potential_vulnerabilities": ["authentication_bypass", "information_disclosure"]
}}

RULES:
1. Include 2-4 recommended_actions
2. Use valid MITRE ATT&CK technique IDs
3. priority: "high", "medium", or "low"
4. risk_assessment: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
5. Base recommendations on discovered services
6. Focus on enumeration, not exploitation

OUTPUT (JSON only):"""

    @staticmethod
    def vulnerability_risk_assessment(vulnerability: Dict[str, Any], target_context: Optional[Dict[str, Any]] = None) -> str:
        """Risk assessment prompt for Mistral-7B"""
        vuln_str = json.dumps(vulnerability, indent=2)
        context_str = json.dumps(target_context, indent=2) if target_context else "None"
        return f"""You are a cybersecurity expert. Assess the risk level of this vulnerability.

VULNERABILITY:
{vuln_str}

TARGET CONTEXT:
{context_str}

TASK: Determine risk level considering:
- Exploitability (how easy to exploit)
- Impact (data breach, system compromise, denial of service)
- Target environment (healthcare/finance = higher risk)
- Presence of compensating controls

RISK LEVELS:
- CRITICAL: Remote code execution, easy exploitation, high impact, no mitigations
- HIGH: Significant security impact, moderate exploitation difficulty, sensitive data at risk
- MEDIUM: Limited impact or requires multiple steps to exploit
- LOW: Information disclosure, requires user interaction, minimal impact

INSTRUCTIONS: Respond with ONLY ONE WORD from: LOW, MEDIUM, HIGH, or CRITICAL

RISK LEVEL:"""

    @staticmethod
    def attack_strategy_planning(target: str, findings: List[Dict[str, Any]], objectives: List[str]) -> str:
        """Attack chain planning prompt"""
        findings_str = json.dumps(findings[:8], indent=2)
        objectives_str = ", ".join(objectives)
        return f"""You are a penetration testing strategist. Create an attack plan based on discovered vulnerabilities.

TARGET: {target}
OBJECTIVES: {objectives_str}

DISCOVERED VULNERABILITIES:
{findings_str}

TASK: Generate a step-by-step attack chain in JSON format.

EXAMPLE OUTPUT:
{{
  "strategy_overview": "Multi-stage attack starting with SQL injection to gain database access",
  "attack_chain": [
    {{
      "step": 1,
      "action": "exploit_sql_injection",
      "target_vulnerability": "SQL Injection in /api/search parameter",
      "technique_id": "T1190",
      "technique_name": "Exploit Public-Facing Application",
      "expected_outcome": "Database access",
      "risk_level": "MEDIUM",
      "prerequisites": []
    }},
    {{
      "step": 2,
      "action": "extract_credentials",
      "target_vulnerability": "Weak password hashing",
      "technique_id": "T1555",
      "technique_name": "Credentials from Password Stores",
      "expected_outcome": "User credentials",
      "risk_level": "HIGH",
      "prerequisites": ["database_access"]
    }}
  ],
  "success_probability": 0.75,
  "estimated_duration": 300,
  "risks": ["detection by IDS", "account lockout"]
}}

RULES:
1. Order steps logically (check prerequisites)
2. Include 2-5 steps maximum
3. Map each step to MITRE ATT&CK technique ID
4. risk_level: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
5. success_probability: 0.0 to 1.0
6. estimated_duration in seconds

OUTPUT (JSON only):"""

    @staticmethod
    def next_action_recommendation(context: Dict[str, Any]) -> str:
        """Generate prompt for next action recommendation"""
        context_str = json.dumps(context, indent=2)
        return f"""You are an AI penetration testing assistant. Based on the current operation state, recommend the next action.

OPERATION CONTEXT:
{context_str}

TASK: Provide recommendation for the next action.

EXAMPLE OUTPUT:
{{
  "recommendations": [
    {{
      "action": "exploit_sql_injection",
      "confidence": 0.85,
      "reasoning": "High-confidence SQL injection detected in /api/search parameter",
      "technique": "T1190",
      "risk_level": "MEDIUM"
    }},
    {{
      "action": "enumerate_databases",
      "confidence": 0.70,
      "reasoning": "Alternative: enumerate database structure before exploitation",
      "technique": "T1046",
      "risk_level": "LOW"
    }}
  ],
  "context_analysis": "Target shows multiple vulnerabilities. SQL injection has highest confidence.",
  "suggested_next_phase": "exploitation"
}}

RULES:
1. Include 1-3 recommendations (prioritized by confidence)
2. confidence: 0.0 to 1.0
3. Use valid MITRE ATT&CK technique IDs
4. risk_level: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
5. Provide clear reasoning for each recommendation

OUTPUT (JSON only):"""

    @staticmethod
    def simple_completion(prompt: str, force_json: bool = False) -> str:
        """Simple completion prompt without specific structure"""
        if force_json:
            return f"""{prompt}

IMPORTANT: Respond with ONLY valid JSON. No explanations or additional text.

JSON OUTPUT:"""
        else:
            return prompt
