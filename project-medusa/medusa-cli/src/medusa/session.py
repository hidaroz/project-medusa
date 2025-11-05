"""
Session Management for MEDUSA Interactive Shell
Handles session state, persistence, and command suggestions
"""

import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path


class Session:
    """Manage interactive session state"""

    def __init__(self, target: str, session_id: Optional[str] = None):
        """
        Initialize session

        Args:
            target: Target URL or IP
            session_id: Optional session ID (generated if not provided)
        """
        self.session_id = session_id or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.target = target
        self.command_history: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.context: Dict[str, Any] = {
            "target": target,
            "phase": "reconnaissance",
            "techniques_used": []
        }
        self.start_time = datetime.now()
        self.metadata: Dict[str, Any] = {
            "session_id": self.session_id,
            "created_at": self.start_time.isoformat(),
            "target": target
        }

    def add_command(self, command: str, result: Dict[str, Any]):
        """
        Add command to history

        Args:
            command: User command
            result: Command result
        """
        self.command_history.append({
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "result": result,
            "phase": self.context.get("phase", "unknown")
        })

    def add_finding(self, finding: Dict[str, Any]):
        """
        Add finding to session

        Args:
            finding: Finding details
        """
        finding_with_metadata = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            **finding
        }
        self.findings.append(finding_with_metadata)

    def add_technique(self, technique_id: str, technique_name: str):
        """
        Add MITRE ATT&CK technique to session

        Args:
            technique_id: MITRE technique ID (e.g., "T1046")
            technique_name: Technique name
        """
        technique = {
            "id": technique_id,
            "name": technique_name,
            "timestamp": datetime.now().isoformat()
        }
        if technique not in self.context["techniques_used"]:
            self.context["techniques_used"].append(technique)

    def update_context(self, updates: Dict[str, Any]):
        """
        Update session context

        Args:
            updates: Context updates
        """
        self.context.update(updates)

    def update_phase(self, phase: str):
        """
        Update current testing phase

        Args:
            phase: New phase (reconnaissance, enumeration, exploitation, etc.)
        """
        self.context["phase"] = phase

    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get findings filtered by severity

        Args:
            severity: Severity level (critical, high, medium, low, info)

        Returns:
            List of findings matching severity
        """
        return [f for f in self.findings if f.get("severity", "").lower() == severity.lower()]

    def get_findings_by_type(self, finding_type: str) -> List[Dict[str, Any]]:
        """
        Get findings filtered by type

        Args:
            finding_type: Finding type (vulnerability, open_port, api_endpoint, etc.)

        Returns:
            List of findings matching type
        """
        return [f for f in self.findings if f.get("type", "").lower() == finding_type.lower()]

    def get_summary(self) -> Dict[str, Any]:
        """
        Get session summary

        Returns:
            Session summary with statistics
        """
        duration = (datetime.now() - self.start_time).total_seconds()

        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            severity = finding.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Count findings by type
        type_counts: Dict[str, int] = {}
        for finding in self.findings:
            finding_type = finding.get("type", "unknown")
            type_counts[finding_type] = type_counts.get(finding_type, 0) + 1

        return {
            "session_id": self.session_id,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "duration_seconds": duration,
            "current_phase": self.context.get("phase", "unknown"),
            "commands_executed": len(self.command_history),
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "type_counts": type_counts,
            "techniques_used": len(self.context.get("techniques_used", []))
        }

    def save(self, directory: str = "./sessions") -> str:
        """
        Save session to file

        Args:
            directory: Directory to save session files

        Returns:
            Path to saved session file
        """
        # Create directory if it doesn't exist
        Path(directory).mkdir(parents=True, exist_ok=True)

        # Prepare session data
        session_data = {
            "metadata": {
                **self.metadata,
                "saved_at": datetime.now().isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds()
            },
            "target": self.target,
            "command_history": self.command_history,
            "findings": self.findings,
            "context": self.context,
            "summary": self.get_summary()
        }

        # Save to file
        filepath = os.path.join(directory, f"{self.session_id}.json")
        with open(filepath, 'w') as f:
            json.dump(session_data, f, indent=2)

        return filepath

    @classmethod
    def load(cls, filepath: str) -> 'Session':
        """
        Load session from file

        Args:
            filepath: Path to session file

        Returns:
            Loaded Session object
        """
        with open(filepath) as f:
            data = json.load(f)

        # Create session
        session = cls(
            target=data["target"],
            session_id=data["metadata"]["session_id"]
        )

        # Restore data
        session.command_history = data["command_history"]
        session.findings = data["findings"]
        session.context = data["context"]
        session.metadata = data["metadata"]

        # Restore start time
        session.start_time = datetime.fromisoformat(data["metadata"]["created_at"])

        return session

    @classmethod
    def list_sessions(cls, directory: str = "./sessions") -> List[Dict[str, Any]]:
        """
        List available sessions

        Args:
            directory: Directory containing session files

        Returns:
            List of session summaries
        """
        sessions = []

        if not os.path.exists(directory):
            return sessions

        for filename in os.listdir(directory):
            if filename.endswith(".json"):
                filepath = os.path.join(directory, filename)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                    sessions.append({
                        "filepath": filepath,
                        "session_id": data["metadata"]["session_id"],
                        "target": data["target"],
                        "created_at": data["metadata"]["created_at"],
                        "duration": data["metadata"].get("duration_seconds", 0),
                        "findings": len(data["findings"])
                    })
                except Exception:
                    # Skip invalid session files
                    continue

        return sorted(sessions, key=lambda x: x["created_at"], reverse=True)


class CommandSuggester:
    """Provide context-aware command suggestions"""

    def __init__(self):
        """Initialize command suggester"""
        self.suggestion_templates = {
            "reconnaissance": [
                "scan for open ports",
                "enumerate services",
                "fingerprint web application",
                "check for common vulnerabilities"
            ],
            "enumeration": [
                "enumerate API endpoints",
                "test authentication mechanisms",
                "discover hidden directories",
                "analyze input validation"
            ],
            "vulnerability_scan": [
                "test for SQL injection",
                "check for XSS vulnerabilities",
                "scan for known CVEs",
                "test for authentication bypass"
            ],
            "exploitation": [
                "exploit SQL injection",
                "attempt privilege escalation",
                "test credential reuse",
                "verify vulnerability impact"
            ]
        }

    def get_suggestions(self, context: Dict[str, Any]) -> List[str]:
        """
        Get relevant command suggestions based on context

        Args:
            context: Session context

        Returns:
            List of suggested commands
        """
        suggestions = []

        phase = context.get("phase", "reconnaissance")
        findings = context.get("findings", [])

        # Phase-based suggestions
        base_suggestions = self.suggestion_templates.get(phase, [])
        suggestions.extend(base_suggestions[:3])

        # Finding-based suggestions
        finding_suggestions = self._get_finding_based_suggestions(findings)
        suggestions.extend(finding_suggestions)

        # Always include utility suggestions
        suggestions.extend([
            "show findings",
            "what should I do next?",
            "show session context"
        ])

        # Remove duplicates while preserving order
        seen = set()
        unique_suggestions = []
        for suggestion in suggestions:
            if suggestion not in seen:
                seen.add(suggestion)
                unique_suggestions.append(suggestion)

        return unique_suggestions[:8]  # Limit to top 8 suggestions

    def _get_finding_based_suggestions(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Get suggestions based on findings"""
        suggestions = []

        # Check for specific types of findings
        has_http_service = any(
            f.get("service") == "http" or f.get("type") == "webapp"
            for f in findings
        )
        has_sql_vuln = any(
            "sql" in f.get("type", "").lower() or "sql" in f.get("title", "").lower()
            for f in findings
        )
        has_xss_vuln = any(
            "xss" in f.get("type", "").lower() or "xss" in f.get("title", "").lower()
            for f in findings
        )
        has_api_endpoints = any(
            f.get("type") == "api_endpoint"
            for f in findings
        )

        if has_http_service and not has_api_endpoints:
            suggestions.append("enumerate API endpoints")

        if has_sql_vuln:
            suggestions.append("test SQL injection vulnerability")
            suggestions.append("enumerate database")

        if has_xss_vuln:
            suggestions.append("verify XSS vulnerability")

        if has_api_endpoints:
            suggestions.append("test API authentication")
            suggestions.append("analyze API for vulnerabilities")

        return suggestions

    def get_next_phase_suggestion(self, current_phase: str, findings_count: int) -> Optional[str]:
        """
        Suggest transitioning to next phase

        Args:
            current_phase: Current testing phase
            findings_count: Number of findings in current phase

        Returns:
            Suggestion for next phase or None
        """
        phase_transitions = {
            "reconnaissance": ("enumeration", 3),
            "enumeration": ("vulnerability_scan", 5),
            "vulnerability_scan": ("exploitation", 2)
        }

        if current_phase in phase_transitions:
            next_phase, required_findings = phase_transitions[current_phase]
            if findings_count >= required_findings:
                return f"You have {findings_count} findings. Consider moving to {next_phase} phase."

        return None
