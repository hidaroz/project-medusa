"""
Objective Parser for MEDUSA
Parses user objectives and determines execution strategy

This module translates natural language objectives into actionable strategies
that guide the CLI to focus on relevant techniques, endpoints, and phases.
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ObjectiveStrategy:
    """Strategy derived from user objective"""
    objective: str
    focus_areas: List[str]  # What to prioritize: ['credentials', 'medical_records', 'vulnerabilities']
    relevant_techniques: List[str]  # MITRE ATT&CK technique IDs
    endpoint_patterns: List[str]  # Endpoint patterns to check: ['/login', '/api/patients']
    skip_phases: List[str]  # Phases to skip: ['post_exploitation']
    priority_endpoints: List[str]  # High-priority endpoints to check first

    def should_check_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is relevant to this objective"""
        if not self.endpoint_patterns:
            return True  # No filtering means check all

        endpoint_lower = endpoint.lower()
        return any(pattern.lower() in endpoint_lower for pattern in self.endpoint_patterns)

    def should_use_technique(self, technique_id: str) -> bool:
        """Check if technique is relevant to this objective"""
        if not self.relevant_techniques:
            return True  # No filtering means use all

        return technique_id in self.relevant_techniques


class ObjectiveParser:
    """
    Parse user objectives and generate execution strategies

    Examples:
    - "find password" → Focus on auth endpoints, credential techniques
    - "find medical records" → Focus on patient APIs, data extraction techniques
    - "find vulnerabilities" → Full scan, all techniques
    """

    # Objective keyword mappings
    PASSWORD_KEYWORDS = ['password', 'passwd', 'pwd', 'credential', 'login', 'auth', 'authentication']
    MEDICAL_KEYWORDS = ['medical', 'patient', 'health', 'record', 'diagnosis', 'prescription', 'ehr', 'phi']
    VULNERABILITY_KEYWORDS = ['vulnerability', 'vuln', 'exploit', 'security', 'weakness', 'flaw']
    ENDPOINT_KEYWORDS = ['endpoint', 'api', 'service', 'route', 'url']

    # Technique mappings by objective type
    PASSWORD_TECHNIQUES = [
        'T1110',  # Brute Force
        'T1078',  # Valid Accounts
        'T1550',  # Use Alternate Authentication Material
        'T1071',  # Application Layer Protocol (for auth endpoints)
        'T1040',  # Network Sniffing (for credential capture)
    ]

    MEDICAL_TECHNIQUES = [
        'T1005',  # Data from Local System
        'T1040',  # Network Sniffing
        'T1071',  # Application Layer Protocol (for API access)
        'T1041',  # Exfiltration Over C2 Channel
    ]

    VULNERABILITY_TECHNIQUES = [
        'T1046',  # Network Service Scanning
        'T1590',  # Gather Victim Network Information
        'T1190',  # Exploit Public-Facing Application
        'T1082',  # System Information Discovery
    ]

    # Endpoint pattern mappings
    PASSWORD_ENDPOINTS = [
        '/login', '/auth', '/authenticate', '/signin',
        '/api/login', '/api/auth', '/api/authenticate',
        '/api/credentials', '/api/users', '/api/account',
        '/oauth', '/token', '/session'
    ]

    MEDICAL_ENDPOINTS = [
        '/api/patients', '/api/medical', '/api/records',
        '/api/health', '/api/diagnosis', '/api/prescription',
        '/patients', '/medical', '/records', '/ehr'
    ]

    def parse(self, objective: str) -> ObjectiveStrategy:
        """
        Parse objective string and return execution strategy

        Args:
            objective: User's objective (e.g., "find password", "find medical records")

        Returns:
            ObjectiveStrategy with relevant techniques, endpoints, and phases
        """
        if not objective:
            # Default: full scan
            return self._create_full_scan_strategy()

        objective_lower = objective.lower()

        # Determine focus areas
        focus_areas = []
        relevant_techniques = []
        endpoint_patterns = []
        skip_phases = []
        priority_endpoints = []

        # Check for password/credential objective
        if any(kw in objective_lower for kw in self.PASSWORD_KEYWORDS):
            focus_areas.append('credentials')
            relevant_techniques.extend(self.PASSWORD_TECHNIQUES)
            endpoint_patterns.extend(self.PASSWORD_ENDPOINTS)
            priority_endpoints.extend(self.PASSWORD_ENDPOINTS[:5])  # Top 5
            skip_phases.append('post_exploitation')  # Don't need post-exploit for password search
            logger.info(f"Objective '{objective}' parsed as: Password/Credential search")

        # Check for medical/patient objective
        if any(kw in objective_lower for kw in self.MEDICAL_KEYWORDS):
            focus_areas.append('medical_records')
            relevant_techniques.extend(self.MEDICAL_TECHNIQUES)
            endpoint_patterns.extend(self.MEDICAL_ENDPOINTS)
            priority_endpoints.extend(self.MEDICAL_ENDPOINTS[:5])  # Top 5
            skip_phases.append('exploitation')  # Don't need exploitation for data extraction
            skip_phases.append('post_exploitation')
            logger.info(f"Objective '{objective}' parsed as: Medical/Patient data search")

        # Check for vulnerability objective
        if any(kw in objective_lower for kw in self.VULNERABILITY_KEYWORDS):
            focus_areas.append('vulnerabilities')
            relevant_techniques.extend(self.VULNERABILITY_TECHNIQUES)
            # No endpoint filtering for vulnerability scans
            logger.info(f"Objective '{objective}' parsed as: Vulnerability assessment")

        # Check for endpoint-specific objective
        if any(kw in objective_lower for kw in self.ENDPOINT_KEYWORDS):
            focus_areas.append('endpoints')
            # Focus on API enumeration techniques
            relevant_techniques.extend(['T1590', 'T1046', 'T1071'])
            logger.info(f"Objective '{objective}' parsed as: Endpoint enumeration")

        # If no specific focus found, do full scan
        if not focus_areas:
            logger.info(f"Objective '{objective}' not recognized, defaulting to full scan")
            return self._create_full_scan_strategy()

        # Remove duplicates
        relevant_techniques = list(set(relevant_techniques))
        endpoint_patterns = list(set(endpoint_patterns))
        skip_phases = list(set(skip_phases))
        priority_endpoints = list(set(priority_endpoints))

        return ObjectiveStrategy(
            objective=objective,
            focus_areas=focus_areas,
            relevant_techniques=relevant_techniques,
            endpoint_patterns=endpoint_patterns,
            skip_phases=skip_phases,
            priority_endpoints=priority_endpoints
        )

    def _create_full_scan_strategy(self) -> ObjectiveStrategy:
        """Create strategy for full scan (no filtering)"""
        return ObjectiveStrategy(
            objective='full_scan',
            focus_areas=['vulnerabilities', 'credentials', 'medical_records', 'endpoints'],
            relevant_techniques=[],  # Empty means use all
            endpoint_patterns=[],  # Empty means check all
            skip_phases=[],
            priority_endpoints=[]
        )

    def is_relevant_finding(self, finding: Dict, strategy: ObjectiveStrategy) -> bool:
        """
        Check if a finding is relevant to the objective strategy

        Args:
            finding: Finding dictionary from CLI
            strategy: Objective strategy

        Returns:
            True if finding is relevant to objective
        """
        if not strategy.focus_areas:
            return True  # No filtering

        finding_type = finding.get('type', '').lower()
        finding_desc = str(finding.get('description', '')).lower()
        finding_path = str(finding.get('path', '')).lower()
        finding_url = str(finding.get('url', '')).lower()

        # Check if finding matches focus areas
        if 'credentials' in strategy.focus_areas:
            if any(kw in finding_type or kw in finding_desc or kw in finding_path or kw in finding_url
                   for kw in self.PASSWORD_KEYWORDS):
                return True

        if 'medical_records' in strategy.focus_areas:
            if any(kw in finding_type or kw in finding_desc or kw in finding_path or kw in finding_url
                   for kw in self.MEDICAL_KEYWORDS):
                return True

        if 'vulnerabilities' in strategy.focus_areas:
            if 'vulnerability' in finding_type or 'vuln' in finding_desc:
                return True

        if 'endpoints' in strategy.focus_areas:
            if 'api_endpoint' in finding_type or 'endpoint' in finding_desc:
                return True

        return False

