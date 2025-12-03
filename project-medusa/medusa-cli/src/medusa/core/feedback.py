"""
Feedback tracking system for continuous learning
Tracks technique success/failure, credentials, and attack paths
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class TechniqueFeedback:
    """Feedback for a specific MITRE ATT&CK technique"""
    technique_id: str
    success_count: int = 0
    failure_count: int = 0
    best_payloads: List[str] = None
    targets: List[str] = None
    last_success: Optional[str] = None
    last_failure: Optional[str] = None

    def __post_init__(self):
        if self.best_payloads is None:
            self.best_payloads = []
        if self.targets is None:
            self.targets = []

    @property
    def success_rate(self) -> float:
        """Calculate success rate (0.0 to 1.0)"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total

    @property
    def total_attempts(self) -> int:
        """Total number of attempts"""
        return self.success_count + self.failure_count


@dataclass
class CredentialEntry:
    """Working credential discovered"""
    service: str
    username: str
    password: str
    discovered_at: str
    used_count: int = 0
    last_used: Optional[str] = None


@dataclass
class AttackPath:
    """Successful attack path sequence"""
    path_id: str
    sequence: List[str]  # List of technique IDs
    success_count: int = 0
    failure_count: int = 0
    avg_time_seconds: float = 0.0
    vulnerabilities_found: int = 0
    last_success: Optional[str] = None

    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total


class FeedbackTracker:
    """
    Tracks learning feedback from operations
    Stores data in JSON file for persistence
    """

    def __init__(self, feedback_file: Optional[Path] = None):
        """
        Initialize feedback tracker

        Args:
            feedback_file: Path to feedback JSON file. Defaults to ~/.medusa/feedback.json
        """
        if feedback_file is None:
            feedback_dir = Path.home() / ".medusa"
            feedback_dir.mkdir(exist_ok=True)
            feedback_file = feedback_dir / "feedback.json"

        self.feedback_file = Path(feedback_file)
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        """Load feedback data from file"""
        if not self.feedback_file.exists():
            return {
                "techniques": {},
                "credentials": [],
                "attack_paths": {},
                "metrics": {
                    "total_operations": 0,
                    "avg_vulnerabilities_per_run": 0.0,
                    "avg_time_to_first_vuln": 0.0,
                    "improvement_trend": "stable"
                },
                "last_updated": None
            }

        try:
            with open(self.feedback_file, 'r') as f:
                data = json.load(f)
                # Ensure all required keys exist
                if "techniques" not in data:
                    data["techniques"] = {}
                if "credentials" not in data:
                    data["credentials"] = []
                if "attack_paths" not in data:
                    data["attack_paths"] = {}
                if "metrics" not in data:
                    data["metrics"] = {
                        "total_operations": 0,
                        "avg_vulnerabilities_per_run": 0.0,
                        "avg_time_to_first_vuln": 0.0,
                        "improvement_trend": "stable"
                    }
                return data
        except Exception as e:
            logger.error(f"Failed to load feedback: {e}")
            return {
                "techniques": {},
                "credentials": [],
                "attack_paths": {},
                "metrics": {
                    "total_operations": 0,
                    "avg_vulnerabilities_per_run": 0.0,
                    "avg_time_to_first_vuln": 0.0,
                    "improvement_trend": "stable"
                },
                "last_updated": None
            }

    def _save(self):
        """Save feedback data to file"""
        try:
            self.data["last_updated"] = datetime.now().isoformat()
            with open(self.feedback_file, 'w') as f:
                json.dump(self.data, f, indent=2)
            logger.debug(f"Feedback saved to {self.feedback_file}")
        except Exception as e:
            logger.error(f"Failed to save feedback: {e}")

    def record_technique_success(
        self,
        technique_id: str,
        payload: Optional[str] = None,
        target: Optional[str] = None,
        data_extracted: Optional[Dict[str, Any]] = None,
        objective: Optional[str] = None
    ):
        """
        Record a successful technique execution

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1190")
            payload: Payload/command that worked
            target: Target where it worked
            data_extracted: Any data extracted (e.g., credentials)
        """
        if technique_id not in self.data["techniques"]:
            self.data["techniques"][technique_id] = {
                "success_count": 0,
                "failure_count": 0,
                "best_payloads": [],
                "targets": [],
                "last_success": None,
                "last_failure": None,
                "objective_performance": {},
                "technique_name": technique_id
            }

        tech = self.data["techniques"][technique_id]
        tech["success_count"] += 1
        tech["last_success"] = datetime.now().isoformat()

        # Ensure objective_performance exists
        if "objective_performance" not in tech:
            tech["objective_performance"] = {}

        # Track objective-specific performance
        if objective:
            focus_areas = self._extract_focus_areas(objective)
            for focus_area in focus_areas:
                if focus_area not in tech["objective_performance"]:
                    tech["objective_performance"][focus_area] = {
                        "success_count": 0,
                        "failure_count": 0
                    }
                tech["objective_performance"][focus_area]["success_count"] += 1

        if payload and payload not in tech["best_payloads"]:
            tech["best_payloads"].append(payload)
            # Keep only top 5 payloads
            tech["best_payloads"] = tech["best_payloads"][:5]

        if target and target not in tech["targets"]:
            tech["targets"].append(target)
            # Keep only top 10 targets
            tech["targets"] = tech["targets"][:10]

        # Extract credentials if provided
        if data_extracted and "credentials" in data_extracted:
            for cred in data_extracted["credentials"]:
                self.record_credential(
                    service=cred.get("service", "unknown"),
                    username=cred.get("username", ""),
                    password=cred.get("password", "")
                )

        self._save()
        logger.info(f"Recorded success for technique {technique_id}")

    def record_technique_failure(
        self,
        technique_id: str,
        reason: Optional[str] = None,
        target: Optional[str] = None,
        objective: Optional[str] = None
    ):
        """
        Record a failed technique execution

        Args:
            technique_id: MITRE ATT&CK technique ID
            reason: Reason for failure
            target: Target where it failed
        """
        if technique_id not in self.data["techniques"]:
            self.data["techniques"][technique_id] = {
                "success_count": 0,
                "failure_count": 0,
                "best_payloads": [],
                "targets": [],
                "last_success": None,
                "last_failure": None,
                "objective_performance": {},
                "technique_name": technique_id
            }

        tech = self.data["techniques"][technique_id]
        tech["failure_count"] += 1
        tech["last_failure"] = datetime.now().isoformat()

        # Ensure objective_performance exists
        if "objective_performance" not in tech:
            tech["objective_performance"] = {}

        # Track objective-specific performance
        if objective:
            focus_areas = self._extract_focus_areas(objective)
            for focus_area in focus_areas:
                if focus_area not in tech["objective_performance"]:
                    tech["objective_performance"][focus_area] = {
                        "success_count": 0,
                        "failure_count": 0
                    }
                tech["objective_performance"][focus_area]["failure_count"] += 1

        self._save()
        logger.info(f"Recorded failure for technique {technique_id}: {reason}")

    def record_credential(
        self,
        service: str,
        username: str,
        password: str
    ):
        """
        Record a working credential

        Args:
            service: Service name (e.g., "mysql", "ssh", "ftp")
            username: Username
            password: Password
        """
        # Check if credential already exists
        for cred in self.data["credentials"]:
            if (cred["service"] == service and
                cred["username"] == username and
                cred["password"] == password):
                cred["used_count"] += 1
                cred["last_used"] = datetime.now().isoformat()
                self._save()
                return

        # New credential
        self.data["credentials"].append({
            "service": service,
            "username": username,
            "password": password,
            "discovered_at": datetime.now().isoformat(),
            "used_count": 1,
            "last_used": datetime.now().isoformat()
        })

        # Keep only most recent 50 credentials
        self.data["credentials"] = self.data["credentials"][:50]

        self._save()
        logger.info(f"Recorded credential: {service}/{username}")

    def record_attack_path(
        self,
        sequence: List[str],
        success: bool,
        time_seconds: float,
        vulnerabilities_found: int
    ):
        """
        Record an attack path execution

        Args:
            sequence: List of technique IDs in order
            success: Whether the path succeeded
            time_seconds: Time taken in seconds
            vulnerabilities_found: Number of vulnerabilities found
        """
        path_id = "_".join(sequence[:3])  # Use first 3 techniques as ID

        if path_id not in self.data["attack_paths"]:
            self.data["attack_paths"][path_id] = {
                "sequence": sequence,
                "success_count": 0,
                "failure_count": 0,
                "avg_time_seconds": 0.0,
                "vulnerabilities_found": 0,
                "last_success": None
            }

        path = self.data["attack_paths"][path_id]

        if success:
            path["success_count"] += 1
            path["last_success"] = datetime.now().isoformat()
        else:
            path["failure_count"] += 1

        # Update average time (simple moving average)
        total_attempts = path["success_count"] + path["failure_count"]
        if success:
            path["avg_time_seconds"] = (
                (path["avg_time_seconds"] * (total_attempts - 1) + time_seconds) / total_attempts
            )

        # Update max vulnerabilities found
        if vulnerabilities_found > path["vulnerabilities_found"]:
            path["vulnerabilities_found"] = vulnerabilities_found

        self._save()
        logger.info(f"Recorded attack path: {path_id} (success={success})")

    def get_technique_success_rate(self, technique_id: str) -> float:
        """Get success rate for a technique (0.0 to 1.0)"""
        if technique_id not in self.data["techniques"]:
            return 0.0

        tech = self.data["techniques"][technique_id]
        total = tech["success_count"] + tech["failure_count"]
        if total == 0:
            return 0.0
        return tech["success_count"] / total

    def get_successful_techniques(self, min_success_rate: float = 0.5) -> List[Dict[str, Any]]:
        """
        Get techniques with success rate above threshold

        Args:
            min_success_rate: Minimum success rate (0.0 to 1.0)

        Returns:
            List of technique info dicts
        """
        successful = []
        for tech_id, tech_data in self.data["techniques"].items():
            rate = self.get_technique_success_rate(tech_id)
            if rate >= min_success_rate and tech_data["success_count"] > 0:
                successful.append({
                    "technique_id": tech_id,
                    "success_rate": rate,
                    "success_count": tech_data["success_count"],
                    "best_payloads": tech_data.get("best_payloads", []),
                    "targets": tech_data.get("targets", [])
                })

        # Sort by success rate descending
        successful.sort(key=lambda x: x["success_rate"], reverse=True)
        return successful

    def get_failed_techniques(self) -> List[str]:
        """Get list of techniques that have failed"""
        failed = []
        for tech_id, tech_data in self.data["techniques"].items():
            if tech_data["failure_count"] > 0 and tech_data["success_count"] == 0:
                failed.append(tech_id)
        return failed

    def get_working_credentials(self, service: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get working credentials

        Args:
            service: Filter by service name (optional)

        Returns:
            List of credential dicts
        """
        creds = self.data["credentials"]
        if service:
            creds = [c for c in creds if c["service"] == service]

        # Sort by most used
        creds.sort(key=lambda x: x["used_count"], reverse=True)
        return creds

    def get_best_attack_paths(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Get best attack paths by success rate

        Args:
            limit: Maximum number of paths to return

        Returns:
            List of attack path dicts
        """
        paths = []
        for path_id, path_data in self.data["attack_paths"].items():
            rate = path_data["success_count"] / max(
                path_data["success_count"] + path_data["failure_count"], 1
            )
            if rate > 0:
                paths.append({
                    "path_id": path_id,
                    "sequence": path_data["sequence"],
                    "success_rate": rate,
                    "avg_time": path_data["avg_time_seconds"],
                    "vulnerabilities_found": path_data["vulnerabilities_found"]
                })

        # Sort by success rate descending
        paths.sort(key=lambda x: x["success_rate"], reverse=True)
        return paths[:limit]

    def update_operation_metrics(
        self,
        vulnerabilities_found: int,
        time_to_first_vuln: Optional[float] = None
    ):
        """
        Update overall operation metrics

        Args:
            vulnerabilities_found: Number of vulnerabilities found
            time_to_first_vuln: Time to first vulnerability in seconds
        """
        metrics = self.data["metrics"]
        metrics["total_operations"] += 1

        # Update average vulnerabilities (simple moving average)
        total_ops = metrics["total_operations"]
        current_avg = metrics["avg_vulnerabilities_per_run"]
        metrics["avg_vulnerabilities_per_run"] = (
            (current_avg * (total_ops - 1) + vulnerabilities_found) / total_ops
        )

        # Update average time to first vuln
        if time_to_first_vuln is not None:
            current_avg_time = metrics.get("avg_time_to_first_vuln", 0.0)
            metrics["avg_time_to_first_vuln"] = (
                (current_avg_time * (total_ops - 1) + time_to_first_vuln) / total_ops
            )

        # Determine improvement trend (simplified)
        # In a real implementation, you'd track this over multiple operations
        if vulnerabilities_found > metrics["avg_vulnerabilities_per_run"]:
            metrics["improvement_trend"] = "increasing"
        elif vulnerabilities_found < metrics["avg_vulnerabilities_per_run"]:
            metrics["improvement_trend"] = "decreasing"
        else:
            metrics["improvement_trend"] = "stable"

        self._save()

    def get_metrics(self) -> Dict[str, Any]:
        """Get all learning metrics"""
        return {
            "technique_success_rates": {
                tech_id: self.get_technique_success_rate(tech_id)
                for tech_id in self.data["techniques"].keys()
            },
            "improvement_trend": self.data["metrics"]["improvement_trend"],
            "total_operations": self.data["metrics"]["total_operations"],
            "avg_vulnerabilities_per_run": self.data["metrics"]["avg_vulnerabilities_per_run"],
            "avg_time_to_first_vuln": self.data["metrics"].get("avg_time_to_first_vuln", 0.0),
            "learned_techniques": self.get_successful_techniques(min_success_rate=0.5),
            "best_attack_paths": self.get_best_attack_paths(limit=5)
        }

    def _extract_focus_areas(self, objective: str) -> List[str]:
        """Extract focus areas from objective string"""
        objective_lower = objective.lower()
        focus_areas = []

        if any(kw in objective_lower for kw in ['password', 'passwd', 'pwd', 'credential', 'login', 'auth']):
            focus_areas.append('credentials')
        if any(kw in objective_lower for kw in ['medical', 'patient', 'health', 'record']):
            focus_areas.append('medical_records')
        if any(kw in objective_lower for kw in ['vulnerability', 'vuln', 'exploit']):
            focus_areas.append('vulnerabilities')
        if any(kw in objective_lower for kw in ['endpoint', 'api', 'service']):
            focus_areas.append('endpoints')

        return focus_areas if focus_areas else ['general']

    def get_all_technique_feedback(self) -> Dict[str, Dict[str, Any]]:
        """Get all technique feedback data"""
        return self.data.get("techniques", {})

    def record_extraction_method(
        self,
        method: str,
        data_type: str,
        success: bool
    ):
        """Record extraction method performance"""
        if "extraction_methods" not in self.data:
            self.data["extraction_methods"] = {}

        if data_type not in self.data["extraction_methods"]:
            self.data["extraction_methods"][data_type] = {}

        if method not in self.data["extraction_methods"][data_type]:
            self.data["extraction_methods"][data_type][method] = {
                "success_count": 0,
                "failure_count": 0
            }

        method_data = self.data["extraction_methods"][data_type][method]
        if success:
            method_data["success_count"] += 1
        else:
            method_data["failure_count"] += 1

        self._save()
        logger.debug(f"Recorded extraction method {method} for {data_type}: success={success}")

    def get_extraction_feedback(self) -> Dict[str, Dict[str, Dict[str, int]]]:
        """Get extraction method feedback by data type"""
        return self.data.get("extraction_methods", {})


# Global feedback tracker instance
_feedback_tracker: Optional[FeedbackTracker] = None


def get_feedback_tracker(feedback_file: Optional[Path] = None) -> FeedbackTracker:
    """Get or create global feedback tracker instance"""
    global _feedback_tracker
    if _feedback_tracker is None:
        _feedback_tracker = FeedbackTracker(feedback_file)
    return _feedback_tracker

