"""
Feedback analyzer for continuous learning metrics
Provides analysis and reporting on learning progress
"""

import logging
from typing import Dict, Any, List
from datetime import datetime
from .core.feedback import get_feedback_tracker

logger = logging.getLogger(__name__)


class FeedbackAnalyzer:
    """Analyzes feedback data to provide learning insights"""

    def __init__(self):
        self.feedback = get_feedback_tracker()

    def get_improvement_summary(self) -> Dict[str, Any]:
        """
        Get summary of learning improvements

        Returns:
            Dictionary with improvement metrics
        """
        metrics = self.feedback.get_metrics()

        # Calculate technique improvement
        techniques = self.feedback.data.get("techniques", {})
        total_techniques = len(techniques)
        successful_techniques = len([
            t for t in techniques.values()
            if t.get("success_count", 0) > 0
        ])

        # Get best performing techniques
        best_techniques = self.feedback.get_successful_techniques(min_success_rate=0.7)

        # Get worst performing techniques
        worst_techniques = []
        for tech_id, tech_data in techniques.items():
            rate = self.feedback.get_technique_success_rate(tech_id)
            if rate < 0.3 and tech_data.get("failure_count", 0) > 0:
                worst_techniques.append({
                    "technique_id": tech_id,
                    "success_rate": rate,
                    "failure_count": tech_data.get("failure_count", 0)
                })
        worst_techniques.sort(key=lambda x: x["failure_count"], reverse=True)

        return {
            "total_operations": metrics["total_operations"],
            "total_techniques_tried": total_techniques,
            "successful_techniques": successful_techniques,
            "success_rate": successful_techniques / max(total_techniques, 1),
            "avg_vulnerabilities_per_run": metrics["avg_vulnerabilities_per_run"],
            "avg_time_to_first_vuln": metrics["avg_time_to_first_vuln"],
            "improvement_trend": metrics["improvement_trend"],
            "best_techniques": best_techniques[:5],
            "worst_techniques": worst_techniques[:5],
            "working_credentials_count": len(self.feedback.data.get("credentials", [])),
            "best_attack_paths": metrics["best_attack_paths"]
        }

    def get_technique_analysis(self, technique_id: str) -> Dict[str, Any]:
        """
        Get detailed analysis for a specific technique

        Args:
            technique_id: MITRE ATT&CK technique ID

        Returns:
            Dictionary with technique analysis
        """
        if technique_id not in self.feedback.data.get("techniques", {}):
            return {
                "technique_id": technique_id,
                "status": "not_tried",
                "message": "This technique has not been attempted yet"
            }

        tech_data = self.feedback.data["techniques"][technique_id]
        success_rate = self.feedback.get_technique_success_rate(technique_id)

        return {
            "technique_id": technique_id,
            "status": "tried",
            "success_rate": success_rate,
            "success_count": tech_data.get("success_count", 0),
            "failure_count": tech_data.get("failure_count", 0),
            "total_attempts": tech_data.get("success_count", 0) + tech_data.get("failure_count", 0),
            "best_payloads": tech_data.get("best_payloads", []),
            "targets": tech_data.get("targets", []),
            "last_success": tech_data.get("last_success"),
            "last_failure": tech_data.get("last_failure"),
            "recommendation": self._get_technique_recommendation(success_rate, tech_data)
        }

    def _get_technique_recommendation(
        self,
        success_rate: float,
        tech_data: Dict[str, Any]
    ) -> str:
        """Get recommendation for a technique based on performance"""
        if success_rate >= 0.8:
            return "Excellent performance - prioritize this technique"
        elif success_rate >= 0.5:
            return "Good performance - continue using this technique"
        elif success_rate >= 0.3:
            return "Moderate performance - consider alternatives"
        elif tech_data.get("failure_count", 0) > 0:
            return "Poor performance - avoid or modify approach"
        else:
            return "Insufficient data - need more attempts"

    def get_learning_progress(self) -> Dict[str, Any]:
        """
        Get learning progress over time

        Returns:
            Dictionary with progress metrics
        """
        metrics = self.feedback.get_metrics()

        # Analyze improvement
        improvement_indicators = []

        if metrics["improvement_trend"] == "increasing":
            improvement_indicators.append("Vulnerabilities found per run is increasing")

        successful_techniques = self.feedback.get_successful_techniques(min_success_rate=0.5)
        if len(successful_techniques) > 0:
            improvement_indicators.append(
                f"{len(successful_techniques)} techniques with >50% success rate"
            )

        working_creds = self.feedback.get_working_credentials()
        if len(working_creds) > 0:
            improvement_indicators.append(
                f"{len(working_creds)} working credentials discovered"
            )

        best_paths = self.feedback.get_best_attack_paths(limit=1)
        if best_paths:
            improvement_indicators.append(
                f"Best attack path: {' → '.join(best_paths[0]['sequence'][:3])} "
                f"({best_paths[0]['success_rate']:.0%} success)"
            )

        return {
            "total_operations": metrics["total_operations"],
            "improvement_trend": metrics["improvement_trend"],
            "indicators": improvement_indicators,
            "metrics": {
                "avg_vulnerabilities_per_run": metrics["avg_vulnerabilities_per_run"],
                "avg_time_to_first_vuln": metrics["avg_time_to_first_vuln"],
                "learned_techniques_count": len(successful_techniques),
                "working_credentials_count": len(working_creds)
            }
        }

    def generate_learning_report(self) -> str:
        """
        Generate a human-readable learning report

        Returns:
            Formatted report string
        """
        summary = self.get_improvement_summary()
        progress = self.get_learning_progress()

        report = []
        report.append("=" * 60)
        report.append("MEDUSA Continuous Learning Report")
        report.append("=" * 60)
        report.append("")

        report.append(f"Total Operations: {summary['total_operations']}")
        report.append(f"Improvement Trend: {summary['improvement_trend'].upper()}")
        report.append("")

        report.append("Performance Metrics:")
        report.append(f"  - Average Vulnerabilities per Run: {summary['avg_vulnerabilities_per_run']:.1f}")
        report.append(f"  - Average Time to First Vulnerability: {summary['avg_time_to_first_vuln']:.1f}s")
        report.append("")

        report.append("Technique Performance:")
        report.append(f"  - Techniques Tried: {summary['total_techniques_tried']}")
        report.append(f"  - Successful Techniques: {summary['successful_techniques']}")
        report.append(f"  - Success Rate: {summary['success_rate']:.1%}")
        report.append("")

        if summary['best_techniques']:
            report.append("Top Performing Techniques:")
            for tech in summary['best_techniques'][:3]:
                report.append(
                    f"  - {tech['technique_id']}: {tech['success_rate']:.0%} "
                    f"({tech['success_count']} successes)"
                )
            report.append("")

        if summary['best_attack_paths']:
            report.append("Best Attack Paths:")
            for path in summary['best_attack_paths'][:3]:
                report.append(
                    f"  - {' → '.join(path['sequence'][:3])}: "
                    f"{path['success_rate']:.0%} success, "
                    f"{path['vulnerabilities_found']} vulnerabilities found"
                )
            report.append("")

        if summary['working_credentials_count'] > 0:
            report.append(f"Working Credentials Discovered: {summary['working_credentials_count']}")
            report.append("")

        report.append("=" * 60)

        return "\n".join(report)

