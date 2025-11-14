"""
Report Generator
Generates professional security reports
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import logging


class ReportGenerator:
    """
    Generates security assessment reports

    Supports multiple formats:
    - PDF (professional)
    - Markdown (editable)
    - JSON (machine-readable)
    - SARIF (CI/CD integration)
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_report(
        self,
        operation_data: Dict[str, Any],
        output_path: Path,
        format_type: str = "markdown",
        template: Optional[str] = None
    ) -> bool:
        """
        Generate a report

        Args:
            operation_data: Operation data dictionary
            output_path: Output file path
            format_type: Report format (pdf, markdown, json, sarif)
            template: Custom template name

        Returns:
            True if report generated successfully
        """
        try:
            self.logger.info(f"Generating {format_type} report: {output_path}")

            if format_type == "markdown":
                return self._generate_markdown(operation_data, output_path)
            elif format_type == "json":
                return self._generate_json(operation_data, output_path)
            elif format_type == "pdf":
                return self._generate_pdf(operation_data, output_path)
            elif format_type == "sarif":
                return self._generate_sarif(operation_data, output_path)
            else:
                self.logger.error(f"Unknown format: {format_type}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            return False

    def _generate_markdown(self, data: Dict[str, Any], output_path: Path) -> bool:
        """Generate Markdown report"""
        import json

        report_lines = []

        # Header
        report_lines.append("# MEDUSA Security Assessment Report")
        report_lines.append(f"\nGenerated: {datetime.now().isoformat()}")
        report_lines.append(f"\nOperation ID: {data.get('operation_id', 'N/A')}")
        report_lines.append(f"\nTarget: {data.get('target', 'N/A')}")

        # Summary
        report_lines.append("\n## Executive Summary")
        report_lines.append(f"\n{data.get('summary', 'No summary available')}")

        # Findings
        findings = data.get('findings', [])
        report_lines.append(f"\n## Findings ({len(findings)})")

        for i, finding in enumerate(findings, 1):
            report_lines.append(f"\n### {i}. {finding.get('title', 'Unknown')}")
            report_lines.append(f"\n**Severity:** {finding.get('severity', 'Unknown')}")
            report_lines.append(f"\n**Description:** {finding.get('description', 'N/A')}")

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write("\n".join(report_lines))

        self.logger.info(f"Markdown report saved: {output_path}")
        return True

    def _generate_json(self, data: Dict[str, Any], output_path: Path) -> bool:
        """Generate JSON report"""
        import json

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        self.logger.info(f"JSON report saved: {output_path}")
        return True

    def _generate_pdf(self, data: Dict[str, Any], output_path: Path) -> bool:
        """Generate PDF report (placeholder)"""
        self.logger.warning("PDF generation not yet implemented")
        # Would use reportlab or weasyprint
        return False

    def _generate_sarif(self, data: Dict[str, Any], output_path: Path) -> bool:
        """Generate SARIF report for CI/CD integration"""
        import json

        # SARIF format
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MEDUSA",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/yourusername/medusa"
                        }
                    },
                    "results": self._convert_findings_to_sarif(data.get('findings', []))
                }
            ]
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)

        self.logger.info(f"SARIF report saved: {output_path}")
        return True

    def _convert_findings_to_sarif(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert findings to SARIF format"""
        sarif_results = []

        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        for finding in findings:
            sarif_results.append({
                "ruleId": finding.get('cve_id', finding.get('id', 'unknown')),
                "level": severity_map.get(finding.get('severity', 'info').lower(), "note"),
                "message": {
                    "text": finding.get('description', 'No description')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get('target', 'unknown')
                            }
                        }
                    }
                ]
            })

        return sarif_results
