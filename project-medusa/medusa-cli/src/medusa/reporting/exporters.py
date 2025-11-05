"""
Multiple export format support
"""
import json
import csv
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


class JSONExporter:
    """Export findings as JSON"""

    @staticmethod
    def export(findings: List[Dict[str, Any]], output_path: Path):
        """Export to JSON"""
        data = {
            "medusa_version": "2.0",
            "generated_at": datetime.now().isoformat(),
            "findings_count": len(findings),
            "findings": findings
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)


class CSVExporter:
    """Export findings as CSV"""

    @staticmethod
    def export(findings: List[Dict[str, Any]], output_path: Path):
        """Export to CSV"""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'severity', 'title', 'description', 'technique_id',
                'technique_name', 'recommendation', 'evidence'
            ])
            writer.writeheader()

            for finding in findings:
                writer.writerow({
                    'severity': finding.get('severity', ''),
                    'title': finding.get('title', ''),
                    'description': finding.get('description', ''),
                    'technique_id': finding.get('technique_id', ''),
                    'technique_name': finding.get('technique_name', ''),
                    'recommendation': finding.get('recommendation', ''),
                    'evidence': finding.get('evidence', '')
                })


class MarkdownExporter:
    """Export findings as Markdown"""

    @staticmethod
    def export(findings: List[Dict[str, Any]], target: str, output_path: Path):
        """Export to Markdown"""
        md = f"# MEDUSA Security Assessment Report\n\n"
        md += f"**Target:** {target}  \n"
        md += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n"
        md += f"**Total Findings:** {len(findings)}  \n\n"

        # Summary
        md += "## Executive Summary\n\n"
        summary = {
            "CRITICAL": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "LOW": sum(1 for f in findings if f.get("severity") == "LOW"),
        }

        for severity, count in summary.items():
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
            md += f"- {emoji[severity]} **{severity}:** {count} findings\n"

        md += "\n---\n\n"

        # Findings
        md += "## Findings\n\n"

        for i, finding in enumerate(findings, 1):
            md += f"### {i}. {finding.get('title', 'Untitled')}\n\n"
            md += f"**Severity:** {finding.get('severity', 'UNKNOWN')}  \n"

            if finding.get('technique_id'):
                md += f"**MITRE ATT&CK:** {finding['technique_id']} - {finding.get('technique_name', '')}  \n"

            md += f"\n**Description:**  \n{finding.get('description', 'No description')}\n\n"

            if finding.get('evidence'):
                md += f"**Evidence:**\n```\n{finding['evidence']}\n```\n\n"

            if finding.get('recommendation'):
                md += f"**Recommendation:**  \n{finding['recommendation']}\n\n"

            md += "---\n\n"

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(md)
