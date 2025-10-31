"""
Report generation for MEDUSA
Creates JSON logs and HTML reports of penetration testing operations
"""

import json
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
from jinja2 import Template

from medusa.config import get_config


class ReportGenerator:
    """Generates reports for MEDUSA operations"""

    def __init__(self):
        self.config = get_config()

    def save_json_log(self, operation_data: Dict[str, Any], operation_id: str) -> Path:
        """Save structured JSON log of operation"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"run-{timestamp}-{operation_id}.json"
        filepath = self.config.logs_dir / filename

        # Ensure logs directory exists
        self.config.logs_dir.mkdir(parents=True, exist_ok=True)

        # Add metadata
        log_data = {
            "metadata": {
                "operation_id": operation_id,
                "timestamp": datetime.now().isoformat(),
                "medusa_version": "1.0.0",
                "log_format_version": "1.0",
            },
            "operation": operation_data,
        }

        # Write JSON
        with open(filepath, "w") as f:
            json.dump(log_data, f, indent=2, default=str)

        return filepath

    def generate_html_report(self, operation_data: Dict[str, Any], operation_id: str) -> Path:
        """Generate HTML report of operation"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report-{timestamp}-{operation_id}.html"
        filepath = self.config.reports_dir / filename

        # Ensure reports directory exists
        self.config.reports_dir.mkdir(parents=True, exist_ok=True)

        # Generate HTML content
        html_content = self._generate_html_template(operation_data, operation_id)

        # Write HTML
        with open(filepath, "w") as f:
            f.write(html_content)

        return filepath

    def _generate_html_template(self, data: Dict[str, Any], operation_id: str) -> str:
        """Generate HTML report using template"""
        # Simple inline template (in production, use separate template files)
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MEDUSA Security Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        header { border-bottom: 3px solid #e74c3c; padding-bottom: 20px; margin-bottom: 30px; }
        h1 { color: #e74c3c; font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #2c3e50; margin-top: 30px; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #ecf0f1; }
        h3 { color: #34495e; margin-top: 20px; margin-bottom: 10px; }
        .metadata { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .metadata-item { background: #ecf0f1; padding: 15px; border-radius: 5px; }
        .metadata-item strong { display: block; color: #7f8c8d; font-size: 0.85em; margin-bottom: 5px; }
        .metadata-item span { font-size: 1.1em; color: #2c3e50; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card h4 { font-size: 0.9em; opacity: 0.9; margin-bottom: 10px; }
        .summary-card .value { font-size: 2em; font-weight: bold; }
        .finding { background: white; border-left: 4px solid #3498db; padding: 20px; margin: 15px 0; border-radius: 4px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        .finding.critical { border-left-color: #c0392b; background: #ffebee; }
        .finding.high { border-left-color: #e74c3c; background: #fff3e0; }
        .finding.medium { border-left-color: #f39c12; background: #fffbf0; }
        .finding.low { border-left-color: #3498db; background: #e3f2fd; }
        .finding h3 { margin-top: 0; }
        .severity-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-size: 0.85em; font-weight: bold; color: white; }
        .severity-badge.critical { background: #c0392b; }
        .severity-badge.high { background: #e74c3c; }
        .severity-badge.medium { background: #f39c12; }
        .severity-badge.low { background: #3498db; }
        .severity-badge.info { background: #95a5a6; }
        .technique { background: #f8f9fa; padding: 10px 15px; margin: 10px 0; border-radius: 4px; border-left: 3px solid #16a085; }
        .technique-id { font-family: 'Courier New', monospace; color: #16a085; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }
        th { background: #34495e; color: white; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .phase { margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .phase-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .status-badge { padding: 5px 12px; border-radius: 15px; font-size: 0.85em; }
        .status-badge.complete { background: #27ae60; color: white; }
        .status-badge.failed { background: #e74c3c; color: white; }
        .status-badge.skipped { background: #f39c12; color: white; }
        footer { margin-top: 40px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d; font-size: 0.9em; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔴 MEDUSA Security Assessment Report</h1>
            <p style="color: #7f8c8d; font-size: 1.1em;">AI-Powered Penetration Testing Results</p>
        </header>

        <div class="warning">
            <strong>⚠️ CONFIDENTIAL:</strong> This report contains sensitive security information. Protect accordingly.
        </div>

        <section>
            <h2>Executive Summary</h2>
            <div class="metadata">
                <div class="metadata-item">
                    <strong>Operation ID</strong>
                    <span>{{ operation_id }}</span>
                </div>
                <div class="metadata-item">
                    <strong>Generated</strong>
                    <span>{{ generated_at }}</span>
                </div>
                <div class="metadata-item">
                    <strong>Duration</strong>
                    <span>{{ duration }} seconds</span>
                </div>
                <div class="metadata-item">
                    <strong>Target</strong>
                    <span>{{ target }}</span>
                </div>
            </div>

            <div class="summary">
                <div class="summary-card">
                    <h4>Total Findings</h4>
                    <div class="value">{{ summary.total_findings }}</div>
                </div>
                <div class="summary-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                    <h4>Critical/High</h4>
                    <div class="value">{{ summary.critical + summary.high }}</div>
                </div>
                <div class="summary-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                    <h4>Techniques Used</h4>
                    <div class="value">{{ summary.techniques_used }}</div>
                </div>
                <div class="summary-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                    <h4>Success Rate</h4>
                    <div class="value">{{ (summary.success_rate * 100)|int }}%</div>
                </div>
            </div>
        </section>

        <section>
            <h2>Security Findings</h2>
            {% for finding in findings %}
            <div class="finding {{ finding.severity }}">
                <h3>
                    <span class="severity-badge {{ finding.severity }}">{{ finding.severity|upper }}</span>
                    {{ finding.title }}
                </h3>
                <p><strong>Description:</strong> {{ finding.description }}</p>
                {% if finding.affected_endpoints %}
                <p><strong>Affected:</strong> {{ finding.affected_endpoints|join(', ') }}</p>
                {% endif %}
                {% if finding.cvss_score %}
                <p><strong>CVSS Score:</strong> {{ finding.cvss_score }}</p>
                {% endif %}
                <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
            </div>
            {% endfor %}
        </section>

        <section>
            <h2>MITRE ATT&CK Coverage</h2>
            <p>Techniques employed during this assessment:</p>
            {% for technique in mitre_coverage %}
            <div class="technique">
                <span class="technique-id">{{ technique.id }}</span> - {{ technique.name }}
                <span class="status-badge {{ technique.status }}">{{ technique.status }}</span>
            </div>
            {% endfor %}
        </section>

        <section>
            <h2>Operation Phases</h2>
            {% for phase in phases %}
            <div class="phase">
                <div class="phase-header">
                    <h3>{{ phase.name|title }}</h3>
                    <span class="status-badge {{ phase.status }}">{{ phase.status|upper }}</span>
                </div>
                <p><strong>Duration:</strong> {{ phase.duration }} seconds</p>
                <p><strong>Findings:</strong> {{ phase.findings }}</p>
                <p><strong>Techniques:</strong> {{ phase.techniques }}</p>
            </div>
            {% endfor %}
        </section>

        <footer>
            <p>Generated by MEDUSA v1.0.0 | {{ generated_at }}</p>
            <p>For authorized security testing purposes only</p>
        </footer>
    </div>
</body>
</html>
        """

        template = Template(template_str)

        # Prepare template data
        template_data = {
            "operation_id": operation_id,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": data.get("duration_seconds", 0),
            "target": data.get("target", "Unknown"),
            "summary": data.get("summary", {}),
            "findings": data.get("findings", []),
            "mitre_coverage": data.get("mitre_coverage", []),
            "phases": data.get("phases", []),
        }

        return template.render(**template_data)

    def generate_summary_text(self, operation_data: Dict[str, Any]) -> str:
        """Generate a text summary of the operation"""
        summary = operation_data.get("summary", {})
        findings = operation_data.get("findings", [])

        text = f"""
MEDUSA Security Assessment Summary
{'=' * 50}

Total Findings: {summary.get('total_findings', 0)}
  - Critical: {summary.get('critical', 0)}
  - High: {summary.get('high', 0)}
  - Medium: {summary.get('medium', 0)}
  - Low: {summary.get('low', 0)}

Techniques Used: {summary.get('techniques_used', 0)}
Success Rate: {summary.get('success_rate', 0) * 100:.1f}%
Duration: {operation_data.get('duration_seconds', 0):.1f} seconds

Top Findings:
"""

        # Add top 5 findings
        for i, finding in enumerate(findings[:5], 1):
            text += f"\n{i}. [{finding.get('severity', 'unknown').upper()}] {finding.get('title', 'Unknown')}\n"
            text += f"   {finding.get('description', 'No description')}\n"

        return text

