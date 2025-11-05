"""
Session export utilities for MEDUSA
Export sessions to various formats: CSV, JSON, HTML, Markdown
"""

import csv
import json
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path


class SessionExporter:
    """Export sessions to various formats"""

    @staticmethod
    def export_to_csv(session_data: Dict[str, Any], filepath: str) -> str:
        """
        Export session findings to CSV

        Args:
            session_data: Session data dictionary
            filepath: Output CSV file path

        Returns:
            Path to created CSV file
        """
        findings = session_data.get("findings", [])

        if not findings:
            raise ValueError("No findings to export")

        # Prepare CSV data
        fieldnames = [
            "timestamp",
            "type",
            "severity",
            "title",
            "description",
            "port",
            "service",
            "version",
            "cve",
            "cvss_score"
        ]

        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()

            for finding in findings:
                # Flatten finding data
                row = {
                    "timestamp": finding.get("timestamp", ""),
                    "type": finding.get("type", ""),
                    "severity": finding.get("severity", ""),
                    "title": finding.get("title", ""),
                    "description": finding.get("description", ""),
                    "port": finding.get("port", ""),
                    "service": finding.get("service", ""),
                    "version": finding.get("version", ""),
                    "cve": finding.get("cve", ""),
                    "cvss_score": finding.get("cvss_score", "")
                }
                writer.writerow(row)

        return filepath

    @staticmethod
    def export_to_markdown(session_data: Dict[str, Any], filepath: str) -> str:
        """
        Export session to Markdown report

        Args:
            session_data: Session data dictionary
            filepath: Output markdown file path

        Returns:
            Path to created markdown file
        """
        summary = session_data.get("summary", {})
        findings = session_data.get("findings", [])
        command_history = session_data.get("command_history", [])

        with open(filepath, 'w') as f:
            # Header
            f.write("# MEDUSA Penetration Test Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Executive Summary
            f.write("## Executive Summary\n\n")
            f.write(f"- **Target:** {session_data.get('target', 'Unknown')}\n")
            f.write(f"- **Session ID:** {summary.get('session_id', 'Unknown')}\n")
            f.write(f"- **Duration:** {summary.get('duration_seconds', 0):.1f} seconds\n")
            f.write(f"- **Total Findings:** {summary.get('total_findings', 0)}\n")
            f.write(f"- **Commands Executed:** {summary.get('commands_executed', 0)}\n\n")

            # Severity Breakdown
            f.write("### Findings by Severity\n\n")
            severity_counts = summary.get("severity_counts", {})
            f.write(f"- **Critical:** {severity_counts.get('critical', 0)}\n")
            f.write(f"- **High:** {severity_counts.get('high', 0)}\n")
            f.write(f"- **Medium:** {severity_counts.get('medium', 0)}\n")
            f.write(f"- **Low:** {severity_counts.get('low', 0)}\n")
            f.write(f"- **Info:** {severity_counts.get('info', 0)}\n\n")

            # Detailed Findings
            f.write("## Detailed Findings\n\n")

            # Group by severity
            for severity in ["critical", "high", "medium", "low", "info"]:
                severity_findings = [
                    f for f in findings
                    if f.get("severity", "").lower() == severity
                ]

                if severity_findings:
                    f.write(f"### {severity.title()} Severity\n\n")
                    for i, finding in enumerate(severity_findings, 1):
                        f.write(f"#### {i}. {finding.get('title', 'Untitled')}\n\n")
                        f.write(f"- **Type:** {finding.get('type', 'Unknown')}\n")
                        f.write(f"- **Severity:** {finding.get('severity', 'Unknown')}\n")
                        if finding.get("description"):
                            f.write(f"- **Description:** {finding['description']}\n")
                        if finding.get("cve"):
                            f.write(f"- **CVE:** {finding['cve']}\n")
                        if finding.get("cvss_score"):
                            f.write(f"- **CVSS Score:** {finding['cvss_score']}\n")
                        if finding.get("recommendation"):
                            f.write(f"- **Recommendation:** {finding['recommendation']}\n")
                        f.write("\n")

            # Command History
            f.write("## Command History\n\n")
            f.write("| # | Time | Command | Phase |\n")
            f.write("|---|------|---------|-------|\n")

            for i, cmd in enumerate(command_history[:50], 1):  # Limit to 50
                timestamp = cmd.get("timestamp", "")
                time_str = timestamp.split("T")[1][:8] if "T" in timestamp else timestamp
                command = cmd.get("command", "")[:50]
                phase = cmd.get("phase", "unknown")
                f.write(f"| {i} | {time_str} | {command} | {phase} |\n")

            f.write("\n")

            # Footer
            f.write("---\n\n")
            f.write("*Generated by MEDUSA AI Penetration Testing Agent*\n")

        return filepath

    @staticmethod
    def export_to_html(session_data: Dict[str, Any], filepath: str) -> str:
        """
        Export session to enhanced HTML report

        Args:
            session_data: Session data dictionary
            filepath: Output HTML file path

        Returns:
            Path to created HTML file
        """
        summary = session_data.get("summary", {})
        findings = session_data.get("findings", [])
        command_history = session_data.get("command_history", [])

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MEDUSA Penetration Test Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header p {{
            opacity: 0.9;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f9f9f9;
        }}

        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            text-align: center;
        }}

        .summary-card h3 {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}

        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}

        .severity-breakdown {{
            padding: 30px;
        }}

        .severity-item {{
            display: flex;
            align-items: center;
            margin-bottom: 15px;
        }}

        .severity-label {{
            width: 100px;
            font-weight: bold;
        }}

        .severity-bar {{
            flex: 1;
            height: 30px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            margin: 0 15px;
        }}

        .severity-fill {{
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            color: white;
            font-weight: bold;
        }}

        .critical {{ background: #d32f2f; }}
        .high {{ background: #f57c00; }}
        .medium {{ background: #fbc02d; color: #333 !important; }}
        .low {{ background: #388e3c; }}
        .info {{ background: #1976d2; }}

        .findings {{
            padding: 30px;
        }}

        .finding {{
            background: white;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }}

        .finding.critical {{ border-left-color: #d32f2f; }}
        .finding.high {{ border-left-color: #f57c00; }}
        .finding.medium {{ border-left-color: #fbc02d; }}
        .finding.low {{ border-left-color: #388e3c; }}

        .finding h3 {{
            color: #333;
            margin-bottom: 10px;
        }}

        .finding .meta {{
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
            font-size: 0.9em;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .badge.critical {{ background: #ffebee; color: #d32f2f; }}
        .badge.high {{ background: #fff3e0; color: #f57c00; }}
        .badge.medium {{ background: #fffde7; color: #f57f17; }}
        .badge.low {{ background: #e8f5e9; color: #388e3c; }}
        .badge.info {{ background: #e3f2fd; color: #1976d2; }}

        .command-history {{
            padding: 30px;
            background: #f9f9f9;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
        }}

        th, td {{
            padding: 12px 15px;
            text-align: left;
        }}

        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}

        tr:nth-child(even) {{
            background: #f9f9f9;
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔱 MEDUSA</h1>
            <p>AI-Powered Penetration Testing Report</p>
            <p style="margin-top: 10px;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Target</h3>
                <div class="value" style="font-size: 1.2em;">{session_data.get('target', 'Unknown')}</div>
            </div>
            <div class="summary-card">
                <h3>Duration</h3>
                <div class="value">{summary.get('duration_seconds', 0):.0f}s</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{summary.get('total_findings', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Commands</h3>
                <div class="value">{summary.get('commands_executed', 0)}</div>
            </div>
        </div>

        <div class="severity-breakdown">
            <h2 style="margin-bottom: 20px;">Severity Breakdown</h2>
"""

        severity_counts = summary.get("severity_counts", {})
        total_findings = summary.get("total_findings", 0)

        for severity, label, color in [
            ("critical", "Critical", "critical"),
            ("high", "High", "high"),
            ("medium", "Medium", "medium"),
            ("low", "Low", "low"),
            ("info", "Info", "info")
        ]:
            count = severity_counts.get(severity, 0)
            percentage = (count / total_findings * 100) if total_findings > 0 else 0

            html_content += f"""
            <div class="severity-item">
                <div class="severity-label {color}">{label}</div>
                <div class="severity-bar">
                    <div class="severity-fill {color}" style="width: {percentage}%;">
                        {count}
                    </div>
                </div>
            </div>
"""

        html_content += """
        </div>

        <div class="findings">
            <h2 style="margin-bottom: 20px;">Detailed Findings</h2>
"""

        # Add findings
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            title = finding.get("title", "Untitled Finding")
            description = finding.get("description", "No description available")
            finding_type = finding.get("type", "unknown")

            html_content += f"""
            <div class="finding {severity}">
                <h3>{title}</h3>
                <div class="meta">
                    <span class="badge {severity}">{severity.upper()}</span>
                    <span style="color: #666;">Type: {finding_type}</span>
"""
            if finding.get("cve"):
                html_content += f'<span style="color: #666;">CVE: {finding["cve"]}</span>'
            if finding.get("cvss_score"):
                html_content += f'<span style="color: #666;">CVSS: {finding["cvss_score"]}</span>'

            html_content += f"""
                </div>
                <p>{description}</p>
"""
            if finding.get("recommendation"):
                html_content += f'<p style="margin-top: 10px;"><strong>Recommendation:</strong> {finding["recommendation"]}</p>'

            html_content += """
            </div>
"""

        html_content += """
        </div>

        <div class="command-history">
            <h2 style="margin-bottom: 20px;">Command History</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Time</th>
                        <th>Command</th>
                        <th>Phase</th>
                    </tr>
                </thead>
                <tbody>
"""

        for i, cmd in enumerate(command_history[:50], 1):
            timestamp = cmd.get("timestamp", "")
            time_str = timestamp.split("T")[1][:8] if "T" in timestamp else timestamp
            command = cmd.get("command", "")[:80]
            phase = cmd.get("phase", "unknown")

            html_content += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{time_str}</td>
                        <td>{command}</td>
                        <td>{phase}</td>
                    </tr>
"""

        html_content += f"""
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Session ID: {summary.get('session_id', 'Unknown')}</p>
            <p style="margin-top: 5px;">Generated by MEDUSA AI Penetration Testing Agent</p>
        </div>
    </div>
</body>
</html>
"""

        with open(filepath, 'w') as f:
            f.write(html_content)

        return filepath
