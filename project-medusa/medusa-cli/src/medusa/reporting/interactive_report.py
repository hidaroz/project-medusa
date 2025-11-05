"""
Generate interactive HTML reports with charts and visualizations
"""
from dataclasses import dataclass
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
import json


class InteractiveReportGenerator:
    """Generate interactive HTML reports"""

    def __init__(self):
        self.template = self._get_template()

    def generate(
        self,
        findings: List[Dict[str, Any]],
        target: str,
        output_path: Path
    ):
        """Generate interactive report"""

        # Calculate summary stats
        summary = {
            "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "medium": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "low": sum(1 for f in findings if f.get("severity") == "LOW"),
            "total": len(findings)
        }

        # Extract MITRE ATT&CK techniques
        techniques = {}
        for finding in findings:
            tech_id = finding.get("technique_id")
            if tech_id:
                techniques[tech_id] = techniques.get(tech_id, 0) + 1

        attack_techniques = {
            "labels": list(techniques.keys()),
            "counts": list(techniques.values())
        }

        # Prepare report data
        report_data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": findings,
            "summary": summary,
            "attack_techniques": attack_techniques
        }

        # Build HTML
        html = self._build_html(
            target=target,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=findings,
            summary=summary,
            attack_techniques=attack_techniques,
            report_data=report_data
        )

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html)

        return output_path

    def _build_html(self, **kwargs):
        """Build the full HTML report"""
        findings_html = self._build_findings(kwargs['findings'])
        summary_cards = self._build_summary_cards(kwargs['summary'])
        chart_data = json.dumps(kwargs['report_data'])

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MEDUSA Report - {kwargs['target']}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        body {{ font-family: 'Inter', sans-serif; }}
        .severity-critical {{ background-color: #dc2626; color: white; }}
        .severity-high {{ background-color: #ea580c; color: white; }}
        .severity-medium {{ background-color: #f59e0b; color: white; }}
        .severity-low {{ background-color: #3b82f6; color: white; }}
        .severity-info {{ background-color: #6b7280; color: white; }}
        .finding-card {{ transition: all 0.3s ease; border-left: 4px solid transparent; }}
        .finding-card:hover {{ transform: translateY(-2px); box-shadow: 0 10px 30px -10px rgba(0,0,0,0.3); }}
        .finding-card.critical {{ border-left-color: #dc2626; }}
        .finding-card.high {{ border-left-color: #ea580c; }}
        .finding-card.medium {{ border-left-color: #f59e0b; }}
        .finding-card.low {{ border-left-color: #3b82f6; }}
        .tab-button.active {{ background-color: #3b82f6; color: white; }}
        @media print {{ .no-print {{ display: none; }} .finding-card {{ page-break-inside: avoid; }} }}
    </style>
</head>
<body class="bg-gray-50">
    <!-- Header -->
    <div class="bg-gradient-to-r from-blue-600 to-purple-600 text-white py-8 shadow-lg no-print">
        <div class="container mx-auto px-6">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-4xl font-bold mb-2">🛡️ MEDUSA Security Assessment</h1>
                    <p class="text-blue-100 text-lg">{kwargs['target']}</p>
                </div>
                <div class="text-right">
                    <p class="text-sm text-blue-100">Generated</p>
                    <p class="text-xl font-semibold">{kwargs['timestamp']}</p>
                </div>
            </div>
        </div>
    </div>

    <div class="container mx-auto px-6 py-8">
        {summary_cards}

        <!-- Charts -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div class="bg-white rounded-lg shadow-md p-6">
                <h3 class="text-lg font-semibold mb-4">Findings by Severity</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="bg-white rounded-lg shadow-md p-6">
                <h3 class="text-lg font-semibold mb-4">MITRE ATT&CK Coverage</h3>
                <canvas id="attackChart"></canvas>
            </div>
        </div>

        <!-- Findings -->
        <div class="bg-white rounded-lg shadow-md mb-8">
            <div class="border-b">
                <div class="p-4 bg-gray-50 no-print">
                    <input type="text" id="searchInput" placeholder="Search findings..."
                           class="w-full px-4 py-2 border rounded-lg" onkeyup="filterFindings()">
                </div>
            </div>
            <div id="findingsContainer" class="p-6">
                {findings_html}
            </div>
        </div>

        <!-- Export Buttons -->
        <div class="flex gap-4 no-print">
            <button onclick="window.print()" class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700">
                📄 Export PDF
            </button>
            <button onclick="exportJSON()" class="bg-green-600 text-white px-6 py-3 rounded-lg hover:bg-green-700">
                📊 Export JSON
            </button>
            <button onclick="exportCSV()" class="bg-purple-600 text-white px-6 py-3 rounded-lg hover:bg-purple-700">
                📈 Export CSV
            </button>
        </div>
    </div>

    <!-- Footer -->
    <div class="bg-gray-800 text-white py-6 mt-12">
        <div class="container mx-auto px-6 text-center">
            <p class="text-gray-400">Generated by MEDUSA v2.0 • {kwargs['timestamp']}</p>
            <p class="text-sm text-gray-500 mt-2">⚠️ For authorized testing only</p>
        </div>
    </div>

    <script>
        const reportData = {chart_data};

        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{kwargs['summary']['critical']}, {kwargs['summary']['high']},
                           {kwargs['summary']['medium']}, {kwargs['summary']['low']}],
                    backgroundColor: ['#dc2626', '#ea580c', '#f59e0b', '#3b82f6']
                }}]
            }},
            options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom' }} }} }}
        }});

        // MITRE ATT&CK Chart
        const attackCtx = document.getElementById('attackChart').getContext('2d');
        new Chart(attackCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(kwargs['attack_techniques']['labels'])},
                datasets: [{{
                    label: 'Techniques Detected',
                    data: {json.dumps(kwargs['attack_techniques']['counts'])},
                    backgroundColor: '#3b82f6'
                }}]
            }},
            options: {{ responsive: true, scales: {{ y: {{ beginAtZero: true }} }} }}
        }});

        function filterFindings() {{
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const findings = document.querySelectorAll('.finding-card');
            findings.forEach(finding => {{
                const text = finding.dataset.search;
                finding.style.display = text.includes(searchTerm) ? 'block' : 'none';
            }});
        }}

        function toggleDetails(id) {{
            const element = document.getElementById(id);
            element.classList.toggle('hidden');
        }}

        function exportJSON() {{
            const dataStr = JSON.stringify(reportData, null, 2);
            const dataBlob = new Blob([dataStr], {{type: 'application/json'}});
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'medusa-report-{kwargs['timestamp']}.json';
            link.click();
        }}

        function exportCSV() {{
            const findings = reportData.findings;
            let csv = 'Severity,Title,Description,Technique,Recommendation\\n';
            findings.forEach(finding => {{
                csv += `"${{finding.severity}}","${{finding.title}}","${{finding.description}}","${{finding.technique_id || ''}}","${{finding.recommendation || ''}}"\\n`;
            }});
            const blob = new Blob([csv], {{type: 'text/csv'}});
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'medusa-report-{kwargs['timestamp']}.csv';
            link.click();
        }}
    </script>
</body>
</html>"""

    def _build_summary_cards(self, summary):
        """Build summary cards HTML"""
        return f"""
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="bg-white rounded-lg shadow-md p-6 border-t-4 border-red-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm uppercase font-semibold">Critical</p>
                        <p class="text-4xl font-bold text-red-600">{summary['critical']}</p>
                    </div>
                    <div class="text-red-500 text-4xl">⚠️</div>
                </div>
            </div>
            <div class="bg-white rounded-lg shadow-md p-6 border-t-4 border-orange-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm uppercase font-semibold">High</p>
                        <p class="text-4xl font-bold text-orange-600">{summary['high']}</p>
                    </div>
                    <div class="text-orange-500 text-4xl">⚡</div>
                </div>
            </div>
            <div class="bg-white rounded-lg shadow-md p-6 border-t-4 border-yellow-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm uppercase font-semibold">Medium</p>
                        <p class="text-4xl font-bold text-yellow-600">{summary['medium']}</p>
                    </div>
                    <div class="text-yellow-500 text-4xl">⚠</div>
                </div>
            </div>
            <div class="bg-white rounded-lg shadow-md p-6 border-t-4 border-blue-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm uppercase font-semibold">Total Findings</p>
                        <p class="text-4xl font-bold text-blue-600">{summary['total']}</p>
                    </div>
                    <div class="text-blue-500 text-4xl">📊</div>
                </div>
            </div>
        </div>
        """

    def _build_findings(self, findings):
        """Build findings HTML"""
        findings_html = ""
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'UNKNOWN').lower()
            title = finding.get('title', 'Untitled')
            description = finding.get('description', 'No description')
            evidence = finding.get('evidence', '')
            recommendation = finding.get('recommendation', '')
            technique_id = finding.get('technique_id', '')

            search_text = f"{title} {description}".lower()

            findings_html += f"""
            <div class="finding-card {severity} bg-white rounded-lg shadow p-6 mb-4"
                 data-severity="{severity}" data-search="{search_text}">
                <div class="flex items-start justify-between mb-4">
                    <div class="flex-1">
                        <div class="flex items-center gap-2 mb-2">
                            <span class="severity-{severity} px-3 py-1 rounded-full text-xs font-bold uppercase">
                                {finding.get('severity', 'UNKNOWN')}
                            </span>
                            {f'<span class="bg-gray-200 text-gray-700 px-3 py-1 rounded-full text-xs font-mono">{technique_id}</span>' if technique_id else ''}
                        </div>
                        <h3 class="text-xl font-semibold text-gray-800 mb-2">{title}</h3>
                    </div>
                    <button class="text-blue-600 hover:text-blue-800 no-print" onclick="toggleDetails('finding-{i}')">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                        </svg>
                    </button>
                </div>
                <p class="text-gray-600 mb-4">{description}</p>
                <div id="finding-{i}" class="hidden mt-4 border-t pt-4">
                    {f'<div class="mb-4"><h4 class="font-semibold text-gray-700 mb-2">Evidence:</h4><pre class="bg-gray-100 p-3 rounded text-sm overflow-x-auto">{evidence}</pre></div>' if evidence else ''}
                    {f'<div class="mb-4"><h4 class="font-semibold text-gray-700 mb-2">Recommendation:</h4><p class="text-gray-600">{recommendation}</p></div>' if recommendation else ''}
                </div>
            </div>
            """
        return findings_html

    def _get_template(self):
        """Placeholder for template - not used in this implementation"""
        return None
