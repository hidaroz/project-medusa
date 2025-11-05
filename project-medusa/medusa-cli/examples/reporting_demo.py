#!/usr/bin/env python3
"""
MEDUSA Reporting Demo
Demonstrates all reporting capabilities with sample data
"""

import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from medusa.reporter import ReportGenerator
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Comprehensive sample data with realistic findings
DEMO_DATA = {
    "target": "demo.example.com",
    "duration_seconds": 247,
    "summary": {
        "total_findings": 8,
        "critical": 2,
        "high": 2,
        "medium": 3,
        "low": 1,
        "techniques_used": 12,
        "success_rate": 0.92,
    },
    "findings": [
        {
            "severity": "critical",
            "title": "SQL Injection in Authentication",
            "description": "The application login form is vulnerable to SQL injection attacks. "
            "Attackers can bypass authentication using a simple ' OR '1'='1 payload.",
            "affected_endpoints": ["/api/login", "/api/auth"],
            "cvss_score": 9.8,
            "impact": "Complete compromise of authentication system. Attackers can access any user account "
            "without credentials and extract sensitive database contents including passwords, personal information, "
            "and financial data.",
            "recommendation": "Implement parameterized queries immediately. Use prepared statements with bound "
            "parameters. Deploy a Web Application Firewall (WAF) as temporary mitigation. Conduct security code "
            "review of all database interactions.",
        },
        {
            "severity": "critical",
            "title": "Remote Code Execution via File Upload",
            "description": "The file upload functionality does not properly validate file types. "
            "Attackers can upload and execute malicious PHP files on the server.",
            "affected_endpoints": ["/api/upload", "/files/upload"],
            "cvss_score": 9.9,
            "impact": "Complete server compromise. Attackers can execute arbitrary code, install backdoors, "
            "access sensitive files, pivot to internal network, and establish persistence.",
            "recommendation": "Implement strict file type validation using magic bytes, not extensions. "
            "Store uploaded files outside webroot. Remove execute permissions. Use virus scanning. "
            "Consider storing files in object storage like S3.",
        },
        {
            "severity": "high",
            "title": "Cross-Site Scripting (XSS) in Search",
            "description": "Reflected XSS vulnerability found in search parameter. User input is not properly "
            "sanitized before being included in HTML response.",
            "affected_endpoints": ["/search", "/api/search"],
            "cvss_score": 7.5,
            "impact": "Attackers can steal session cookies, perform actions as the victim user, deface pages, "
            "or redirect users to malicious sites. Can be used for phishing attacks.",
            "recommendation": "Implement output encoding for all user-supplied data. Use Content Security Policy (CSP) "
            "headers. Enable HTTPOnly and Secure flags on cookies. Consider using a template engine with automatic "
            "escaping.",
        },
        {
            "severity": "high",
            "title": "Insecure Direct Object Reference (IDOR)",
            "description": "Users can access other users' data by manipulating URL parameters. "
            "No authorization checks on user profile endpoints.",
            "affected_endpoints": ["/api/users/{id}", "/profile/{id}"],
            "cvss_score": 7.1,
            "impact": "Unauthorized access to personal information including email addresses, phone numbers, "
            "addresses, and purchase history of other users.",
            "recommendation": "Implement proper authorization checks. Verify user has permission to access requested "
            "resource. Use indirect references or UUIDs instead of sequential IDs. Log access attempts for monitoring.",
        },
        {
            "severity": "medium",
            "title": "Missing Security Headers",
            "description": "Critical security headers are not configured: X-Frame-Options, X-Content-Type-Options, "
            "Strict-Transport-Security, Content-Security-Policy.",
            "affected_endpoints": ["All endpoints"],
            "recommendation": "Configure security headers in web server or application middleware. "
            "Set X-Frame-Options: DENY, X-Content-Type-Options: nosniff, HSTS with max-age of at least 31536000.",
        },
        {
            "severity": "medium",
            "title": "Weak Password Policy",
            "description": "Password policy allows weak passwords. Minimum length is only 6 characters. "
            "No complexity requirements enforced.",
            "recommendation": "Implement strong password policy: minimum 12 characters, require uppercase, lowercase, "
            "numbers, and special characters. Use password strength meter. Consider passwordless authentication.",
        },
        {
            "severity": "medium",
            "title": "Unencrypted Sensitive Data Storage",
            "description": "Sensitive user data including credit card information is stored in plaintext in database.",
            "recommendation": "Encrypt sensitive data at rest using AES-256. Use proper key management system. "
            "Consider using tokenization for payment card data. Implement field-level encryption.",
        },
        {
            "severity": "low",
            "title": "Information Disclosure in Headers",
            "description": "Server version and technology stack are exposed in HTTP response headers.",
            "recommendation": "Configure web server to hide version information. Remove X-Powered-By headers. "
            "Use generic error pages that don't reveal stack traces.",
        },
    ],
    "mitre_coverage": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "status": "executed"},
        {"id": "T1078", "name": "Valid Accounts", "status": "executed"},
        {"id": "T1059.004", "name": "Unix Shell", "status": "executed"},
        {"id": "T1071.001", "name": "Web Protocols", "status": "executed"},
        {"id": "T1083", "name": "File and Directory Discovery", "status": "executed"},
        {"id": "T1082", "name": "System Information Discovery", "status": "executed"},
        {"id": "T1018", "name": "Remote System Discovery", "status": "executed"},
        {"id": "T1046", "name": "Network Service Scanning", "status": "executed"},
        {"id": "T1595.002", "name": "Vulnerability Scanning", "status": "executed"},
        {"id": "T1589.002", "name": "Email Addresses", "status": "executed"},
        {"id": "T1590.001", "name": "Domain Properties", "status": "executed"},
        {"id": "T1592.002", "name": "Software", "status": "skipped"},
    ],
    "phases": [
        {
            "name": "reconnaissance",
            "status": "complete",
            "duration": 45,
            "findings": 1,
            "techniques": 3,
        },
        {
            "name": "enumeration",
            "status": "complete",
            "duration": 67,
            "findings": 3,
            "techniques": 4,
        },
        {
            "name": "vulnerability_scanning",
            "status": "complete",
            "duration": 89,
            "findings": 4,
            "techniques": 4,
        },
        {
            "name": "exploitation",
            "status": "complete",
            "duration": 46,
            "findings": 0,
            "techniques": 1,
        },
    ],
}


def print_banner():
    """Display demo banner"""
    banner = """
[bold cyan]╔═══════════════════════════════════════════╗[/bold cyan]
[bold cyan]║     MEDUSA REPORTING DEMO                 ║[/bold cyan]
[bold cyan]║     Showcasing Professional Reports       ║[/bold cyan]
[bold cyan]╚═══════════════════════════════════════════╝[/bold cyan]
    """
    console.print(Panel(banner, border_style="cyan"))


def print_section(title: str):
    """Print section header"""
    console.print(f"\n[bold yellow]{'=' * 60}[/bold yellow]")
    console.print(f"[bold yellow]{title}[/bold yellow]")
    console.print(f"[bold yellow]{'=' * 60}[/bold yellow]\n")


def demonstrate_reports():
    """Demonstrate all report types"""
    print_banner()

    # Initialize reporter
    print_section("Initializing Reporter")
    console.print("📋 Creating ReportGenerator instance...")
    reporter = ReportGenerator()
    console.print(f"✅ Reports will be saved to: [cyan]{reporter.config.reports_dir}[/cyan]\n")

    operation_id = f"demo-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    console.print(f"🆔 Operation ID: [cyan]{operation_id}[/cyan]\n")

    # Display sample data summary
    print_section("Sample Assessment Data")

    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="green")

    summary_table.add_row("Target", DEMO_DATA["target"])
    summary_table.add_row("Duration", f"{DEMO_DATA['duration_seconds']}s")
    summary_table.add_row("Total Findings", str(DEMO_DATA["summary"]["total_findings"]))
    summary_table.add_row("Critical", str(DEMO_DATA["summary"]["critical"]))
    summary_table.add_row("High", str(DEMO_DATA["summary"]["high"]))
    summary_table.add_row("Medium", str(DEMO_DATA["summary"]["medium"]))
    summary_table.add_row("Low", str(DEMO_DATA["summary"]["low"]))
    summary_table.add_row("MITRE Techniques", str(DEMO_DATA["summary"]["techniques_used"]))

    console.print(summary_table)

    # Generate all report types
    print_section("Generating All Report Types")

    reports = []

    try:
        # 1. JSON Log
        console.print("[bold]1️⃣  JSON Log (Structured Data)[/bold]")
        console.print("   Purpose: Machine-readable structured data for automation")
        json_path = reporter.save_json_log(DEMO_DATA, operation_id)
        reports.append(("JSON Log", json_path, "🔷"))
        console.print(f"   ✅ Generated: [dim]{json_path.name}[/dim]\n")

        # 2. Technical HTML Report
        console.print("[bold]2️⃣  Technical HTML Report[/bold]")
        console.print("   Purpose: Detailed technical analysis for security professionals")
        console.print("   Features: Dark theme, CVSS scores, MITRE ATT&CK mapping")
        tech_path = reporter.generate_html_report(
            DEMO_DATA, operation_id, report_type="technical"
        )
        reports.append(("Technical Report (HTML)", tech_path, "📄"))
        console.print(f"   ✅ Generated: [dim]{tech_path.name}[/dim]\n")

        # 3. Executive Summary
        console.print("[bold]3️⃣  Executive Summary[/bold]")
        console.print("   Purpose: Business-focused report for management")
        console.print("   Features: Risk ratings, business impact, remediation timeline")
        exec_path = reporter.generate_executive_summary(DEMO_DATA, operation_id)
        reports.append(("Executive Summary (HTML)", exec_path, "📈"))
        console.print(f"   ✅ Generated: [dim]{exec_path.name}[/dim]\n")

        # 4. Markdown Report
        console.print("[bold]4️⃣  Markdown Report[/bold]")
        console.print("   Purpose: Documentation and version control integration")
        console.print("   Features: GitHub/GitLab ready, easy to diff, portable")
        md_path = reporter.generate_markdown_report(DEMO_DATA, operation_id)
        reports.append(("Markdown Report", md_path, "📝"))
        console.print(f"   ✅ Generated: [dim]{md_path.name}[/dim]\n")

        # 5. PDF Report (optional)
        console.print("[bold]5️⃣  PDF Report (Optional)[/bold]")
        console.print("   Purpose: Printable and shareable document")
        console.print("   Requires: pip install weasyprint")
        pdf_path = reporter.generate_pdf_report(DEMO_DATA, operation_id)
        if pdf_path:
            reports.append(("PDF Report", pdf_path, "📕"))
            console.print(f"   ✅ Generated: [dim]{pdf_path.name}[/dim]\n")
        else:
            console.print("   ⚠️  Skipped: weasyprint not installed\n")

    except Exception as e:
        console.print(f"[red]❌ Error generating reports: {e}[/red]")
        import traceback

        traceback.print_exc()
        return False

    # Summary
    print_section("Summary - Reports Generated")

    report_table = Table(show_header=True, header_style="bold cyan")
    report_table.add_column("Type", style="cyan")
    report_table.add_column("File Name", style="white")
    report_table.add_column("Size", style="green")

    for report_type, report_path, icon in reports:
        size_kb = report_path.stat().st_size / 1024
        report_table.add_row(f"{icon} {report_type}", report_path.name, f"{size_kb:.1f} KB")

    console.print(report_table)

    # Next steps
    print_section("Next Steps - View the Reports")

    console.print("[bold cyan]CLI Commands:[/bold cyan]\n")

    console.print("📊 List all reports:")
    console.print("   [dim]medusa reports[/dim]\n")

    console.print("🌐 Open technical report in browser:")
    console.print("   [dim]medusa reports --type html --open[/dim]\n")

    console.print("📈 Open executive summary:")
    console.print("   [dim]medusa reports --type exec --open[/dim]\n")

    console.print("📝 View markdown report:")
    console.print(f"   [dim]cat {md_path}[/dim]\n")

    console.print("🔄 Generate reports from log:")
    console.print("   [dim]medusa generate-report --type all[/dim]\n")

    print_section("Report Locations")

    console.print(f"[bold]Reports Directory:[/bold] [cyan]{reporter.config.reports_dir}[/cyan]\n")
    console.print(f"[bold]Logs Directory:[/bold] [cyan]{reporter.config.logs_dir}[/cyan]\n")

    # Feature highlights
    print_section("Report Features Highlight")

    features_table = Table(show_header=True, header_style="bold magenta")
    features_table.add_column("Feature", style="cyan")
    features_table.add_column("Technical", style="white", justify="center")
    features_table.add_column("Executive", style="white", justify="center")
    features_table.add_column("Markdown", style="white", justify="center")

    features = [
        ("Dark Professional Theme", "✅", "❌", "N/A"),
        ("CVSS Scores", "✅", "✅", "✅"),
        ("MITRE ATT&CK Mapping", "✅", "✅", "✅"),
        ("Business Impact", "✅", "✅", "✅"),
        ("Technical Details", "✅", "❌", "✅"),
        ("Remediation Timeline", "✅", "✅", "✅"),
        ("Risk Ratings", "✅", "✅", "✅"),
        ("Version Control Ready", "❌", "❌", "✅"),
        ("Print Ready", "✅", "✅", "✅"),
    ]

    for feature, tech, exec_val, md in features:
        features_table.add_row(feature, tech, exec_val, md)

    console.print(features_table)

    console.print("\n[bold green]✅ Demo Complete![/bold green]")
    console.print(
        f"\n[dim]Generated {len(reports)} report(s) from sample penetration test data[/dim]"
    )

    return True


if __name__ == "__main__":
    try:
        success = demonstrate_reports()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        import traceback

        traceback.print_exc()
        sys.exit(1)
