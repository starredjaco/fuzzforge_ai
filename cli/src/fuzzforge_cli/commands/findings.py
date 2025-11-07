"""
Findings and security results management commands.
"""
# Copyright (c) 2025 FuzzingLabs
#
# Licensed under the Business Source License 1.1 (BSL). See the LICENSE file
# at the root of this repository for details.
#
# After the Change Date (four years from publication), this version of the
# Licensed Work will be made available under the Apache License, Version 2.0.
# See the LICENSE-APACHE file or http://www.apache.org/licenses/LICENSE-2.0
#
# Additional attribution and requirements are provided in the NOTICE file.


import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from rich import box

from ..config import get_project_config, FuzzForgeConfig
from ..database import get_project_db, ensure_project_db, FindingRecord
from ..exceptions import (
    retry_on_network_error, validate_run_id,
    require_project, ValidationError
)
from fuzzforge_sdk import FuzzForgeClient

console = Console()
app = typer.Typer()


@retry_on_network_error(max_retries=3, delay=1.0)
def get_client() -> FuzzForgeClient:
    """Get configured FuzzForge client with retry on network errors"""
    config = get_project_config() or FuzzForgeConfig()
    return FuzzForgeClient(base_url=config.get_api_url(), timeout=config.get_timeout())


def severity_style(severity: str) -> str:
    """Get rich style for severity level"""
    return {
        "error": "bold red",
        "warning": "bold yellow",
        "note": "bold blue",
        "info": "bold cyan"
    }.get(severity.lower(), "white")


@app.command("get")
def get_findings(
    run_id: str = typer.Argument(..., help="Run ID to get findings for"),
    save: bool = typer.Option(
        True, "--save/--no-save",
        help="Save findings to local database"
    ),
    format: str = typer.Option(
        "table", "--format", "-f",
        help="Output format: table, json, sarif"
    ),
    limit: Optional[int] = typer.Option(
        None, "--limit", "-l",
        help="Maximum number of findings to display (no limit by default)"
    ),
    offset: int = typer.Option(
        0, "--offset",
        help="Number of findings to skip (for pagination)"
    )
):
    """
    🔍 Retrieve and display security findings for a run
    """
    try:
        require_project()
        validate_run_id(run_id)

        if format not in ["table", "json", "sarif"]:
            raise ValidationError("format", format, "one of: table, json, sarif")
        with get_client() as client:
            console.print(f"🔍 Fetching findings for run: {run_id}")
            findings = client.get_run_findings(run_id)

        # Save to database if requested
        if save:
            try:
                db = ensure_project_db()

                # Get findings data (API returns .sarif for now, will be native format later)
                findings_data = findings.sarif
                summary = {}

                # Support both native format and SARIF format
                if "findings" in findings_data:
                    # Native FuzzForge format
                    findings_list = findings_data.get("findings", [])
                    summary = {
                        "total_issues": len(findings_list),
                        "by_severity": {},
                        "by_rule": {},
                        "by_source": {}
                    }

                    for finding in findings_list:
                        severity = finding.get("severity", "info")
                        rule_id = finding.get("rule_id", "unknown")
                        module = finding.get("found_by", {}).get("module", "unknown")

                        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
                        summary["by_rule"][rule_id] = summary["by_rule"].get(rule_id, 0) + 1
                        summary["by_source"][module] = summary["by_source"].get(module, 0) + 1

                elif "runs" in findings_data:
                    # SARIF format (backward compatibility)
                    runs_data = findings_data.get("runs", [])
                    if runs_data:
                        results = runs_data[0].get("results", [])
                        summary = {
                            "total_issues": len(results),
                            "by_severity": {},
                            "by_rule": {},
                            "tools": []
                        }

                        for result in results:
                            level = result.get("level", "note")
                            rule_id = result.get("ruleId", "unknown")

                            summary["by_severity"][level] = summary["by_severity"].get(level, 0) + 1
                            summary["by_rule"][rule_id] = summary["by_rule"].get(rule_id, 0) + 1

                        # Extract tool info
                        tool = runs_data[0].get("tool", {})
                        driver = tool.get("driver", {})
                        if driver.get("name"):
                            summary["tools"].append({
                                "name": driver.get("name"),
                                "version": driver.get("version"),
                                "rules": len(driver.get("rules", []))
                            })

                finding_record = FindingRecord(
                    run_id=run_id,
                    findings_data=findings_data,
                    summary=summary,
                    created_at=datetime.now()
                )
                db.save_findings(finding_record)
                console.print("✅ Findings saved to local database", style="green")
            except Exception as e:
                console.print(f"⚠️  Failed to save findings to database: {e}", style="yellow")

        # Display findings
        if format == "json":
            findings_json = json.dumps(findings.sarif, indent=2)
            console.print(Syntax(findings_json, "json", theme="monokai"))

        elif format == "sarif":
            sarif_json = json.dumps(findings.sarif, indent=2)
            console.print(sarif_json)

        else:  # table format
            display_findings_table(findings.sarif, limit=limit, offset=offset)

            # Suggest export command and show command
            console.print(f"\n💡 View full details of a finding: [bold cyan]ff finding show {run_id} --id <finding-id>[/bold cyan]")
            console.print(f"💡 Export these findings: [bold cyan]ff findings export {run_id} --format native[/bold cyan]")
            console.print("   Supported formats: [cyan]native[/cyan] (default), [cyan]sarif[/cyan], [cyan]json[/cyan], [cyan]csv[/cyan], [cyan]html[/cyan]")

    except Exception as e:
        console.print(f"❌ Failed to get findings: {e}", style="red")
        raise typer.Exit(1)


def show_finding(
    run_id: str = typer.Argument(..., help="Run ID to get finding from"),
    finding_id: str = typer.Option(..., "--id", "-i", help="Unique ID of the specific finding to show")
):
    """
    🔍 Show detailed information about a specific finding

    This function is registered as a command in main.py under the finding (singular) command group.
    Use the unique finding ID (shown in the findings table) to view details.
    """
    try:
        require_project()
        validate_run_id(run_id)

        # Try to get from database first, fallback to API
        db = get_project_db()
        findings_data = None
        if db:
            findings_data = db.get_findings(run_id)

        if not findings_data:
            with get_client() as client:
                console.print(f"🔍 Fetching findings for run: {run_id}")
                findings = client.get_run_findings(run_id)
                findings_dict = findings.sarif  # API still returns .sarif for now
        else:
            findings_dict = findings_data.findings_data

        # Find the specific finding by unique ID
        # For now, support both SARIF (old) and native format (new)
        matching_finding = None

        # Try native format first
        if "findings" in findings_dict:
            for finding in findings_dict.get("findings", []):
                if finding.get("id") == finding_id or finding.get("id", "").startswith(finding_id):
                    matching_finding = finding
                    break
        # Fallback to SARIF format (for backward compatibility during transition)
        elif "runs" in findings_dict:
            runs = findings_dict.get("runs", [])
            if runs:
                run_data = runs[0]
                results = run_data.get("results", [])
                for result in results:
                    # Check if finding ID is in properties
                    props = result.get("properties", {})
                    fid = props.get("findingId", "")
                    if fid == finding_id or fid.startswith(finding_id):
                        matching_finding = result
                        break

        if not matching_finding:
            console.print(f"❌ No finding found with ID: {finding_id}", style="red")
            console.print(f"💡 Use [bold cyan]ff findings get {run_id}[/bold cyan] to see all findings", style="dim")
            raise typer.Exit(1)

        # Display detailed finding
        display_finding_detail(matching_finding, run_id)

    except Exception as e:
        console.print(f"❌ Failed to get finding: {e}", style="red")
        raise typer.Exit(1)


@app.command("by-rule")
def show_findings_by_rule(
    run_id: str = typer.Argument(..., help="Run ID to get findings from"),
    rule_id: str = typer.Option(..., "--rule", "-r", help="Rule ID to filter findings")
):
    """
    🔍 Show all findings matching a specific rule

    This command shows ALL findings that match the given rule ID.
    Useful when you have multiple instances of the same vulnerability type.
    """
    try:
        require_project()
        validate_run_id(run_id)

        # Try to get from database first, fallback to API
        db = get_project_db()
        findings_data = None
        if db:
            findings_data = db.get_findings(run_id)

        if not findings_data:
            with get_client() as client:
                console.print(f"🔍 Fetching findings for run: {run_id}")
                findings = client.get_run_findings(run_id)
                findings_dict = findings.sarif  # API still returns .sarif for now
        else:
            findings_dict = findings_data.findings_data

        # Find all findings matching the rule
        matching_findings = []

        # Try native format first
        if "findings" in findings_dict:
            for finding in findings_dict.get("findings", []):
                if finding.get("rule_id") == rule_id:
                    matching_findings.append(finding)
        # Fallback to SARIF format
        elif "runs" in findings_dict:
            runs = findings_dict.get("runs", [])
            if runs:
                run_data = runs[0]
                results = run_data.get("results", [])
                for result in results:
                    if result.get("ruleId") == rule_id:
                        matching_findings.append(result)

        if not matching_findings:
            console.print(f"❌ No findings found with rule ID: {rule_id}", style="red")
            console.print(f"💡 Use [bold cyan]ff findings get {run_id}[/bold cyan] to see all findings", style="dim")
            raise typer.Exit(1)

        console.print(f"\n🔍 Found {len(matching_findings)} finding(s) matching rule: [bold cyan]{rule_id}[/bold cyan]\n")

        # Display each finding
        for i, finding in enumerate(matching_findings, 1):
            console.print(f"[bold]Finding {i} of {len(matching_findings)}[/bold]")
            display_finding_detail(finding, run_id)
            if i < len(matching_findings):
                console.print("\n" + "─" * 80 + "\n")

    except Exception as e:
        console.print(f"❌ Failed to get findings: {e}", style="red")
        raise typer.Exit(1)


def display_finding_detail(finding: Dict[str, Any], run_id: str):
    """Display detailed information about a single finding (supports both native and SARIF format)"""

    # Detect format and extract fields
    is_native = "rule_id" in finding  # Native format has rule_id, SARIF has ruleId

    if is_native:
        # Native FuzzForge format
        finding_id = finding.get("id", "unknown")
        rule_id = finding.get("rule_id", "unknown")
        title = finding.get("title", "No title")
        description = finding.get("description", "No description")
        severity = finding.get("severity", "info")
        confidence = finding.get("confidence", "medium")
        category = finding.get("category", "unknown")
        cwe = finding.get("cwe")
        owasp = finding.get("owasp")
        recommendation = finding.get("recommendation")

        # Found by information
        found_by = finding.get("found_by", {})
        module = found_by.get("module", "unknown")
        tool_name = found_by.get("tool_name", "Unknown")
        tool_version = found_by.get("tool_version", "unknown")
        detection_type = found_by.get("type", "unknown")

        # LLM context if available
        llm_context = finding.get("llm_context")

        # Location
        location = finding.get("location", {})
        file_path = location.get("file", "")
        line_start = location.get("line_start")
        column_start = location.get("column_start")
        code_snippet = location.get("snippet")

        location_str = file_path if file_path else "Unknown location"
        if line_start:
            location_str += f":{line_start}"
            if column_start:
                location_str += f":{column_start}"

    else:
        # SARIF format (backward compatibility)
        props = finding.get("properties", {})
        finding_id = props.get("findingId", "unknown")
        rule_id = finding.get("ruleId", "unknown")
        title = props.get("title", "No title")
        severity = finding.get("level", "note")
        confidence = "medium"  # Not available in SARIF
        category = "unknown"
        cwe = None
        owasp = None

        message = finding.get("message", {})
        description = message.get("text", "No description")
        recommendation = None

        module = "unknown"
        tool_name = "Unknown"
        tool_version = "unknown"
        detection_type = "tool"
        llm_context = None

        # Location from SARIF
        locations = finding.get("locations", [])
        location_str = "Unknown location"
        code_snippet = None

        if locations:
            physical_location = locations[0].get("physicalLocation", {})
            artifact_location = physical_location.get("artifactLocation", {})
            region = physical_location.get("region", {})

            file_path = artifact_location.get("uri", "")
            if file_path:
                location_str = file_path
                if region.get("startLine"):
                    location_str += f":{region['startLine']}"
                    if region.get("startColumn"):
                        location_str += f":{region['startColumn']}"

            if region.get("snippet", {}).get("text"):
                code_snippet = region["snippet"]["text"].strip()

    # Get severity style
    severity_color = {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "cyan",
        # SARIF levels
        "error": "red",
        "warning": "yellow",
        "note": "blue"
    }.get(severity.lower(), "white")

    # Build detailed content
    content_lines = []
    content_lines.append(f"[bold]Finding ID:[/bold] {finding_id}")
    content_lines.append(f"[bold]Rule ID:[/bold] {rule_id}")
    content_lines.append(f"[bold]Title:[/bold] {title}")

    # Confidence indicator with emoji
    confidence_indicators = {
        "high": "🟢",
        "medium": "🟡",
        "low": "🔴"
    }
    confidence_emoji = confidence_indicators.get(confidence.lower(), "⚪")
    content_lines.append(f"[bold]Severity:[/bold] [{severity_color}]{severity.upper()}[/{severity_color}]   [bold]Confidence:[/bold] {confidence_emoji} {confidence.capitalize()}")

    if cwe:
        content_lines.append(f"[bold]CWE:[/bold] {cwe}")
    if owasp:
        content_lines.append(f"[bold]OWASP:[/bold] {owasp}")

    content_lines.append(f"[bold]Category:[/bold] {category}")
    content_lines.append(f"[bold]Location:[/bold] {location_str}")

    # Enhanced found_by display with badge
    type_badges = {
        "llm": "🤖",
        "tool": "🔧",
        "fuzzer": "🎯",
        "manual": "👤"
    }
    type_badge = type_badges.get(detection_type.lower(), "🔍")
    content_lines.append(f"[bold]Found by:[/bold] {type_badge} {tool_name} v{tool_version} [dim]({module})[/dim] [[yellow]{detection_type}[/yellow]]")

    # LLM context details
    if llm_context:
        model = llm_context.get("model", "unknown")
        prompt = llm_context.get("prompt", "")
        content_lines.append(f"[bold]LLM Model:[/bold] {model}")
        if prompt:
            # Show first 100 chars of prompt
            prompt_preview = prompt[:100] + "..." if len(prompt) > 100 else prompt
            content_lines.append(f"[bold]Prompt:[/bold] [dim]{prompt_preview}[/dim]")

    content_lines.append(f"[bold]Run ID:[/bold] {run_id}")
    content_lines.append("")
    content_lines.append("[bold]Description:[/bold]")
    content_lines.append(description)

    if recommendation:
        content_lines.append("")
        content_lines.append("[bold]💡 Recommendation:[/bold]")
        content_lines.append(recommendation)

    content = "\n".join(content_lines)

    # Display in panel
    console.print()
    console.print(Panel(
        content,
        title="🔍 Finding Detail",
        border_style=severity_color,
        box=box.ROUNDED,
        padding=(1, 2)
    ))

    # Display code snippet with syntax highlighting (separate from panel for better rendering)
    if code_snippet:
        # Detect language from file path
        language = "text"
        if is_native and location:
            file_path = location.get("file", "")
        elif not is_native and locations:
            file_path = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
        else:
            file_path = ""

        if file_path:
            ext = Path(file_path).suffix.lower()
            language_map = {
                ".py": "python",
                ".js": "javascript",
                ".ts": "typescript",
                ".java": "java",
                ".c": "c",
                ".cpp": "cpp",
                ".cc": "cpp",
                ".h": "c",
                ".hpp": "cpp",
                ".go": "go",
                ".rs": "rust",
                ".rb": "ruby",
                ".php": "php",
                ".swift": "swift",
                ".kt": "kotlin",
                ".cs": "csharp",
                ".html": "html",
                ".xml": "xml",
                ".json": "json",
                ".yaml": "yaml",
                ".yml": "yaml",
                ".sh": "bash",
                ".bash": "bash",
                ".sql": "sql",
            }
            language = language_map.get(ext, "text")

        console.print("\n[bold]Code Snippet:[/bold]")
        syntax = Syntax(
            code_snippet,
            language,
            theme="monokai",
            line_numbers=True,
            start_line=line_start if is_native and location.get("line_start") else 1
        )
        console.print(syntax)

    console.print()
    console.print(f"💡 View all findings with this rule: [bold cyan]ff findings by-rule {run_id} --rule {rule_id}[/bold cyan]")
    console.print(f"💡 Export this run: [bold cyan]ff findings export {run_id} --format native[/bold cyan]")


def display_findings_table(findings_data: Dict[str, Any], limit: Optional[int] = None, offset: int = 0):
    """Display findings in a rich table format (supports both native and SARIF formats)"""

    # Detect format and extract findings
    is_native = "findings" in findings_data

    if is_native:
        # Native FuzzForge format
        findings_list = findings_data.get("findings", [])
        workflow = findings_data.get("workflow", "Unknown")
        total_findings = len(findings_list)
    else:
        # SARIF format (backward compatibility)
        runs = findings_data.get("runs", [])
        if not runs:
            console.print("ℹ️  No findings data available", style="dim")
            return

        run_data = runs[0]
        findings_list = run_data.get("results", [])
        tool = run_data.get("tool", {}).get("driver", {})
        workflow = tool.get("name", "Unknown")
        total_findings = len(findings_list)

    # Tool information
    console.print("\n🔍 [bold]Security Analysis Results[/bold]")
    console.print(f"Workflow: {workflow}")

    if not findings_list:
        console.print("✅ No security issues found!", style="green")
        return

    # Summary statistics
    summary_by_level = {}
    for finding in findings_list:
        if is_native:
            level = finding.get("severity", "info")
        else:
            level = finding.get("level", "note")
        summary_by_level[level] = summary_by_level.get(level, 0) + 1

    summary_table = Table(show_header=False, box=box.SIMPLE)
    summary_table.add_column("Severity", width=15, justify="left", style="bold")
    summary_table.add_column("Count", width=8, justify="right", style="bold")

    # Sort by severity order (critical > high > medium > low > info)
    severity_order = {"critical": 0, "high": 1, "error": 1, "medium": 2, "warning": 2, "low": 3, "note": 3, "info": 4}
    for level in sorted(summary_by_level.keys(), key=lambda x: severity_order.get(x, 99)):
        count = summary_by_level[level]
        severity_text = Text(level.upper(), style=severity_style(level))
        count_text = Text(str(count))
        summary_table.add_row(severity_text, count_text)

    console.print(
        Panel.fit(
            summary_table,
            title=f"📊 Summary ({total_findings} total issues)",
            box=box.ROUNDED
        )
    )

    # Apply pagination
    start_idx = offset
    end_idx = start_idx + limit if limit else len(findings_list)
    paginated_findings = findings_list[start_idx:end_idx]

    # Detailed results table with enhanced columns
    results_table = Table(box=box.ROUNDED)
    results_table.add_column("ID", width=10, justify="left", style="dim")
    results_table.add_column("Severity", width=10, justify="left", no_wrap=True)
    results_table.add_column("Message", width=50, justify="left", no_wrap=True)
    results_table.add_column("Found By", width=15, justify="left", style="yellow", no_wrap=True)
    results_table.add_column("Location", width=20, justify="left", style="dim", no_wrap=True)

    for finding in paginated_findings:
        if is_native:
            # Native format
            finding_id = finding.get("id", "")[:8]  # First 8 chars
            severity = finding.get("severity", "info")
            rule_id = finding.get("rule_id", "unknown")
            message = finding.get("title", "No message")
            found_by_info = finding.get("found_by", {})
            found_by = found_by_info.get("module", "unknown")

            location = finding.get("location", {})
            file_path = location.get("file", "")
            line_start = location.get("line_start")
            location_str = ""
            if file_path:
                location_str = Path(file_path).name
                if line_start:
                    location_str += f":{line_start}"
        else:
            # SARIF format
            props = finding.get("properties", {})
            finding_id = props.get("findingId", "")[:8] if props.get("findingId") else "N/A"
            severity = finding.get("level", "note")
            rule_id = finding.get("ruleId", "unknown")
            message = finding.get("message", {}).get("text", "No message")
            found_by = "unknown"

            locations = finding.get("locations", [])
            location_str = ""
            if locations:
                physical_location = locations[0].get("physicalLocation", {})
                artifact_location = physical_location.get("artifactLocation", {})
                region = physical_location.get("region", {})

                file_path = artifact_location.get("uri", "")
                if file_path:
                    location_str = Path(file_path).name
                    if region.get("startLine"):
                        location_str += f":{region['startLine']}"

        # Create styled text objects
        severity_text = Text(severity.upper(), style=severity_style(severity))

        # Truncate long text
        message_text = Text(message)
        message_text.truncate(50, overflow="ellipsis")

        found_by_text = Text(found_by)
        found_by_text.truncate(15, overflow="ellipsis")

        location_text = Text(location_str)
        location_text.truncate(18, overflow="ellipsis")

        results_table.add_row(
            finding_id,
            severity_text,
            message_text,
            found_by_text,
            location_text
        )

    console.print("\n📋 [bold]Detailed Results[/bold]")

    # Pagination info
    if limit and total_findings > limit:
        console.print(f"Showing {start_idx + 1}-{min(end_idx, total_findings)} of {total_findings} results")

    console.print()
    console.print(results_table)


@app.command("history")
def findings_history(
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum number of findings to show")
):
    """
    📚 Show findings history from local database
    """
    db = get_project_db()
    if not db:
        console.print("❌ No FuzzForge project found. Run 'ff init' first.", style="red")
        raise typer.Exit(1)

    try:
        findings = db.list_findings(limit=limit)

        if not findings:
            console.print("❌ No findings found in database", style="red")
            return

        table = Table(box=box.ROUNDED)
        table.add_column("Run ID", style="bold cyan", width=36)  # Full UUID width
        table.add_column("Date", justify="center")
        table.add_column("Total Issues", justify="center", style="bold")
        table.add_column("Errors", justify="center", style="red")
        table.add_column("Warnings", justify="center", style="yellow")
        table.add_column("Notes", justify="center", style="blue")
        table.add_column("Tools", style="dim")

        for finding in findings:
            summary = finding.summary
            total_issues = summary.get("total_issues", 0)
            by_severity = summary.get("by_severity", {})
            tools = summary.get("tools", [])

            tool_names = ", ".join([tool.get("name", "Unknown") for tool in tools])

            table.add_row(
                finding.run_id,  # Show full Run ID
                finding.created_at.strftime("%m-%d %H:%M"),
                str(total_issues),
                str(by_severity.get("error", 0)),
                str(by_severity.get("warning", 0)),
                str(by_severity.get("note", 0)),
                tool_names[:30] + "..." if len(tool_names) > 30 else tool_names
            )

        console.print(f"\n📚 [bold]Findings History ({len(findings)})[/bold]\n")
        console.print(table)

        console.print("\n💡 Use [bold cyan]fuzzforge finding <run-id>[/bold cyan] to view detailed findings")

    except Exception as e:
        console.print(f"❌ Failed to get findings history: {e}", style="red")
        raise typer.Exit(1)


@app.command("export")
def export_findings(
    run_id: str = typer.Argument(..., help="Run ID to export findings for"),
    format: str = typer.Option(
        "sarif", "--format", "-f",
        help="Export format: sarif (standard), json, csv, html"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file path (defaults to findings-<run-id>-<timestamp>.<format>)"
    )
):
    """
    📤 Export security findings in various formats

    SARIF is the standard format for security findings and is recommended
    for interoperability with other security tools. Filenames are automatically
    made unique with timestamps to prevent overwriting previous exports.
    """
    db = get_project_db()
    if not db:
        console.print("❌ No FuzzForge project found. Run 'ff init' first.", style="red")
        raise typer.Exit(1)

    try:
        # Get findings from database first, fallback to API
        findings_record = db.get_findings(run_id)
        if not findings_record:
            console.print(f"📡 Fetching findings from API for run: {run_id}")
            with get_client() as client:
                findings = client.get_run_findings(run_id)
                findings_data = findings.sarif
        else:
            findings_data = findings_record.findings_data

        # Generate output filename with timestamp for uniqueness
        if not output:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output = f"findings-{run_id[:8]}-{timestamp}.{format}"

        output_path = Path(output)

        # Export based on format
        if format == "sarif":
            with open(output_path, 'w') as f:
                json.dump(findings_data, f, indent=2)

        elif format == "json":
            # Simplified JSON format
            simplified_data = extract_simplified_findings(findings_data)
            with open(output_path, 'w') as f:
                json.dump(simplified_data, f, indent=2)

        elif format == "csv":
            export_to_csv(findings_data, output_path)

        elif format == "html":
            export_to_html(findings_data, output_path, run_id)

        else:
            console.print(f"❌ Unsupported format: {format}", style="red")
            raise typer.Exit(1)

        console.print(f"✅ Findings exported to: [bold cyan]{output_path}[/bold cyan]")

    except Exception as e:
        console.print(f"❌ Failed to export findings: {e}", style="red")
        raise typer.Exit(1)


def extract_simplified_findings(findings_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract simplified findings structure from native format or SARIF"""
    # Detect format
    is_native = "findings" in findings_data and "version" in findings_data

    if is_native:
        # Native FuzzForge format
        findings_list = findings_data.get("findings", [])
        workflow = findings_data.get("workflow", "Unknown")
        summary = findings_data.get("summary", {})

        simplified = {
            "tool": {
                "name": workflow,
                "version": findings_data.get("version", "1.0.0")
            },
            "summary": summary if summary else {
                "total_issues": len(findings_list),
                "by_severity": {}
            },
            "findings": []
        }

        # Count by severity if not in summary
        if not summary:
            for finding in findings_list:
                severity = finding.get("severity", "info")
                simplified["summary"]["by_severity"][severity] = simplified["summary"]["by_severity"].get(severity, 0) + 1

        # Extract simplified findings
        for finding in findings_list:
            location = finding.get("location", {})
            simplified["findings"].append({
                "id": finding.get("id"),
                "rule_id": finding.get("rule_id", "unknown"),
                "severity": finding.get("severity", "info"),
                "confidence": finding.get("confidence", "medium"),
                "title": finding.get("title", ""),
                "description": finding.get("description", ""),
                "category": finding.get("category", "other"),
                "found_by": finding.get("found_by", {}),
                "location": {
                    "file": location.get("file", ""),
                    "line": location.get("line_start"),
                    "column": location.get("column_start")
                }
            })
    else:
        # SARIF format
        runs = findings_data.get("runs", [])
        if not runs:
            return {"findings": [], "summary": {}}

        run_data = runs[0]
        results = run_data.get("results", [])
        tool = run_data.get("tool", {}).get("driver", {})

        simplified = {
            "tool": {
                "name": tool.get("name", "Unknown"),
                "version": tool.get("version", "Unknown")
            },
            "summary": {
                "total_issues": len(results),
                "by_severity": {}
            },
            "findings": []
        }

        for result in results:
            level = result.get("level", "note")
            simplified["summary"]["by_severity"][level] = simplified["summary"]["by_severity"].get(level, 0) + 1

            # Extract location
            location_info = {}
            locations = result.get("locations", [])
            if locations:
                physical_location = locations[0].get("physicalLocation", {})
                artifact_location = physical_location.get("artifactLocation", {})
                region = physical_location.get("region", {})

                location_info = {
                    "file": artifact_location.get("uri", ""),
                    "line": region.get("startLine"),
                    "column": region.get("startColumn")
                }

            simplified["findings"].append({
                "rule_id": result.get("ruleId", "unknown"),
                "severity": level,
                "message": result.get("message", {}).get("text", ""),
                "location": location_info
            })

    return simplified


def export_to_csv(findings_data: Dict[str, Any], output_path: Path):
    """Export findings to CSV format (supports both native and SARIF)"""
    # Detect format
    is_native = "findings" in findings_data and "version" in findings_data

    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        if is_native:
            # Native FuzzForge format - include more fields
            fieldnames = ['id', 'rule_id', 'severity', 'confidence', 'title', 'category', 'module', 'file', 'line', 'column']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            findings_list = findings_data.get("findings", [])
            for finding in findings_list:
                location = finding.get("location", {})
                found_by = finding.get("found_by", {})

                writer.writerow({
                    "id": finding.get("id", "")[:8],
                    "rule_id": finding.get("rule_id", ""),
                    "severity": finding.get("severity", "info"),
                    "confidence": finding.get("confidence", "medium"),
                    "title": finding.get("title", ""),
                    "category": finding.get("category", ""),
                    "module": found_by.get("module", ""),
                    "file": location.get("file", ""),
                    "line": location.get("line_start", ""),
                    "column": location.get("column_start", "")
                })
        else:
            # SARIF format
            fieldnames = ['rule_id', 'severity', 'message', 'file', 'line', 'column']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            runs = findings_data.get("runs", [])
            if not runs:
                return

            results = runs[0].get("results", [])

            for result in results:
                location_info = {"file": "", "line": "", "column": ""}
                locations = result.get("locations", [])
                if locations:
                    physical_location = locations[0].get("physicalLocation", {})
                    artifact_location = physical_location.get("artifactLocation", {})
                    region = physical_location.get("region", {})

                    location_info = {
                        "file": artifact_location.get("uri", ""),
                        "line": region.get("startLine", ""),
                        "column": region.get("startColumn", "")
                    }

                writer.writerow({
                    "rule_id": result.get("ruleId", ""),
                    "severity": result.get("level", "note"),
                    "message": result.get("message", {}).get("text", ""),
                    **location_info
                })


def export_to_html(findings_data: Dict[str, Any], output_path: Path, run_id: str):
    """Export findings to modern, interactive HTML format with charts"""
    import html
    from datetime import datetime

    # Helper function to safely escape strings
    def safe_escape(value):
        """Safely escape a value, handling None and non-string types"""
        if value is None:
            return ""
        return html.escape(str(value))

    # Detect format (native or SARIF)
    is_native = "findings" in findings_data and "version" in findings_data

    if is_native:
        # Native FuzzForge format
        findings_list = findings_data.get("findings", [])
        workflow = findings_data.get("workflow", "Security Assessment")
        summary = findings_data.get("summary", {})
        total_findings = len(findings_list)
    else:
        # SARIF format (backward compatibility)
        runs = findings_data.get("runs", [])
        if not runs:
            # Empty report
            findings_list = []
            workflow = "Security Assessment"
            summary = {}
            total_findings = 0
        else:
            run_data = runs[0]
            findings_list = run_data.get("results", [])
            tool = run_data.get("tool", {}).get("driver", {})
            workflow = tool.get("name", "Security Assessment")
            total_findings = len(findings_list)
            summary = {}

    # Calculate statistics
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    category_counts = {}
    source_counts = {}
    type_counts = {}

    for finding in findings_list:
        if is_native:
            severity = finding.get("severity", "info")
            confidence = finding.get("confidence", "medium")
            category = finding.get("category", "other")
            found_by = finding.get("found_by", {})
            source = found_by.get("module", "unknown")
            detection_type = found_by.get("type", "tool")
        else:
            # Map SARIF levels to severity
            level = finding.get("level", "note")
            severity_map = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
            severity = severity_map.get(level, "info")
            confidence = "medium"
            category = "other"
            source = "unknown"
            detection_type = "tool"

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
        source_counts[source] = source_counts.get(source, 0) + 1
        type_counts[detection_type] = type_counts.get(detection_type, 0) + 1

    # Prepare chart data
    severity_data = {k: v for k, v in severity_counts.items() if v > 0}
    category_data = dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    source_data = dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    type_data = {k: v for k, v in type_counts.items() if v > 0}

    # Generate findings rows
    findings_rows = ""
    for idx, finding in enumerate(findings_list):
        if is_native:
            finding_id = finding.get("id", "")[:8] if finding.get("id") else ""
            severity = finding.get("severity", "info")
            confidence = finding.get("confidence", "medium")
            title = safe_escape(finding.get("title") or "No title")
            description = safe_escape(finding.get("description"))
            rule_id = safe_escape(finding.get("rule_id") or "unknown")
            category = safe_escape(finding.get("category") or "other")

            found_by = finding.get("found_by") or {}
            module = safe_escape(found_by.get("module") or "unknown")
            tool_name = safe_escape(found_by.get("tool_name") or "Unknown")
            detection_type = found_by.get("type") or "tool"

            location = finding.get("location") or {}
            file_path = safe_escape(location.get("file"))
            line_start = location.get("line_start")
            code_snippet = safe_escape(location.get("snippet"))

            cwe = safe_escape(finding.get("cwe"))
            owasp = safe_escape(finding.get("owasp"))
            recommendation = safe_escape(finding.get("recommendation"))

            llm_context = finding.get("llm_context")
            if llm_context:
                llm_model = safe_escape(llm_context.get("model"))
                prompt_text = llm_context.get("prompt", "")
                if prompt_text:
                    llm_prompt_preview = safe_escape(prompt_text[:100] + "..." if len(prompt_text) > 100 else prompt_text)
                else:
                    llm_prompt_preview = ""
            else:
                llm_model = ""
                llm_prompt_preview = ""
        else:
            # SARIF format
            props = finding.get("properties") or {}
            finding_id = props.get("findingId", "")[:8] if props.get("findingId") else ""
            level = finding.get("level", "note")
            severity_map = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
            severity = severity_map.get(level, "info")
            confidence = "medium"
            rule_id = safe_escape(finding.get("ruleId") or "unknown")
            message = finding.get("message") or {}
            title = safe_escape(message.get("text") or "No message")
            description = title
            category = "other"
            module = "unknown"
            tool_name = "Unknown"
            detection_type = "tool"

            locations = finding.get("locations", [])
            if locations:
                physical_location = locations[0].get("physicalLocation") or {}
                artifact_location = physical_location.get("artifactLocation") or {}
                region = physical_location.get("region") or {}
                file_path = safe_escape(artifact_location.get("uri"))
                line_start = region.get("startLine")
                snippet_obj = region.get("snippet") or {}
                code_snippet = safe_escape(snippet_obj.get("text"))
            else:
                file_path = ""
                line_start = None
                code_snippet = ""

            cwe = ""
            owasp = ""
            recommendation = ""
            llm_model = ""
            llm_prompt_preview = ""

        location_str = file_path if file_path else "-"
        if line_start and file_path:
            location_str = f"{file_path}:{line_start}"

        severity_badge = {
            "critical": '<span class="badge badge-critical">CRITICAL</span>',
            "high": '<span class="badge badge-high">HIGH</span>',
            "medium": '<span class="badge badge-medium">MEDIUM</span>',
            "low": '<span class="badge badge-low">LOW</span>',
            "info": '<span class="badge badge-info">INFO</span>'
        }.get(severity, '<span class="badge badge-info">INFO</span>')

        confidence_badge = {
            "high": '<span class="badge badge-confidence">High</span>',
            "medium": '<span class="badge badge-confidence">Medium</span>',
            "low": '<span class="badge badge-confidence">Low</span>'
        }.get(confidence, '<span class="badge badge-confidence">Medium</span>')

        type_icon = {
            "llm": "🤖",
            "tool": "🔧",
            "fuzzer": "🎯",
            "manual": "👤"
        }.get(detection_type, "🔧")

        # Build details HTML
        details_html = f"""
        <div class="finding-details" id="details-{idx}" style="display:none;">
            <div class="details-card">
                <h6>Description</h6>
                <p>{description}</p>

                {f'<h6>Code Snippet</h6><pre><code>{code_snippet}</code></pre>' if code_snippet else ''}

                <div class="details-grid">
                    <div>
                        <h6>Classification</h6>
                        <p><strong>Category:</strong> {category}</p>
                        {f'<p><strong>CWE:</strong> {cwe}</p>' if cwe else ''}
                        {f'<p><strong>OWASP:</strong> {owasp}</p>' if owasp else ''}
                    </div>
                    <div>
                        <h6>Detection</h6>
                        <p><strong>Module:</strong> {module}</p>
                        <p><strong>Tool:</strong> {tool_name}</p>
                        <p><strong>Type:</strong> {type_icon} {detection_type}</p>
                        <p><strong>Confidence:</strong> {confidence_badge}</p>
                    </div>
                </div>

                {f'<div class="mt-3"><h6>LLM Detection Context</h6><p><strong>Model:</strong> {llm_model}</p><p><strong>Prompt:</strong> {llm_prompt_preview}</p></div>' if llm_model else ''}

                {f'<div class="mt-3"><h6>Recommendation</h6><p>{recommendation}</p></div>' if recommendation else ''}
            </div>
        </div>
        """

        findings_rows += f"""
        <tr class="finding-row" data-severity="{severity}" data-confidence="{confidence}" data-category="{category}" data-source="{module}" data-type="{detection_type}" onclick="toggleDetails({idx})">
            <td>{finding_id}</td>
            <td>{severity_badge}</td>
            <td>{title}</td>
            <td>{type_icon} {module}</td>
            <td>{location_str}</td>
        </tr>
        <tr>
            <td colspan="5" class="p-0">{details_html}</td>
        </tr>
        """

    # Generate HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Findings Report - {run_id}</title>

    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- Google Fonts: Inter & Fira Code -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">

    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

    <style>
        /* FuzzForge Design System - Color Palette */
        :root {{
            /* Base Background */
            --bg-base: #111427;
            --bg-card: rgba(31, 37, 60, 0.8);
            --bg-card-elevated: rgba(31, 37, 60, 0.9);
            --bg-card-hover: rgba(31, 37, 60, 0.95);

            /* Border Colors */
            --border-default: #374151;
            --border-hover: #4b5563;
            --border-subtle: rgba(55, 65, 81, 0.5);

            /* Text Colors */
            --text-primary: #e5e7eb;
            --text-secondary: #d1d5db;
            --text-tertiary: #9ca3af;
            --text-muted: #6b7280;

            /* Brand Colors - Indigo/Violet Gradient */
            --brand-indigo: #6366f1;
            --brand-violet: #8b5cf6;
            --brand-pink: #ec4899;

            /* Severity Colors */
            --critical-bg: rgba(239, 68, 68, 0.1);
            --critical-border: rgba(239, 68, 68, 0.4);
            --critical-text: #fca5a5;
            --critical-badge-bg: rgba(239, 68, 68, 0.2);
            --critical-badge-text: #fca5a5;

            --high-bg: rgba(249, 115, 22, 0.1);
            --high-border: rgba(249, 115, 22, 0.4);
            --high-text: #fdba74;
            --high-badge-bg: rgba(249, 115, 22, 0.2);
            --high-badge-text: #fdba74;

            --medium-bg: rgba(234, 179, 8, 0.1);
            --medium-border: rgba(234, 179, 8, 0.4);
            --medium-text: #fde047;
            --medium-badge-bg: rgba(234, 179, 8, 0.2);
            --medium-badge-text: #fde047;

            --low-bg: rgba(59, 130, 246, 0.1);
            --low-border: rgba(59, 130, 246, 0.4);
            --low-text: #93c5fd;
            --low-badge-bg: rgba(59, 130, 246, 0.2);
            --low-badge-text: #93c5fd;

            --info-bg: rgba(107, 114, 128, 0.1);
            --info-border: rgba(107, 114, 128, 0.4);
            --info-text: #d1d5db;
            --info-badge-bg: rgba(107, 114, 128, 0.2);
            --info-badge-text: #d1d5db;

            /* Syntax Highlighting Colors */
            --syntax-comment: #6b7280;
            --syntax-keyword: #f97316;
            --syntax-string: #10b981;
            --syntax-number: #3b82f6;
            --syntax-function: #a78bfa;
            --syntax-type: #f59e0b;
            --syntax-attribute: #06b6d4;
        }}

        /* Reset & Base Styles */
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background-color: var(--bg-base);
            color: var(--text-primary);
            line-height: 1.6;
            padding-bottom: 50px;
            position: relative;
            overflow-x: hidden;
            scroll-behavior: smooth;
        }}

        /* Custom Scrollbar */
        ::-webkit-scrollbar {{
            width: 10px;
        }}

        ::-webkit-scrollbar-track {{
            background: var(--bg-base);
        }}

        ::-webkit-scrollbar-thumb {{
            background: linear-gradient(180deg, var(--brand-indigo), var(--brand-violet));
            border-radius: 5px;
        }}

        ::-webkit-scrollbar-thumb:hover {{
            background: linear-gradient(180deg, var(--brand-violet), var(--brand-pink));
        }}

        /* Animated Background Gradients - FuzzForge Ambient Glow */
        @keyframes float {{
            0%, 100% {{ transform: translate(0, 0) scale(1); }}
            33% {{ transform: translate(30px, -30px) scale(1.1); }}
            66% {{ transform: translate(-20px, 20px) scale(0.9); }}
        }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 0.15; }}
            50% {{ opacity: 0.25; }}
        }}

        body::before {{
            content: '';
            position: fixed;
            top: -20%;
            right: -10%;
            width: 60%;
            height: 60%;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, transparent 70%);
            pointer-events: none;
            z-index: 0;
            animation: float 20s ease-in-out infinite, pulse 8s ease-in-out infinite;
        }}

        body::after {{
            content: '';
            position: fixed;
            bottom: -20%;
            left: -10%;
            width: 60%;
            height: 60%;
            background: radial-gradient(circle, rgba(139, 92, 246, 0.15) 0%, transparent 70%);
            pointer-events: none;
            z-index: 0;
            animation: float 25s ease-in-out infinite reverse, pulse 10s ease-in-out infinite;
        }}

        /* Additional floating gradient orb */
        .container::before {{
            content: '';
            position: fixed;
            top: 40%;
            left: 50%;
            width: 40%;
            height: 40%;
            background: radial-gradient(circle, rgba(236, 72, 153, 0.1) 0%, transparent 70%);
            pointer-events: none;
            z-index: 0;
            animation: float 30s ease-in-out infinite;
            transform: translate(-50%, -50%);
        }}

        /* Typography */
        h1, h2, h3, h4, h5, h6 {{
            font-weight: 700;
            color: var(--text-primary);
        }}

        h1 {{
            font-size: 3rem;
            line-height: 1.1;
        }}

        h2 {{
            font-size: 1.875rem;
            line-height: 1.2;
            margin-bottom: 1rem;
        }}

        h5 {{
            font-size: 1.125rem;
            font-weight: 600;
        }}

        h6 {{
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}

        p {{
            color: var(--text-secondary);
        }}

        code, pre {{
            font-family: 'Fira Code', 'Courier New', monospace;
        }}

        /* Header Section */
        @keyframes shimmer {{
            0% {{ background-position: -1000px 0; }}
            100% {{ background-position: 1000px 0; }}
        }}

        @keyframes headerFloat {{
            0%, 100% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(-10px); }}
        }}

        .header-section {{
            background: linear-gradient(135deg, var(--brand-indigo) 0%, var(--brand-violet) 50%, var(--brand-pink) 100%);
            background-size: 200% 200%;
            padding: 4rem 0;
            margin-bottom: 3rem;
            position: relative;
            z-index: 1;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(99, 102, 241, 0.3);
        }}

        .header-section::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(
                90deg,
                transparent,
                rgba(255, 255, 255, 0.1),
                transparent
            );
            animation: shimmer 3s infinite;
        }}

        .header-content {{
            max-width: 1280px;
            margin: 0 auto;
            padding: 0 1.5rem;
            position: relative;
            z-index: 1;
        }}

        .header-title {{
            background: linear-gradient(to right, #e0e7ff, #ddd6fe, #fce7f3, #e0e7ff);
            background-size: 200% auto;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            animation: shimmer 8s linear infinite;
            text-shadow: 0 0 40px rgba(255, 255, 255, 0.5);
            letter-spacing: -0.02em;
        }}

        .header-subtitle {{
            font-size: 1.25rem;
            color: rgba(255, 255, 255, 0.95);
            margin-bottom: 0.25rem;
            font-weight: 500;
            animation: headerFloat 3s ease-in-out infinite;
        }}

        .header-meta {{
            font-size: 0.875rem;
            color: rgba(255, 255, 255, 0.8);
            font-weight: 400;
            letter-spacing: 0.02em;
        }}

        /* Container */
        .container {{
            max-width: 1280px;
            margin: 0 auto;
            padding: 0 1.5rem;
            position: relative;
            z-index: 1;
        }}

        /* Grid System */
        .row {{
            display: flex;
            flex-wrap: wrap;
            margin: -0.75rem;
        }}

        .col {{
            padding: 0.75rem;
        }}

        .col-12 {{ width: 100%; }}
        .col-6 {{ width: 50%; }}
        .col-3 {{ width: 25%; }}

        @media (max-width: 768px) {{
            .col-6, .col-3 {{ width: 100%; }}
        }}

        /* Card Styles - Glass Morphism */
        @keyframes borderGlow {{
            0%, 100% {{ box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), 0 0 20px rgba(99, 102, 241, 0); }}
            50% {{ box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), 0 0 20px rgba(99, 102, 241, 0.3); }}
        }}

        @keyframes slideUp {{
            from {{
                opacity: 0;
                transform: translateY(30px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        .card {{
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-default);
            border-radius: 0.75rem;
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
            animation: slideUp 0.6s ease-out backwards;
        }}

        .card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, var(--brand-indigo), var(--brand-violet), var(--brand-pink));
            opacity: 0;
            transition: opacity 0.3s ease;
        }}

        .card:hover::before {{
            opacity: 1;
        }}

        .card:hover {{
            border-color: var(--border-hover);
            box-shadow: 0 12px 48px rgba(0, 0, 0, 0.4), 0 0 30px rgba(99, 102, 241, 0.2);
            transform: translateY(-2px);
        }}

        .card-elevated {{
            background: var(--bg-card-elevated);
            border-color: var(--border-hover);
            box-shadow: 0 12px 48px rgba(0, 0, 0, 0.4);
        }}

        /* Stat Cards */
        @keyframes gradientBorder {{
            0% {{ background-position: 0% 50%; }}
            50% {{ background-position: 100% 50%; }}
            100% {{ background-position: 0% 50%; }}
        }}

        @keyframes countUp {{
            from {{ transform: scale(0.8); opacity: 0; }}
            to {{ transform: scale(1); opacity: 1; }}
        }}

        .stat-card {{
            text-align: center;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: default;
            position: relative;
            border: 2px solid transparent;
            background: var(--bg-card), linear-gradient(135deg, var(--brand-indigo), var(--brand-violet), var(--brand-pink));
            background-clip: padding-box, border-box;
            background-origin: padding-box, border-box;
        }}

        .stat-card::after {{
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 0.75rem;
            padding: 2px;
            background: linear-gradient(135deg, var(--brand-indigo), var(--brand-violet), var(--brand-pink));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            opacity: 0;
            transition: opacity 0.4s ease;
        }}

        .stat-card:hover::after {{
            opacity: 1;
        }}

        .stat-card:hover {{
            transform: translateY(-8px) scale(1.02);
            box-shadow: 0 20px 60px rgba(99, 102, 241, 0.3), 0 0 40px rgba(99, 102, 241, 0.2);
        }}

        .stat-number {{
            font-size: 3rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 0.5rem;
            animation: countUp 0.8s cubic-bezier(0.4, 0, 0.2, 1) backwards;
            text-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
        }}

        .stat-label {{
            font-size: 0.875rem;
            color: var(--text-tertiary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }}

        .stat-critical {{
            color: var(--critical-text);
            text-shadow: 0 0 20px rgba(239, 68, 68, 0.5);
        }}

        .stat-medium {{
            color: var(--medium-text);
            text-shadow: 0 0 20px rgba(234, 179, 8, 0.5);
        }}

        .stat-low {{
            color: var(--low-text);
            text-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
        }}

        /* Chart Container */
        .chart-container {{
            position: relative;
            height: 300px;
            margin-top: 1rem;
        }}

        /* Section Title */
        @keyframes underlineExpand {{
            from {{ width: 0; }}
            to {{ width: 60px; }}
        }}

        .section-title {{
            font-size: 1.875rem;
            margin-bottom: 1.5rem;
            margin-top: 2rem;
            color: var(--text-primary);
            position: relative;
            display: inline-block;
            font-weight: 700;
            background: linear-gradient(135deg, var(--text-primary), var(--brand-indigo));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .section-title::after {{
            content: '';
            position: absolute;
            bottom: -8px;
            left: 0;
            height: 3px;
            width: 60px;
            background: linear-gradient(90deg, var(--brand-indigo), var(--brand-violet));
            border-radius: 2px;
            animation: underlineExpand 0.6s ease-out;
        }}

        /* Filters */
        @keyframes filterSlideIn {{
            from {{
                opacity: 0;
                transform: translateX(-20px);
            }}
            to {{
                opacity: 1;
                transform: translateX(0);
            }}
        }}

        .filters {{
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
            margin-bottom: 1.5rem;
            animation: filterSlideIn 0.5s ease-out;
        }}

        .filter-input {{
            flex: 1;
            min-width: 200px;
            background: rgba(31, 37, 60, 0.6);
            border: 1px solid var(--border-default);
            border-radius: 0.5rem;
            padding: 0.625rem 1rem;
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(8px);
        }}

        .filter-input:focus {{
            outline: none;
            border-color: var(--brand-indigo);
            background: rgba(31, 37, 60, 0.8);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1), 0 0 20px rgba(99, 102, 241, 0.2);
            transform: translateY(-2px);
        }}

        .search-with-icon {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.625rem 1rem;
            border-radius: 0.65rem;
            border: 1px solid rgba(99, 102, 241, 0.3);
            background: rgba(6, 8, 22, 0.75);
        }}

        .search-with-icon input {{
            flex: 1;
            background: transparent;
            border: none;
            color: var(--text-primary);
            font-size: 0.875rem;
        }}

        .search-with-icon input:focus {{
            outline: none;
        }}

        .search-with-icon .search-icon {{
            width: 1.1rem;
            height: 1.1rem;
            color: var(--brand-indigo);
            opacity: 0.8;
        }}

        .filter-select {{
            background: rgba(31, 37, 60, 0.6);
            border: 1px solid var(--border-default);
            border-radius: 0.5rem;
            padding: 0.625rem 1.25rem;
            color: var(--text-primary);
            font-size: 0.875rem;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            min-width: 150px;
            backdrop-filter: blur(8px);
            appearance: none;
            -webkit-appearance: none;
            -moz-appearance: none;
            background-image: linear-gradient(45deg, transparent 50%, var(--text-tertiary) 50%),
                              linear-gradient(135deg, var(--text-tertiary) 50%, transparent 50%);
            background-position: calc(100% - 18px) calc(50% - 2px), calc(100% - 12px) calc(50% - 2px);
            background-size: 6px 6px, 6px 6px;
            background-repeat: no-repeat;
            padding-right: 2.5rem;
        }}

        .filter-select:hover {{
            border-color: var(--brand-indigo);
            transform: translateY(-2px);
        }}

        .filter-select:focus {{
            outline: none;
            border-color: var(--brand-indigo);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }}

        .btn {{
            background: rgba(99, 102, 241, 0.15);
            border: 1px solid var(--brand-indigo);
            border-radius: 0.5rem;
            padding: 0.625rem 1.5rem;
            color: var(--brand-indigo);
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}

        .btn::before {{
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            background: rgba(99, 102, 241, 0.3);
            border-radius: 50%;
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }}

        .btn:hover::before {{
            width: 300px;
            height: 300px;
        }}

        .btn:hover {{
            background: rgba(99, 102, 241, 0.25);
            border-color: var(--brand-violet);
            color: var(--brand-violet);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }}

        .btn:active {{
            transform: translateY(0);
        }}

        /* Table Styles */
        @keyframes fadeInRow {{
            from {{
                opacity: 0;
                transform: translateX(-10px);
            }}
            to {{
                opacity: 1;
                transform: translateX(0);
            }}
        }}

        @keyframes sortArrow {{
            0%, 100% {{ transform: translateY(0); }}
            50% {{ transform: translateY(-3px); }}
        }}

        .table-card {{
            background: transparent;
            border: none;
            box-shadow: none;
            padding: 0;
        }}

        .table-card .filters {{
            background: linear-gradient(135deg, rgba(15, 18, 35, 0.95) 0%, rgba(25, 18, 62, 0.85) 40%, rgba(43, 13, 62, 0.75) 100%);
            border: 1px solid rgba(148, 163, 184, 0.25);
            border-radius: 1rem;
            padding: 1rem 1.25rem;
            backdrop-filter: blur(18px);
            box-shadow: 0 20px 35px rgba(3, 7, 18, 0.55);
            position: relative;
            overflow: hidden;
        }}

        .table-card .filters::before {{
            content: '';
            position: absolute;
            inset: 1px;
            border-radius: 0.9rem;
            border: 1px solid rgba(255, 255, 255, 0.05);
            pointer-events: none;
        }}

        .table-card .filters .filter-select,
        .table-card .filters .filter-input {{
            background: rgba(6, 8, 22, 0.75);
            border: 1px solid rgba(99, 102, 241, 0.3);
            color: var(--text-primary);
            border-radius: 0.65rem;
        }}

        .table-card .filters .btn {{
            background: linear-gradient(90deg, var(--brand-indigo), var(--brand-violet));
            color: #fff;
            border: 1px solid transparent;
            border-radius: 0.65rem;
            min-width: 110px;
        }}

        /* Bootstrap Table Dark Theme Overrides */
        .table-responsive {{
            border-radius: 1.1rem;
            overflow-x: auto;
            overflow-y: hidden;
            border: 1px solid var(--border-default);
            background: rgba(17, 24, 39, 0.85);
            box-shadow: 0 25px 45px rgba(10, 14, 25, 0.55);
            margin-top: 1rem;
        }}

        .table {{
            width: 100%;
            color: var(--text-secondary) !important;
            border-color: var(--border-subtle) !important;
            margin-bottom: 0;
            table-layout: auto;
            border-collapse: collapse;
            background: rgba(15, 18, 35, 0.95);
            --bs-table-bg: transparent !important;
            --bs-table-striped-bg: transparent !important;
            --bs-table-hover-bg: transparent !important;
        }}

        .table thead {{
            position: sticky;
            top: 0;
            z-index: 5;
            box-shadow: inset 0 -1px 0 var(--border-default);
        }}

        .table thead th {{
            background: linear-gradient(180deg, rgba(31, 37, 60, 0.98) 0%, rgba(17, 20, 39, 0.95) 100%) !important;
            color: var(--text-tertiary) !important;
            text-transform: none;
            font-size: 0.9rem;
            letter-spacing: 0.05em;
            font-weight: 600;
            border-bottom: 1px solid var(--border-default) !important;
            border-top: none !important;
            padding: 0.95rem 1.1rem !important;
            cursor: pointer;
        }}

        .table thead th:hover {{
            color: var(--brand-indigo) !important;
        }}

        .table tbody tr.finding-row {{
            cursor: pointer;
            transition: background 0.2s ease, transform 0.2s ease;
            border-bottom: 1px solid var(--border-subtle) !important;
            background: rgba(17, 20, 39, 0.7);
        }}

        .table tbody tr.finding-row:nth-of-type(4n+3) {{
            background: rgba(31, 37, 60, 0.65);
        }}

        .table tbody tr.finding-row:hover {{
            background: linear-gradient(90deg, rgba(99, 102, 241, 0.18) 0%, rgba(99, 102, 241, 0.08) 100%);
            transform: translateX(4px);
        }}

        .table thead th,
        .table tbody td {{
            text-align: left;
        }}

        .table thead th:nth-child(2),
        .table tbody td:nth-child(2) {{
            text-align: center;
            white-space: nowrap;
        }}

        .table tbody td {{
            color: var(--text-secondary) !important;
            border-bottom: 1px solid var(--border-subtle) !important;
            border-top: none !important;
            padding: 0.95rem 1.1rem !important;
            vertical-align: middle;
            background: transparent !important;
        }}

        .table tbody td:nth-child(1) {{
            font-family: 'Fira Code', monospace;
            font-size: 0.82rem;
            color: var(--text-tertiary) !important;
            font-weight: 500;
            white-space: nowrap;
        }}

        .table tbody td:nth-child(3) {{
            font-weight: 500;
            color: var(--text-primary) !important;
            white-space: normal;
            word-break: break-word;
        }}

        .table tbody td:nth-child(4),
        .table tbody td:nth-child(5) {{
            font-size: 0.82rem;
            white-space: nowrap;
            color: var(--text-tertiary) !important;
        }}

        .table tbody td:nth-child(5) {{
            font-family: 'Fira Code', monospace;
        }}

        /* Enhanced row state when expanded */
        tbody tr.finding-row.expanded {{
            background: rgba(99, 102, 241, 0.18) !important;
            border-bottom-color: var(--brand-indigo) !important;
        }}

        /* Severity Badges */
        @keyframes badgePulse {{
            0%, 100% {{
                box-shadow: 0 0 0 0 currentColor;
            }}
            50% {{
                box-shadow: 0 0 0 4px transparent;
            }}
        }}

        @keyframes badgeGlow {{
            0%, 100% {{ filter: brightness(1); }}
            50% {{ filter: brightness(1.2); }}
        }}

        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.35rem 0.85rem;
            border-radius: 0.5rem;
            font-size: 0.65rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            position: relative;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(8px);
        }}

        .badge::before {{
            content: '';
            position: absolute;
            inset: -1px;
            border-radius: inherit;
            padding: 1px;
            background: linear-gradient(135deg, currentColor, transparent);
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            opacity: 0.3;
        }}

        .badge-critical {{
            background: var(--critical-badge-bg);
            color: var(--critical-badge-text);
            border: 1px solid var(--critical-border);
        }}

        .badge-high {{
            background: var(--high-badge-bg);
            color: var(--high-badge-text);
            border: 1px solid var(--high-border);
        }}

        .badge-medium {{
            background: var(--medium-badge-bg);
            color: var(--medium-badge-text);
            border: 1px solid var(--medium-border);
        }}

        .badge-low {{
            background: var(--low-badge-bg);
            color: var(--low-badge-text);
            border: 1px solid var(--low-border);
        }}

        .badge-info {{
            background: var(--info-badge-bg);
            color: var(--info-badge-text);
            border: 1px solid var(--info-border);
        }}

        .badge-confidence {{
            background: rgba(99, 102, 241, 0.15);
            color: var(--brand-indigo);
            border: 1px solid rgba(99, 102, 241, 0.3);
        }}

        /* Finding Details */
        @keyframes detailsExpand {{
            from {{
                opacity: 0;
                max-height: 0;
                transform: scaleY(0.8);
            }}
            to {{
                opacity: 1;
                max-height: 2000px;
                transform: scaleY(1);
            }}
        }}

        .finding-details {{
            background: linear-gradient(180deg, rgba(17, 20, 39, 0.5) 0%, rgba(17, 20, 39, 0.85) 100%);
            border-top: 1px solid var(--border-subtle);
            animation: detailsExpand 0.4s ease-out;
            overflow: hidden;
        }}

        .details-card {{
            background: rgba(31, 37, 60, 0.85);
            border: 1px solid var(--border-default);
            border-radius: 0.75rem;
            padding: 1.75rem 2rem;
            margin: 1.25rem 1.5rem;
            position: relative;
            backdrop-filter: blur(12px);
        }}

        .details-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--brand-indigo), var(--brand-violet), transparent);
        }}

        .details-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 1rem;
        }}

        /* Code Blocks */
        pre {{
            background: linear-gradient(135deg, rgba(17, 20, 39, 0.9) 0%, rgba(17, 20, 39, 0.95) 100%);
            border: 1px solid var(--border-default);
            border-radius: 0.75rem;
            border-left: 3px solid var(--brand-indigo);
            padding: 1.25rem;
            overflow-x: auto;
            margin: 1rem 0;
            position: relative;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        }}

        pre::before {{{{
            content: '{{{{ }}}}';
            position: absolute;
            top: 0.5rem;
            right: 0.75rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.75rem;
            color: var(--brand-indigo);
            opacity: 0.5;
        }}}}

        code {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            line-height: 1.7;
            font-family: 'Fira Code', 'Courier New', monospace;
        }}

        /* Syntax Highlighting */
        .token.comment {{ color: var(--syntax-comment); }}
        .token.keyword {{ color: var(--syntax-keyword); }}
        .token.string {{ color: var(--syntax-string); }}
        .token.number {{ color: var(--syntax-number); }}
        .token.function {{ color: var(--syntax-function); }}
        .token.class-name {{ color: var(--syntax-type); }}
        .token.attr-name {{ color: var(--syntax-attribute); }}

        /* Utilities */
        .mb-0 {{ margin-bottom: 0; }}
        .mb-1 {{ margin-bottom: 0.5rem; }}
        .mb-2 {{ margin-bottom: 1rem; }}
        .mb-3 {{ margin-bottom: 1.5rem; }}
        .mb-4 {{ margin-bottom: 2rem; }}
        .mt-2 {{ margin-top: 1rem; }}
        .mt-3 {{ margin-top: 1.5rem; }}
        .text-center {{ text-align: center; }}

        /* Staggered Animation Delays */
        .col:nth-child(1) .card {{ animation-delay: 0.1s; }}
        .col:nth-child(2) .card {{ animation-delay: 0.2s; }}
        .col:nth-child(3) .card {{ animation-delay: 0.3s; }}
        .col:nth-child(4) .card {{ animation-delay: 0.4s; }}

        tbody tr.finding-row:nth-child(2) {{ animation-delay: 0.05s; }}
        tbody tr.finding-row:nth-child(4) {{ animation-delay: 0.1s; }}
        tbody tr.finding-row:nth-child(6) {{ animation-delay: 0.15s; }}
        tbody tr.finding-row:nth-child(8) {{ animation-delay: 0.2s; }}
        tbody tr.finding-row:nth-child(10) {{ animation-delay: 0.25s; }}

        /* Scroll Progress Indicator */
        @keyframes progressGrow {{
            from {{ transform: scaleX(0); }}
            to {{ transform: scaleX(1); }}
        }}

        body::after {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            height: 3px;
            width: 100%;
            background: linear-gradient(90deg, var(--brand-indigo), var(--brand-violet), var(--brand-pink));
            transform-origin: left;
            z-index: 9999;
            pointer-events: none;
        }}

        /* Enhanced Hover States */
        h5 {{
            transition: color 0.3s ease;
        }}

        .card:hover h5 {{
            color: var(--brand-indigo);
        }}

        /* Responsive Adjustments */
        @media (max-width: 768px) {{
            .header-title {{ font-size: 2rem; }}
            .stat-number {{ font-size: 2.5rem; }}
            .section-title {{ font-size: 1.5rem; }}
            .filters {{ flex-direction: column; }}
            .filter-input, .filter-select, .btn {{ width: 100%; }}
        }}

        /* Selection Styles */
        ::selection {{
            background: var(--brand-indigo);
            color: white;
        }}

        ::-moz-selection {{
            background: var(--brand-indigo);
            color: white;
        }}

        /* Focus Visible for Accessibility */
        *:focus-visible {{
            outline: 2px solid var(--brand-indigo);
            outline-offset: 2px;
            border-radius: 0.25rem;
        }}

        /* Print Styles */
        @media print {{
            body::before, body::after, .container::before {{ display: none; }}
            .filters, .no-print {{ display: none !important; }}
            .card {{
                box-shadow: none;
                border: 1px solid #ddd;
                animation: none;
                break-inside: avoid;
            }}
            .header-section {{ box-shadow: none; }}
            thead {{ display: table-header-group; }}
            tbody tr {{ break-inside: avoid; }}
            .stat-card:hover, .badge:hover, .btn:hover {{ transform: none; }}
        }}
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header-section">
        <div class="header-content">
            <h1 class="header-title">Security Findings Report</h1>
            <p class="header-subtitle">{workflow}</p>
            <p class="header-meta"><strong>Run ID:</strong> {run_id} | <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>

    <div class="container">
        <!-- Executive Summary -->
        <h2 class="section-title">Executive Summary</h2>
        <div class="row mb-4">
            <div class="col col-3">
                <div class="card stat-card">
                    <div class="stat-number">{total_findings}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
            </div>

            <div class="col col-3">
                <div class="card stat-card">
                    <div class="stat-number stat-critical">{severity_counts['critical'] + severity_counts['high']}</div>
                    <div class="stat-label">Critical + High</div>
                </div>
            </div>

            <div class="col col-3">
                <div class="card stat-card">
                    <div class="stat-number stat-medium">{severity_counts['medium']}</div>
                    <div class="stat-label">Medium</div>
                </div>
            </div>

            <div class="col col-3">
                <div class="card stat-card">
                    <div class="stat-number stat-low">{severity_counts['low'] + severity_counts['info']}</div>
                    <div class="stat-label">Low + Info</div>
                </div>
            </div>
        </div>

        <!-- Charts -->
        <h2 class="section-title mt-3">Analysis</h2>
        <div class="row mb-4">
            <div class="col col-6">
                <div class="card">
                    <h5>Severity Distribution</h5>
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="col col-6">
                <div class="card">
                    <h5>Detection Type</h5>
                    <div class="chart-container">
                        <canvas id="typeChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="col col-6">
                <div class="card">
                    <h5>Top Categories</h5>
                    <div class="chart-container">
                        <canvas id="categoryChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="col col-6">
                <div class="card">
                    <h5>Findings by Source</h5>
                    <div class="chart-container">
                        <canvas id="sourceChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Filters & Findings Table -->
        <h2 class="section-title mt-3">Detailed Findings</h2>
        <div class="card table-card">
            <!-- Filters -->
            <div class="filters no-print">
                <select class="filter-select" id="severityFilter" onchange="applyFilters()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <select class="filter-select" id="typeFilter" onchange="applyFilters()">
                    <option value="">All Types</option>
                    <option value="llm">🤖 LLM</option>
                    <option value="tool">🔧 Tool</option>
                    <option value="fuzzer">🎯 Fuzzer</option>
                    <option value="manual">👤 Manual</option>
                </select>
                <div class="filter-input search-with-icon">
                    <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="11" cy="11" r="7"></circle>
                        <path d="m21 21-4.35-4.35"></path>
                    </svg>
                    <input type="text" id="searchInput" placeholder="Search findings..." onkeyup="applyFilters()">
                </div>
                <button class="btn" onclick="resetFilters()">Reset</button>
            </div>

            <!-- Table -->
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)" style="cursor: pointer;">ID</th>
                            <th onclick="sortTable(1)" style="cursor: pointer;">Severity</th>
                            <th onclick="sortTable(2)" style="cursor: pointer;">Finding</th>
                            <th onclick="sortTable(3)" style="cursor: pointer;">Source</th>
                            <th onclick="sortTable(4)" style="cursor: pointer;">Location</th>
                        </tr>
                    </thead>
                    <tbody id="findingsTable">
                        {findings_rows}
                    </tbody>
                </table>
            </div>

            <p style="color: var(--text-tertiary); font-size: 0.875rem; margin-top: 1rem;">
                <span id="visibleCount">{total_findings}</span> of {total_findings} findings shown.
                Click on a row to view details.
            </p>
        </div>
    </div>

    <script>
        // Chart.js setup with FuzzForge colors (matching stat cards)
        const chartColors = {{
            critical: '#fca5a5',  // Red/pink - matches stat-critical
            high: '#fca5a5',      // Red/pink - same as critical (they're grouped together)
            medium: '#fde047',    // Yellow - matches stat-medium
            low: '#93c5fd',       // Blue - matches stat-low
            info: '#93c5fd'       // Blue - same as low (they're grouped together)
        }};

        // Chart.js defaults for dark theme
        Chart.defaults.color = '#d1d5db';
        Chart.defaults.borderColor = 'rgba(55, 65, 81, 0.5)';

        // Severity Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: {list(severity_data.keys())},
                datasets: [{{
                    data: {list(severity_data.values())},
                    backgroundColor: [{', '.join([f"chartColors['{k}']" for k in severity_data.keys()])}],
                    borderWidth: 2,
                    borderColor: '#111427'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            color: '#e5e7eb',
                            padding: 20,
                            font: {{
                                family: 'Inter',
                                size: 13,
                                weight: '600'
                            }},
                            usePointStyle: true,
                            pointStyle: 'circle',
                            boxWidth: 12,
                            boxHeight: 12,
                            textAlign: 'left',
                            generateLabels: function(chart) {{
                                const data = chart.data;
                                return data.labels.map((label, i) => ({{
                                    text: label.toUpperCase(),
                                    fillStyle: data.datasets[0].backgroundColor[i],
                                    strokeStyle: data.datasets[0].backgroundColor[i],
                                    lineWidth: 0,
                                    hidden: false,
                                    index: i,
                                    fontColor: '#e5e7eb'
                                }}));
                            }}
                        }}
                    }},
                    tooltip: {{
                        backgroundColor: 'rgba(31, 37, 60, 0.95)',
                        titleColor: '#e5e7eb',
                        bodyColor: '#d1d5db',
                        borderColor: '#374151',
                        borderWidth: 1,
                        padding: 12,
                        displayColors: true,
                        boxPadding: 6,
                        titleFont: {{ family: 'Inter', size: 13, weight: 'bold' }},
                        bodyFont: {{ family: 'Inter', size: 12 }}
                    }}
                }}
            }}
        }});

        // Type Chart
        new Chart(document.getElementById('typeChart'), {{
            type: 'pie',
            data: {{
                labels: {list(type_data.keys())},
                datasets: [{{
                    data: {list(type_data.values())},
                    backgroundColor: ['#6366f1', '#8b5cf6', '#a78bfa', '#c084fc'],
                    borderWidth: 2,
                    borderColor: '#111427'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            color: '#e5e7eb',
                            padding: 20,
                            font: {{
                                family: 'Inter',
                                size: 13,
                                weight: '600'
                            }},
                            usePointStyle: true,
                            pointStyle: 'circle',
                            boxWidth: 12,
                            boxHeight: 12,
                            textAlign: 'left',
                            generateLabels: function(chart) {{
                                const data = chart.data;
                                const typeIcons = {{
                                    'llm': '🤖',
                                    'tool': '🔧',
                                    'fuzzer': '🎯',
                                    'manual': '👤'
                                }};
                                return data.labels.map((label, i) => ({{
                                    text: (typeIcons[label] || '') + ' ' + label.toUpperCase(),
                                    fillStyle: data.datasets[0].backgroundColor[i],
                                    strokeStyle: data.datasets[0].backgroundColor[i],
                                    lineWidth: 0,
                                    hidden: false,
                                    index: i,
                                    fontColor: '#e5e7eb'
                                }}));
                            }}
                        }}
                    }},
                    tooltip: {{
                        backgroundColor: 'rgba(31, 37, 60, 0.95)',
                        titleColor: '#e5e7eb',
                        bodyColor: '#d1d5db',
                        borderColor: '#374151',
                        borderWidth: 1,
                        padding: 12,
                        displayColors: true,
                        boxPadding: 6,
                        titleFont: {{ family: 'Inter', size: 13, weight: 'bold' }},
                        bodyFont: {{ family: 'Inter', size: 12 }}
                    }}
                }}
            }}
        }});

        // Category Chart
        new Chart(document.getElementById('categoryChart'), {{
            type: 'bar',
            data: {{
                labels: {list(category_data.keys())},
                datasets: [{{
                    label: 'Findings',
                    data: {list(category_data.values())},
                    backgroundColor: '#6366f1',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{ color: '#9ca3af', font: {{ family: 'Inter' }} }},
                        grid: {{ color: 'rgba(55, 65, 81, 0.3)' }}
                    }},
                    x: {{
                        ticks: {{ color: '#9ca3af', font: {{ family: 'Inter' }} }},
                        grid: {{ color: 'rgba(55, 65, 81, 0.3)' }}
                    }}
                }}
            }}
        }});

        // Source Chart
        new Chart(document.getElementById('sourceChart'), {{
            type: 'bar',
            data: {{
                labels: {list(source_data.keys())},
                datasets: [{{
                    label: 'Findings',
                    data: {list(source_data.values())},
                    backgroundColor: '#8b5cf6',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    x: {{
                        beginAtZero: true,
                        ticks: {{ color: '#9ca3af', font: {{ family: 'Inter' }} }},
                        grid: {{ color: 'rgba(55, 65, 81, 0.3)' }}
                    }},
                    y: {{
                        ticks: {{ color: '#9ca3af', font: {{ family: 'Inter' }} }},
                        grid: {{ color: 'rgba(55, 65, 81, 0.3)' }}
                    }}
                }}
            }}
        }});

        // Toggle finding details
        function toggleDetails(idx) {{
            const details = document.getElementById('details-' + idx);
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }}

        // Apply filters
        function applyFilters() {{
            const severityFilter = document.getElementById('severityFilter').value.toLowerCase();
            const typeFilter = document.getElementById('typeFilter').value.toLowerCase();
            const searchText = document.getElementById('searchInput').value.toLowerCase();

            const rows = document.querySelectorAll('.finding-row');
            let visibleCount = 0;

            rows.forEach(row => {{
                const severity = row.dataset.severity;
                const type = row.dataset.type;
                const text = row.textContent.toLowerCase();

                const severityMatch = !severityFilter || severity === severityFilter;
                const typeMatch = !typeFilter || type === typeFilter;
                const searchMatch = !searchText || text.includes(searchText);

                const nextRow = row.nextElementSibling; // Details row
                if (severityMatch && typeMatch && searchMatch) {{
                    row.style.display = '';
                    if (nextRow) nextRow.style.display = '';
                    visibleCount++;
                }} else {{
                    row.style.display = 'none';
                    if (nextRow) nextRow.style.display = 'none';
                }}
            }});

            document.getElementById('visibleCount').textContent = visibleCount;
        }}

        // Reset filters
        function resetFilters() {{
            document.getElementById('severityFilter').value = '';
            document.getElementById('typeFilter').value = '';
            document.getElementById('searchInput').value = '';
            applyFilters();
        }}

        // Sort table
        function sortTable(column) {{
            const table = document.getElementById('findingsTable');
            const rows = Array.from(table.querySelectorAll('.finding-row'));

            rows.sort((a, b) => {{
                const aVal = a.cells[column].textContent.trim();
                const bVal = b.cells[column].textContent.trim();
                return aVal.localeCompare(bVal);
            }});

            rows.forEach(row => {{
                const detailsRow = row.nextElementSibling;
                table.appendChild(row);
                table.appendChild(detailsRow);
            }});
        }}
    </script>
</body>
</html>
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


@app.command("all")
def all_findings(
    workflow: Optional[str] = typer.Option(
        None, "--workflow", "-w",
        help="Filter by workflow name"
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Filter by severity levels (comma-separated: error,warning,note,info)"
    ),
    since: Optional[str] = typer.Option(
        None, "--since",
        help="Show findings since date (YYYY-MM-DD)"
    ),
    limit: Optional[int] = typer.Option(
        None, "--limit", "-l",
        help="Maximum number of findings to show"
    ),
    export_format: Optional[str] = typer.Option(
        None, "--export", "-e",
        help="Export format: json, csv, html"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file for export"
    ),
    stats_only: bool = typer.Option(
        False, "--stats",
        help="Show statistics only"
    ),
    show_findings: bool = typer.Option(
        False, "--show-findings", "-f",
        help="Show actual findings content, not just summary"
    ),
    max_findings: int = typer.Option(
        50, "--max-findings",
        help="Maximum number of individual findings to display"
    )
):
    """
    📊 Show all findings for the entire project
    """
    db = get_project_db()
    if not db:
        console.print("❌ No FuzzForge project found. Run 'ff init' first.", style="red")
        raise typer.Exit(1)

    try:
        # Parse filters
        severity_list = None
        if severity:
            severity_list = [s.strip().lower() for s in severity.split(",")]

        since_date = None
        if since:
            try:
                since_date = datetime.strptime(since, "%Y-%m-%d")
            except ValueError:
                console.print(f"❌ Invalid date format: {since}. Use YYYY-MM-DD", style="red")
                raise typer.Exit(1)

        # Get aggregated stats
        stats = db.get_aggregated_stats()

        # Show statistics
        if stats_only or not export_format:
            # Create summary panel
            summary_text = f"""[bold]📊 Project Security Summary[/bold]

[cyan]Total Findings Records:[/cyan] {stats['total_findings_records']}
[cyan]Total Runs Analyzed:[/cyan] {stats['total_runs']}
[cyan]Total Security Issues:[/cyan] {stats['total_issues']}
[cyan]Recent Findings (7 days):[/cyan] {stats['recent_findings']}

[bold]Severity Distribution:[/bold]
  🔴 Critical: {stats['severity_distribution'].get('critical', 0)}
  🟠 High: {stats['severity_distribution'].get('high', 0) + stats['severity_distribution'].get('error', 0)}
  🟡 Medium: {stats['severity_distribution'].get('medium', 0) + stats['severity_distribution'].get('warning', 0)}
  🔵 Low: {stats['severity_distribution'].get('low', 0) + stats['severity_distribution'].get('note', 0)}
  ℹ️  Info: {stats['severity_distribution'].get('info', 0)}

[bold]By Workflow:[/bold]"""

            for wf_name, count in stats['workflows'].items():
                summary_text += f"\n  • {wf_name}: {count} findings"

            console.print(Panel(summary_text, box=box.ROUNDED, title="FuzzForge Project Analysis", border_style="cyan"))

        if stats_only:
            return

        # Get all findings with filters
        findings = db.get_all_findings(
            workflow=workflow,
            severity=severity_list,
            since_date=since_date,
            limit=limit
        )

        if not findings:
            console.print("ℹ️  No findings match the specified filters", style="dim")
            return

        # Export if requested
        if export_format:
            if not output:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output = f"all_findings_{timestamp}.{export_format}"

            export_all_findings(findings, export_format, output)
            console.print(f"✅ Exported {len(findings)} findings to: {output}", style="green")
            return

        # Display findings table
        table = Table(box=box.ROUNDED, title=f"All Project Findings ({len(findings)} records)")
        table.add_column("Run ID", style="bold cyan", width=36)  # Full UUID width
        table.add_column("Workflow", style="dim", width=20)
        table.add_column("Date", justify="center")
        table.add_column("Issues", justify="center", style="bold")
        table.add_column("Critical", justify="center", style="red")
        table.add_column("High", justify="center", style="red")
        table.add_column("Medium", justify="center", style="yellow")
        table.add_column("Low", justify="center", style="blue")

        # Get run info for each finding
        runs_info = {}
        for finding in findings:
            run_id = finding.run_id
            if run_id not in runs_info:
                run_info = db.get_run(run_id)
                runs_info[run_id] = run_info

        for finding in findings:
            run_id = finding.run_id
            run_info = runs_info.get(run_id)
            workflow_name = run_info.workflow if run_info else "unknown"

            summary = finding.summary
            total_issues = summary.get("total_issues", 0)
            by_severity = summary.get("by_severity", {})

            # Count issues from findings_data if summary is incomplete
            if total_issues == 0:
                if "findings" in finding.findings_data:
                    total_issues = len(finding.findings_data.get("findings", []))
                elif "runs" in finding.findings_data:
                    for run in finding.findings_data["runs"]:
                        total_issues += len(run.get("results", []))

            # Support both native (critical/high/medium/low) and SARIF (error/warning/note) severities
            critical = by_severity.get("critical", 0)
            high = by_severity.get("high", 0) + by_severity.get("error", 0)  # Map error to high
            medium = by_severity.get("medium", 0) + by_severity.get("warning", 0)  # Map warning to medium
            low = by_severity.get("low", 0) + by_severity.get("note", 0)  # Map note to low

            table.add_row(
                run_id,  # Show full Run ID
                workflow_name[:17] + "..." if len(workflow_name) > 20 else workflow_name,
                finding.created_at.strftime("%Y-%m-%d %H:%M"),
                str(total_issues),
                str(critical),
                str(high),
                str(medium),
                str(low)
            )

        console.print(table)

        # Show actual findings if requested
        if show_findings:
            display_detailed_findings(findings, max_findings)

        console.print("\n💡 Use filters to refine results: --workflow, --severity, --since")
        console.print("💡 Show findings content: --show-findings")
        console.print("💡 Export findings: --export json --output report.json")
        console.print("💡 View specific findings: [bold cyan]fuzzforge finding <run-id>[/bold cyan]")

    except Exception as e:
        console.print(f"❌ Failed to get all findings: {e}", style="red")
        raise typer.Exit(1)


def display_detailed_findings(findings: List[FindingRecord], max_findings: int):
    """Display detailed findings content"""
    console.print(f"\n📋 [bold]Detailed Findings Content[/bold] (showing up to {max_findings} findings)\n")

    findings_count = 0

    for finding_record in findings:
        if findings_count >= max_findings:
            remaining = sum(len(run.get("results", []))
                          for f in findings[findings.index(finding_record):]
                          for run in f.sarif_data.get("runs", []))
            if remaining > 0:
                console.print(f"\n... and {remaining} more findings (use --max-findings to show more)")
            break

        # Get run info for this finding
        sarif_data = finding_record.sarif_data
        if not sarif_data or "runs" not in sarif_data:
            continue

        for run in sarif_data["runs"]:
            tool = run.get("tool", {})
            driver = tool.get("driver", {})
            tool_name = driver.get("name", "Unknown Tool")

            results = run.get("results", [])
            if not results:
                continue

            # Group results by severity
            for result in results:
                if findings_count >= max_findings:
                    break

                findings_count += 1

                # Extract key information
                rule_id = result.get("ruleId", "unknown")
                level = result.get("level", "note").upper()
                message_text = result.get("message", {}).get("text", "No description")

                # Get location information
                locations = result.get("locations", [])
                location_str = "Unknown location"
                if locations:
                    physical = locations[0].get("physicalLocation", {})
                    artifact = physical.get("artifactLocation", {})
                    region = physical.get("region", {})

                    file_path = artifact.get("uri", "")
                    line_number = region.get("startLine", "")

                    if file_path:
                        location_str = f"{file_path}"
                        if line_number:
                            location_str += f":{line_number}"

                # Get severity style
                severity_style = {
                    "ERROR": "bold red",
                    "WARNING": "bold yellow",
                    "NOTE": "bold blue",
                    "INFO": "bold cyan"
                }.get(level, "white")

                # Create finding panel
                finding_content = f"""[bold]Rule:[/bold] {rule_id}
[bold]Location:[/bold] {location_str}
[bold]Tool:[/bold] {tool_name}
[bold]Run:[/bold] {finding_record.run_id[:12]}...

[bold]Description:[/bold]
{message_text}"""

                # Add code context if available
                region = locations[0].get("physicalLocation", {}).get("region", {}) if locations else {}
                if region.get("snippet", {}).get("text"):
                    code_snippet = region["snippet"]["text"].strip()
                    finding_content += f"\n\n[bold]Code:[/bold]\n[dim]{code_snippet}[/dim]"

                console.print(Panel(
                    finding_content,
                    title=f"[{severity_style}]{level}[/{severity_style}] Finding #{findings_count}",
                    border_style=severity_style.split()[-1] if " " in severity_style else severity_style,
                    box=box.ROUNDED
                ))

                console.print()  # Add spacing between findings


def export_all_findings(findings: List[FindingRecord], format: str, output_path: str):
    """Export all findings to specified format"""
    output_file = Path(output_path)

    if format == "json":
        # Combine all SARIF data
        all_results = []
        for finding in findings:
            if "runs" in finding.sarif_data:
                for run in finding.sarif_data["runs"]:
                    for result in run.get("results", []):
                        result_entry = {
                            "run_id": finding.run_id,
                            "created_at": finding.created_at.isoformat(),
                            **result
                        }
                        all_results.append(result_entry)

        with open(output_file, 'w') as f:
            json.dump({
                "total_findings": len(findings),
                "export_date": datetime.now().isoformat(),
                "results": all_results
            }, f, indent=2)

    elif format == "csv":
        # Export to CSV
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Run ID", "Date", "Severity", "Rule ID", "Message", "File", "Line"])

            for finding in findings:
                if "runs" in finding.sarif_data:
                    for run in finding.sarif_data["runs"]:
                        for result in run.get("results", []):
                            locations = result.get("locations", [])
                            location_info = locations[0] if locations else {}
                            physical = location_info.get("physicalLocation", {})
                            artifact = physical.get("artifactLocation", {})
                            region = physical.get("region", {})

                            writer.writerow([
                                finding.run_id[:12],
                                finding.created_at.strftime("%Y-%m-%d %H:%M"),
                                result.get("level", "note"),
                                result.get("ruleId", ""),
                                result.get("message", {}).get("text", ""),
                                artifact.get("uri", ""),
                                region.get("startLine", "")
                            ])

    elif format == "html":
        # Generate HTML report
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>FuzzForge Security Findings Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .stats {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4CAF50; color: white; }}
        .error {{ color: red; font-weight: bold; }}
        .warning {{ color: orange; font-weight: bold; }}
        .note {{ color: blue; }}
        .info {{ color: gray; }}
    </style>
</head>
<body>
    <h1>FuzzForge Security Findings Report</h1>
    <div class="stats">
        <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>
    </div>
    <table>
        <tr>
            <th>Run ID</th>
            <th>Date</th>
            <th>Severity</th>
            <th>Rule</th>
            <th>Message</th>
            <th>Location</th>
        </tr>"""

        for finding in findings:
            if "runs" in finding.sarif_data:
                for run in finding.sarif_data["runs"]:
                    for result in run.get("results", []):
                        level = result.get("level", "note")
                        locations = result.get("locations", [])
                        location_info = locations[0] if locations else {}
                        physical = location_info.get("physicalLocation", {})
                        artifact = physical.get("artifactLocation", {})
                        region = physical.get("region", {})

                        html_content += f"""
        <tr>
            <td>{finding.run_id[:12]}</td>
            <td>{finding.created_at.strftime("%Y-%m-%d %H:%M")}</td>
            <td class="{level}">{level.upper()}</td>
            <td>{result.get("ruleId", "")}</td>
            <td>{result.get("message", {}).get("text", "")}</td>
            <td>{artifact.get("uri", "")} : {region.get("startLine", "")}</td>
        </tr>"""

        html_content += """
    </table>
</body>
</html>"""

        with open(output_file, 'w') as f:
            f.write(html_content)


@app.callback(invoke_without_command=True)
def findings_callback(ctx: typer.Context):
    """
    🔍 View and export security findings
    """
    # Check if a subcommand is being invoked
    if ctx.invoked_subcommand is not None:
        # Let the subcommand handle it
        return

    # Default to history when no subcommand provided
    findings_history(limit=20)
