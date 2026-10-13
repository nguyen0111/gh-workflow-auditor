"""CLI entry point for gh-workflow-auditor."""

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from ruamel.yaml import YAML

from auditor.rules import (
    check_missing_permissions,
    check_missing_timeouts,
    check_pull_request_target,
    check_unpinned_actions,
    Finding,
)

app = typer.Typer(help="GitHub Actions workflow security and operational compliance auditor")
console = Console()


@app.command()
def main(path: str = typer.Argument(".github/workflows", help="Path to workflow directory or file")) -> None:
    """Scan GitHub Actions workflow files for compliance issues."""
    workflow_path = Path(path)

    if not workflow_path.exists():
        console.print(f"[red]Error: Path '{path}' does not exist.[/red]")
        raise typer.Exit(1)

    yaml = YAML()
    all_findings: list[Finding] = []

    # Find all .yml and .yaml files
    if workflow_path.is_file():
        workflow_files = [workflow_path]
    else:
        workflow_files = workflow_path.glob("**/*.y*ml")
        workflow_files = [f for f in workflow_files if f.name.endswith(".yml") or f.name.endswith(".yaml")]

    for workflow_file in workflow_files:
        try:
            with open(workflow_file, "r") as f:
                data = yaml.load(f)
                if data is None:
                    continue

                # Run all checks
                all_findings.extend(check_unpinned_actions(data, str(workflow_file)))
                all_findings.extend(check_missing_permissions(data, str(workflow_file)))
                all_findings.extend(check_pull_request_target(data, str(workflow_file)))
                all_findings.extend(check_missing_timeouts(data, str(workflow_file)))
        except Exception as e:
            console.print(f"[yellow]Warning: Could not parse {workflow_file}: {e}[/yellow]")

    # Display results
    if not all_findings:
        console.print("[green]✓ No compliance issues found![/green]")
        raise typer.Exit(0)

    # Create table
    table = Table(title="Compliance Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Rule ID")
    table.add_column("Message")
    table.add_column("File")
    table.add_column("Line")

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    for finding in all_findings:
        color = severity_colors.get(finding.severity, "white")
        table.add_row(
            f"[{color}]{finding.severity}[/{color}]",
            finding.rule_id,
            finding.message,
            finding.file,
            str(finding.line),
        )

    console.print(table)

    # Exit with error code if critical or high findings exist
    has_critical_or_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in all_findings
    )
    if has_critical_or_high:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
