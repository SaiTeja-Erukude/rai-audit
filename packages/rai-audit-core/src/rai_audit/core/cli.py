from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from rai_audit.core.history import diff_runs, list_runs, load_run, render_diff_text
from rai_audit.core.scoring import gate_check

app = typer.Typer(
    name="rai-audit",
    help="Responsible AI (RAI) Audit Kit — evidence-grade audits for responsible AI systems.",
    no_args_is_help=True,
)
export_app = typer.Typer(no_args_is_help=True, help="Export audit results to different formats.")
app.add_typer(export_app, name="export")
console = Console()


@app.command()
def init(
    project: str = typer.Option("my-project", help="Project name"),
    output: Path = typer.Option(Path("audit.yaml"), help="Output config path"),
) -> None:
    """Scaffold a starter audit.yaml config file."""
    config = f"""project:
  name: {project}
  owner: ""
  version: 0.1.0

audit:
  output_dir: ./audit-report
  report_formats:
    - html
    - markdown
    - json

checks:
  fairness:
    enabled: true
    max_demographic_parity_difference: 0.10
    max_equal_opportunity_difference: 0.10
  robustness:
    enabled: true
  data_quality:
    enabled: true
  drift:
    enabled: false

gate:
  min_score: null
  fail_on_critical: true
"""
    output.write_text(config, encoding="utf-8")
    console.print(f"[green]✓[/green] Created {output}")


@app.command()
def report(
    input: Path = typer.Argument(..., help="Path to a saved audit JSON run"),
    format: str = typer.Option("html", help="Output format: html | markdown | json"),
    output: Optional[Path] = typer.Option(None, help="Output file path"),
) -> None:
    """Render a report from a saved audit run JSON file."""
    if not input.exists():
        console.print(f"[red]Error:[/red] {input} not found")
        raise typer.Exit(1)

    run = load_run(input)

    if output is None:
        output = input.with_suffix(f".{format}" if format != "json" else ".out.json")

    if format == "json":
        output.write_text(json.dumps(run, indent=2), encoding="utf-8")
    elif format == "markdown":
        from rai_audit.core.findings import AuditReport, AuditFinding, CategoryRisk, Severity, RiskLevel, RemediationEffort
        from rai_audit.core.report import render_markdown
        report_obj = _dict_to_report(run)
        output.write_text(render_markdown(report_obj), encoding="utf-8")
    elif format == "html":
        from rai_audit.core.report import render_html
        report_obj = _dict_to_report(run)
        output.write_text(render_html(report_obj), encoding="utf-8")
    else:
        console.print(f"[red]Unknown format:[/red] {format}")
        raise typer.Exit(1)

    console.print(f"[green]✓[/green] Report written to {output}")


@app.command()
def gate(
    input: Path = typer.Argument(..., help="Path to saved audit JSON run"),
    min_score: Optional[float] = typer.Option(None, help="Minimum required score"),
    fail_on_critical: bool = typer.Option(True, help="Fail if any critical findings exist"),
    output_json: Optional[Path] = typer.Option(None, help="Write gate result to JSON file"),
) -> None:
    """
    CI/CD deployment gate. Exits with code 1 on failure, 0 on pass.
    """
    if not input.exists():
        console.print(f"[red]Error:[/red] {input} not found")
        raise typer.Exit(1)

    run = load_run(input)
    passed, reason = gate_check(run, min_score=min_score, fail_on_critical=fail_on_critical)

    risk_matrix = {r["category"]: r["risk_level"] for r in run.get("risk_matrix", [])}
    critical_count = sum(
        1 for f in run.get("findings", []) if f.get("severity") == "critical"
    )

    result = {
        "passed": passed,
        "reason": reason,
        "critical_count": critical_count,
        "risk_matrix": risk_matrix,
    }

    if output_json:
        output_json.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if passed:
        console.print(f"[green]✓ GATE PASSED:[/green] {reason}")
    else:
        console.print(f"[red]✗ GATE FAILED:[/red] {reason}")
        raise typer.Exit(1)


@app.command()
def diff(
    run_a: Path = typer.Argument(..., help="Older audit run JSON"),
    run_b: Path = typer.Argument(..., help="Newer audit run JSON"),
    output_json: Optional[Path] = typer.Option(None, help="Write diff to JSON file"),
) -> None:
    """Compare two audit runs and show what changed."""
    for p in [run_a, run_b]:
        if not p.exists():
            console.print(f"[red]Error:[/red] {p} not found")
            raise typer.Exit(1)

    result = diff_runs(run_a, run_b)

    if output_json:
        output_json.write_text(json.dumps(result, indent=2), encoding="utf-8")

    console.print(render_diff_text(result))


@app.command()
def history(
    directory: Path = typer.Option(Path(".rai-audit/history"), help="History directory"),
) -> None:
    """List past audit runs."""
    runs = list_runs(directory)
    if not runs:
        console.print("No audit runs found.")
        return

    table = Table(title="Audit History")
    table.add_column("File", style="cyan")
    table.add_column("Project")
    table.add_column("Risk")
    table.add_column("Findings", justify="right")

    for run_path in runs:
        try:
            run = load_run(run_path)
            risk_levels = [r["risk_level"] for r in run.get("risk_matrix", [])]
            worst = max(risk_levels, key=lambda r: ["low","medium","high","critical"].index(r)) if risk_levels else "n/a"
            count = sum(1 for f in run.get("findings", []) if f.get("severity") not in ("passed", "info"))
            table.add_row(run_path.name, run.get("project_name", "?"), worst.upper(), str(count))
        except Exception:
            table.add_row(run_path.name, "?", "?", "?")

    console.print(table)


def _dict_to_report(d: dict):
    """Reconstruct an AuditReport from a saved dict (for re-rendering)."""
    from rai_audit.core.findings import (
        AuditFinding, AuditReport, CategoryRisk,
        RemediationEffort, RiskLevel, Severity,
    )

    findings = [
        AuditFinding(
            check_id=f["check_id"],
            title=f["title"],
            severity=Severity(f["severity"]),
            description=f["description"],
            evidence=f.get("evidence", {}),
            recommendation=f.get("recommendation", ""),
            category=f.get("category", ""),
            affected_group=f.get("affected_group"),
            remediation_effort=RemediationEffort(f.get("remediation_effort", "medium")),
            standards_refs=f.get("standards_refs", []),
            timestamp=f.get("timestamp"),
        )
        for f in d.get("findings", [])
    ]

    risk_matrix = [
        CategoryRisk(
            category=r["category"],
            risk_level=RiskLevel(r["risk_level"]),
            finding_count=r["finding_count"],
            passed_count=r["passed_count"],
        )
        for r in d.get("risk_matrix", [])
    ]

    return AuditReport(
        project_name=d.get("project_name", "Audit"),
        audit_type=d.get("audit_type", ""),
        risk_matrix=risk_matrix,
        findings=findings,
        metadata=d.get("metadata", {}),
        overall_score=d.get("overall_score"),
    )


@export_app.command("model-card")
def model_card(
    input: Path = typer.Argument(..., help="Path to saved audit JSON run"),
    output: Optional[Path] = typer.Option(None, help="Output .md file path (default: <input>.model-card.md)"),
    model_name: str = typer.Option("", help="Model display name"),
    model_version: str = typer.Option("", help="Model version string"),
    author: str = typer.Option("", help="Author / team name"),
    license_id: str = typer.Option("MIT", help="SPDX license identifier"),
    language: str = typer.Option("en", help="ISO 639-1 language code"),
) -> None:
    """Export an audit run as a Markdown model card (HuggingFace-compatible)."""
    if not input.exists():
        console.print(f"[red]Error:[/red] {input} not found")
        raise typer.Exit(1)

    run = load_run(input)
    report_obj = _dict_to_report(run)

    if output is None:
        output = input.with_suffix(".model-card.md")

    from rai_audit.core.model_card import render_model_card

    card_text = render_model_card(
        report_obj,
        model_name=model_name,
        model_version=model_version,
        author=author,
        license_id=license_id,
        language=language,
    )
    output.write_text(card_text, encoding="utf-8")
    console.print(f"[green]✓[/green] Model card written to {output}")
