from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_HISTORY_DIR = Path(".rai-audit") / "history"


def save_run(report_dict: dict, directory: Path | None = None) -> Path:
    """Persist an audit run as a timestamped JSON file."""
    directory = directory or DEFAULT_HISTORY_DIR
    directory.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    slug = report_dict.get("project_name", "audit").replace(" ", "_").lower()
    path = directory / f"{slug}_{ts}.json"
    path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
    return path


def load_run(path: Path) -> dict:
    """Load a persisted audit run."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def list_runs(directory: Path | None = None) -> list[Path]:
    """List all persisted audit run files, newest first."""
    directory = directory or DEFAULT_HISTORY_DIR
    if not directory.exists():
        return []
    return sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def diff_runs(path_a: Path, path_b: Path) -> dict:
    """
    Compare two audit runs and return a structured diff.
    path_a is the older run, path_b is the newer run.
    """
    a = load_run(Path(path_a))
    b = load_run(Path(path_b))

    risk_a = {r["category"]: r["risk_level"] for r in a.get("risk_matrix", [])}
    risk_b = {r["category"]: r["risk_level"] for r in b.get("risk_matrix", [])}

    risk_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    risk_changes: list[dict] = []
    all_cats = sorted(set(risk_a) | set(risk_b))
    for cat in all_cats:
        old = risk_a.get(cat, "n/a")
        new = risk_b.get(cat, "n/a")
        if old != new:
            old_rank = risk_order.get(old, -1)
            new_rank = risk_order.get(new, -1)
            direction = "REGRESSION" if new_rank > old_rank else "IMPROVED"
            risk_changes.append(
                {"category": cat, "from": old, "to": new, "direction": direction}
            )

    ids_a = {f["check_id"] for f in a.get("findings", []) if f.get("severity") != "passed"}
    ids_b = {f["check_id"] for f in b.get("findings", []) if f.get("severity") != "passed"}

    new_findings = [
        f for f in b.get("findings", [])
        if f["check_id"] not in ids_a and f.get("severity") != "passed"
    ]
    resolved_findings = [
        f for f in a.get("findings", [])
        if f["check_id"] not in ids_b and f.get("severity") != "passed"
    ]

    return {
        "project_name": b.get("project_name", "unknown"),
        "run_a": str(path_a),
        "run_b": str(path_b),
        "risk_changes": risk_changes,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "summary": {
            "regressions": sum(1 for c in risk_changes if c["direction"] == "REGRESSION"),
            "improvements": sum(1 for c in risk_changes if c["direction"] == "IMPROVED"),
            "new_finding_count": len(new_findings),
            "resolved_finding_count": len(resolved_findings),
        },
    }


def render_diff_text(diff: dict) -> str:
    """Render a diff dict as a human-readable text report."""
    lines: list[str] = []
    lines.append(f"Audit Diff: {diff['project_name']}")
    lines.append("─" * 60)

    if diff["risk_changes"]:
        for c in diff["risk_changes"]:
            arrow = "⚠ REGRESSION" if c["direction"] == "REGRESSION" else "✓ IMPROVED"
            lines.append(f"{c['category']:30s}  {c['from'].upper()} → {c['to'].upper()}    {arrow}")
    else:
        lines.append("No risk level changes.")

    if diff["new_findings"]:
        lines.append("\nNew findings:")
        for f in diff["new_findings"]:
            lines.append(f"  [{f['severity'].upper()}] {f['check_id']}: {f['title']}")

    if diff["resolved_findings"]:
        lines.append("\nResolved findings:")
        for f in diff["resolved_findings"]:
            lines.append(f"  ✓ {f['check_id']}: {f['title']}")

    s = diff["summary"]
    lines.append(
        f"\nSummary: {s['regressions']} regression(s), {s['improvements']} improvement(s), "
        f"{s['new_finding_count']} new, {s['resolved_finding_count']} resolved."
    )
    return "\n".join(lines)
