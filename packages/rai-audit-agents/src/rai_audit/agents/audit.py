from __future__ import annotations

from datetime import datetime, timezone

from rai_audit.agents.checks import (
    memory_findings,
    memory_poisoning_findings,
    permission_findings,
    prompt_injection_findings,
    resource_budget_findings,
    tool_use_findings,
)
from rai_audit.agents.models import AgentTrace
from rai_audit.core.engine import BaseAudit
from rai_audit.core.findings import AuditReport
from rai_audit.core.history import save_run
from rai_audit.core.scoring import compute_risk_matrix


class AgentAudit(BaseAudit):
    """Audit an agent execution trace for tool, memory, permission, and injection risks."""

    def __init__(
        self,
        trace: AgentTrace,
        *,
        allowed_tools: list[str] | tuple[str, ...] | None = None,
        project_name: str | None = None,
        metadata: dict | None = None,
        thresholds: dict | None = None,
        persist: bool = True,
    ):
        self.trace = trace
        self.allowed_tools = allowed_tools
        self.project_name = project_name or trace.workflow_name
        self.metadata = metadata or {}
        self.thresholds = thresholds or {}
        self.persist = persist

    def run(self) -> AuditReport:
        findings = [
            *tool_use_findings(
                self.trace,
                allowed_tools=self.allowed_tools,
                max_tool_errors=self.thresholds.get("max_tool_errors", 0),
            ),
            *memory_findings(self.trace),
            *memory_poisoning_findings(self.trace),
            *permission_findings(self.trace),
            *prompt_injection_findings(self.trace),
            *resource_budget_findings(
                self.trace,
                max_tool_calls=self.thresholds.get("max_tool_calls", 50),
                max_consecutive_tool_calls=self.thresholds.get("max_consecutive_tool_calls", 10),
            ),
        ]
        timestamp = datetime.now(timezone.utc).isoformat()
        for finding in findings:
            finding.timestamp = timestamp
        report = AuditReport(
            project_name=self.project_name,
            audit_type="agent_trace",
            risk_matrix=compute_risk_matrix(findings),
            findings=findings,
            metadata={
                **self.trace.metadata,
                **self.metadata,
                "trace_id": self.trace.trace_id,
                "group_id": self.trace.group_id,
                "workflow_name": self.trace.workflow_name,
                "event_count": len(self.trace.events),
            },
        )
        if self.persist:
            save_run(report.to_dict())
        return report
