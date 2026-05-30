from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from rai_audit.core.findings import AuditFinding, RemediationEffort, Severity

_FAIRNESS_STANDARDS = ["EU-AI-ACT-ART-10", "NIST-AI-RMF-MEASURE-2.5"]


@dataclass
class GroupMetrics:
    group_col: str
    group_val: str
    n: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    selection_rate: float
    false_positive_rate: float
    false_negative_rate: float
    true_positive_rate: float
    true_negative_rate: float

    def to_dict(self) -> dict:
        return {
            "group_col": self.group_col,
            "group_val": self.group_val,
            "n": self.n,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "selection_rate": round(self.selection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "true_positive_rate": round(self.true_positive_rate, 4),
            "true_negative_rate": round(self.true_negative_rate, 4),
        }


def compute_group_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    group_col: str,
    group_values: np.ndarray,
) -> list[GroupMetrics]:
    results = []
    unique_groups = np.unique(group_values)

    for val in unique_groups:
        mask = group_values == val
        yt = y_true[mask]
        yp = y_pred[mask]
        n = int(mask.sum())

        if n < 5:
            continue

        tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel() if len(np.unique(yt)) > 1 else (0, 0, 0, n)

        denom_fpr = fp + tn
        denom_fnr = fn + tp
        denom_tpr = tp + fn
        denom_tnr = tn + fp

        results.append(
            GroupMetrics(
                group_col=group_col,
                group_val=str(val),
                n=n,
                accuracy=accuracy_score(yt, yp),
                precision=precision_score(yt, yp, zero_division=0),
                recall=recall_score(yt, yp, zero_division=0),
                f1=f1_score(yt, yp, zero_division=0),
                selection_rate=float(yp.mean()),
                false_positive_rate=fp / denom_fpr if denom_fpr > 0 else 0.0,
                false_negative_rate=fn / denom_fnr if denom_fnr > 0 else 0.0,
                true_positive_rate=tp / denom_tpr if denom_tpr > 0 else 0.0,
                true_negative_rate=tn / denom_tnr if denom_tnr > 0 else 0.0,
            )
        )
    return results


def fairness_findings_classification(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    sensitive_features: pd.DataFrame,
    max_demographic_parity_diff: float = 0.10,
    max_equal_opportunity_diff: float = 0.10,
    max_fnr_diff: float = 0.15,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []

    for col in sensitive_features.columns:
        group_vals = sensitive_features[col].astype(str).values
        metrics = compute_group_metrics(y_true, y_pred, col, group_vals)

        if len(metrics) < 2:
            continue

        # Demographic parity difference (max - min selection rate)
        selection_rates = [m.selection_rate for m in metrics]
        dp_diff = max(selection_rates) - min(selection_rates)
        best_sr = max(metrics, key=lambda m: m.selection_rate)
        worst_sr = min(metrics, key=lambda m: m.selection_rate)

        severity = _diff_severity(dp_diff, max_demographic_parity_diff)
        findings.append(
            AuditFinding(
                check_id="FAIR-CLS-001",
                title=f"Demographic parity difference for '{col}'",
                severity=severity,
                description=(
                    f"Selection rate difference across groups in '{col}' is "
                    f"{dp_diff:.3f} (threshold: {max_demographic_parity_diff}). "
                    f"Highest: {best_sr.group_val} ({best_sr.selection_rate:.3f}), "
                    f"lowest: {worst_sr.group_val} ({worst_sr.selection_rate:.3f})."
                ),
                evidence={
                    "demographic_parity_difference": round(dp_diff, 4),
                    "threshold": max_demographic_parity_diff,
                    "group_metrics": {m.group_val: m.selection_rate for m in metrics},
                },
                recommendation=(
                    "Investigate training data selection rates by group. "
                    "Consider post-processing calibration or resampling."
                ),
                category="Fairness",
                affected_group=col,
                remediation_effort=RemediationEffort.HIGH,
                standards_refs=_FAIRNESS_STANDARDS,
            )
        )

        # Equal opportunity difference (recall / TPR)
        recalls = [m.recall for m in metrics]
        eo_diff = max(recalls) - min(recalls)
        best_rec = max(metrics, key=lambda m: m.recall)
        worst_rec = min(metrics, key=lambda m: m.recall)

        severity = _diff_severity(eo_diff, max_equal_opportunity_diff)
        findings.append(
            AuditFinding(
                check_id="FAIR-CLS-002",
                title=f"Equal opportunity difference for '{col}'",
                severity=severity,
                description=(
                    f"True positive rate difference across groups in '{col}' is "
                    f"{eo_diff:.3f} (threshold: {max_equal_opportunity_diff}). "
                    f"Highest: {best_rec.group_val} ({best_rec.recall:.3f}), "
                    f"lowest: {worst_rec.group_val} ({worst_rec.recall:.3f})."
                ),
                evidence={
                    "equal_opportunity_difference": round(eo_diff, 4),
                    "threshold": max_equal_opportunity_diff,
                    "group_recalls": {m.group_val: round(m.recall, 4) for m in metrics},
                },
                recommendation=(
                    "The model is less likely to correctly identify positive cases for some groups. "
                    "Review training data balance and consider threshold adjustment per group."
                ),
                category="Fairness",
                affected_group=col,
                remediation_effort=RemediationEffort.HIGH,
                standards_refs=_FAIRNESS_STANDARDS,
            )
        )

        # FNR gap
        fnrs = [m.false_negative_rate for m in metrics]
        fnr_diff = max(fnrs) - min(fnrs)
        worst_fnr = max(metrics, key=lambda m: m.false_negative_rate)
        best_fnr = min(metrics, key=lambda m: m.false_negative_rate)

        severity = _diff_severity(fnr_diff, max_fnr_diff)
        findings.append(
            AuditFinding(
                check_id="FAIR-CLS-003",
                title=f"False negative rate gap for '{col}'",
                severity=severity,
                description=(
                    f"False negative rate gap across groups in '{col}' is {fnr_diff:.3f}. "
                    f"Highest FNR: {worst_fnr.group_val} ({worst_fnr.false_negative_rate:.3f}), "
                    f"lowest: {best_fnr.group_val} ({best_fnr.false_negative_rate:.3f})."
                ),
                evidence={
                    "fnr_gap": round(fnr_diff, 4),
                    "group_fnrs": {m.group_val: round(m.false_negative_rate, 4) for m in metrics},
                },
                recommendation=(
                    "A higher false negative rate for a group means the model misses more positives "
                    "in that group. Review error patterns and consider group-specific thresholds."
                ),
                category="Fairness",
                affected_group=col,
                remediation_effort=RemediationEffort.HIGH,
                standards_refs=_FAIRNESS_STANDARDS,
            )
        )

    return findings


def _diff_severity(diff: float, threshold: float) -> Severity:
    if diff > threshold * 2:
        return Severity.HIGH
    if diff > threshold:
        return Severity.MEDIUM
    return Severity.PASSED


class FairnessAudit:
    """Standalone fairness-only audit for classification models."""

    def __init__(
        self,
        y_true,
        y_pred,
        sensitive_features: pd.DataFrame,
        y_prob=None,
        project_name: str = "Fairness Audit",
        max_demographic_parity_diff: float = 0.10,
        max_equal_opportunity_diff: float = 0.10,
    ):
        self.y_true = np.asarray(y_true)
        self.y_pred = np.asarray(y_pred)
        self.sensitive_features = sensitive_features
        self.y_prob = np.asarray(y_prob) if y_prob is not None else None
        self.project_name = project_name
        self.max_dp_diff = max_demographic_parity_diff
        self.max_eo_diff = max_equal_opportunity_diff

    def run(self):
        from rai_audit.core.findings import AuditReport
        from rai_audit.core.scoring import compute_risk_matrix
        from rai_audit.core.history import save_run

        findings = fairness_findings_classification(
            self.y_true,
            self.y_pred,
            self.sensitive_features,
            max_demographic_parity_diff=self.max_dp_diff,
            max_equal_opportunity_diff=self.max_eo_diff,
        )

        risk_matrix = compute_risk_matrix(findings)
        report = AuditReport(
            project_name=self.project_name,
            audit_type="classification_fairness",
            risk_matrix=risk_matrix,
            findings=findings,
            metadata={"sensitive_features": list(self.sensitive_features.columns)},
        )
        save_run(report.to_dict())
        return report
