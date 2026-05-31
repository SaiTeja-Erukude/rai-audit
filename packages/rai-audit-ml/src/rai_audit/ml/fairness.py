from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

import numpy as np
import pandas as pd
from rai_audit.core.findings import AuditFinding, RemediationEffort, Severity
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

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
    positive_label=1,
) -> list[GroupMetrics]:
    """Compute binary one-vs-rest metrics for a selected positive label."""
    results = []
    unique_groups = np.unique(group_values)

    for val in unique_groups:
        mask = group_values == val
        yt = (y_true[mask] == positive_label).astype(int)
        yp = (y_pred[mask] == positive_label).astype(int)
        n = int(mask.sum())

        if n < 5:
            continue

        tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()

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
    positive_label=None,
    include_intersections: bool = False,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    labels = _positive_labels(y_true, y_pred, positive_label)
    fairness_slices = _fairness_slices(sensitive_features, include_intersections)

    for label in labels:
        suffix = "" if len(labels) == 1 else f"-{_slug(label)}"
        class_context = "" if len(labels) == 1 else f" for class '{label}'"
        for col in fairness_slices.columns:
            group_vals = fairness_slices[col].astype(str).values
            metrics = compute_group_metrics(y_true, y_pred, col, group_vals, positive_label=label)

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
                    check_id=f"FAIR-CLS-001{suffix}",
                    title=f"Demographic parity difference for '{col}'{class_context}",
                    severity=severity,
                    description=(
                        f"Selection rate difference across groups in '{col}'{class_context} is "
                        f"{dp_diff:.3f} (threshold: {max_demographic_parity_diff}). "
                        f"Highest: {best_sr.group_val} ({best_sr.selection_rate:.3f}), "
                        f"lowest: {worst_sr.group_val} ({worst_sr.selection_rate:.3f})."
                    ),
                    evidence={
                        "positive_label": str(label),
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
                    check_id=f"FAIR-CLS-002{suffix}",
                    title=f"Equal opportunity difference for '{col}'{class_context}",
                    severity=severity,
                    description=(
                        f"True positive rate difference across groups in '{col}'{class_context} is "
                        f"{eo_diff:.3f} (threshold: {max_equal_opportunity_diff}). "
                        f"Highest: {best_rec.group_val} ({best_rec.recall:.3f}), "
                        f"lowest: {worst_rec.group_val} ({worst_rec.recall:.3f})."
                    ),
                    evidence={
                        "positive_label": str(label),
                        "equal_opportunity_difference": round(eo_diff, 4),
                        "threshold": max_equal_opportunity_diff,
                        "group_recalls": {m.group_val: round(m.recall, 4) for m in metrics},
                    },
                    recommendation=(
                        "The model is less likely to correctly identify positive cases for some "
                        "groups. Review training data balance and consider threshold adjustment "
                        "per group."
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
                    check_id=f"FAIR-CLS-003{suffix}",
                    title=f"False negative rate gap for '{col}'{class_context}",
                    severity=severity,
                    description=(
                        f"False negative rate gap across groups in '{col}'{class_context} is "
                        f"{fnr_diff:.3f}. Highest FNR: {worst_fnr.group_val} "
                        f"({worst_fnr.false_negative_rate:.3f}), lowest: {best_fnr.group_val} "
                        f"({best_fnr.false_negative_rate:.3f})."
                    ),
                    evidence={
                        "positive_label": str(label),
                        "fnr_gap": round(fnr_diff, 4),
                        "group_fnrs": {
                            m.group_val: round(m.false_negative_rate, 4) for m in metrics
                        },
                    },
                    recommendation=(
                        "A higher false negative rate for a group means the model misses more "
                        "positives in that group. Review error patterns and consider "
                        "group-specific "
                        "thresholds."
                    ),
                    category="Fairness",
                    affected_group=col,
                    remediation_effort=RemediationEffort.HIGH,
                    standards_refs=_FAIRNESS_STANDARDS,
                )
            )

    return findings


def _positive_labels(y_true: np.ndarray, y_pred: np.ndarray, positive_label) -> list:
    labels = list(np.unique(np.concatenate([np.asarray(y_true), np.asarray(y_pred)])))
    if positive_label is not None:
        if positive_label not in labels:
            raise ValueError(f"positive_label {positive_label!r} is not present in labels")
        return [positive_label]
    if len(labels) <= 2:
        return [1 if 1 in labels else labels[-1]]
    return labels


def _fairness_slices(sensitive_features: pd.DataFrame, include_intersections: bool) -> pd.DataFrame:
    slices = sensitive_features.astype(str).copy()
    if include_intersections:
        for left, right in combinations(slices.columns, 2):
            slices[f"{left}&{right}"] = (
                left
                + "="
                + slices[left].astype(str)
                + "|"
                + right
                + "="
                + slices[right].astype(str)
            )
    return slices


def _slug(value) -> str:
    normalized = "".join(char if char.isalnum() else "-" for char in str(value).upper())
    return "-".join(part for part in normalized.split("-") if part)


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
        positive_label=None,
        include_intersections: bool = False,
    ):
        self.y_true = np.asarray(y_true)
        self.y_pred = np.asarray(y_pred)
        self.sensitive_features = sensitive_features
        self.y_prob = np.asarray(y_prob) if y_prob is not None else None
        self.project_name = project_name
        self.max_dp_diff = max_demographic_parity_diff
        self.max_eo_diff = max_equal_opportunity_diff
        self.positive_label = positive_label
        self.include_intersections = include_intersections

    def run(self):
        from rai_audit.core.findings import AuditReport
        from rai_audit.core.history import save_run
        from rai_audit.core.scoring import compute_risk_matrix

        findings = fairness_findings_classification(
            self.y_true,
            self.y_pred,
            self.sensitive_features,
            max_demographic_parity_diff=self.max_dp_diff,
            max_equal_opportunity_diff=self.max_eo_diff,
            positive_label=self.positive_label,
            include_intersections=self.include_intersections,
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
