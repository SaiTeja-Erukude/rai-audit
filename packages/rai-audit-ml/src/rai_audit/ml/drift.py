from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
import pandas as pd
from rai_audit.core.engine import BaseAudit
from rai_audit.core.findings import AuditFinding, AuditReport, RemediationEffort, Severity
from rai_audit.core.history import save_run
from rai_audit.core.scoring import compute_risk_matrix
from scipy import stats

_DRIFT_STANDARDS = ["NIST-AI-RMF-MEASURE-2.6", "EU-AI-ACT-ART-9"]


def drift_findings(
    reference: pd.DataFrame,
    current: pd.DataFrame,
    sensitive_features: pd.DataFrame | None = None,
    y_true_ref: np.ndarray | None = None,
    y_pred_ref: np.ndarray | None = None,
    y_true_cur: np.ndarray | None = None,
    y_pred_cur: np.ndarray | None = None,
    ks_pvalue_threshold: float = 0.05,
    *,
    reference_sensitive_features: pd.DataFrame | None = None,
    current_sensitive_features: pd.DataFrame | None = None,
    max_subgroup_proportion_diff: float = 0.10,
    max_group_error_rate_diff: float = 0.10,
) -> list[AuditFinding]:
    """
    Detect drift between reference and current batches.

    ``sensitive_features`` is retained as an alias for
    ``reference_sensitive_features`` for compatibility with the original API.
    Both reference and current sensitive features are required for subgroup
    and group error-rate monitoring.
    """
    reference_sensitive_features = _resolve_reference_sensitive_features(
        sensitive_features,
        reference_sensitive_features,
    )
    _validate_inputs(
        reference,
        current,
        reference_sensitive_features,
        current_sensitive_features,
        y_true_ref,
        y_pred_ref,
        y_true_cur,
        y_pred_cur,
    )

    findings = _feature_drift_findings(reference, current, ks_pvalue_threshold)

    if y_pred_ref is not None and y_pred_cur is not None:
        findings.append(_prediction_drift_finding(y_pred_ref, y_pred_cur, ks_pvalue_threshold))

    if reference_sensitive_features is not None and current_sensitive_features is not None:
        findings.extend(
            _subgroup_drift_findings(
                reference_sensitive_features,
                current_sensitive_features,
                max_subgroup_proportion_diff,
            )
        )

        if all(value is not None for value in (y_true_ref, y_pred_ref, y_true_cur, y_pred_cur)):
            findings.extend(
                _group_error_rate_drift_findings(
                    np.asarray(y_true_ref),
                    np.asarray(y_pred_ref),
                    np.asarray(y_true_cur),
                    np.asarray(y_pred_cur),
                    reference_sensitive_features,
                    current_sensitive_features,
                    max_group_error_rate_diff,
                )
            )

    return findings


def _feature_drift_findings(
    reference: pd.DataFrame,
    current: pd.DataFrame,
    ks_pvalue_threshold: float,
) -> list[AuditFinding]:
    numeric_cols = reference.select_dtypes(include=[np.number]).columns.intersection(
        current.select_dtypes(include=[np.number]).columns
    )
    drifted_cols = []
    drift_pvalues = {}

    for col in numeric_cols:
        ref_vals = reference[col].dropna().values
        cur_vals = current[col].dropna().values
        if len(ref_vals) < 10 or len(cur_vals) < 10:
            continue
        _, pvalue = stats.ks_2samp(ref_vals, cur_vals)
        drift_pvalues[col] = round(float(pvalue), 6)
        if pvalue < ks_pvalue_threshold:
            drifted_cols.append(col)

    if drifted_cols:
        return [
            AuditFinding(
                check_id="DRIFT-001",
                title="Feature distribution drift detected",
                severity=Severity.MEDIUM if len(drifted_cols) <= 3 else Severity.HIGH,
                description=(
                    f"{len(drifted_cols)} feature(s) show statistically significant distribution "
                    f"drift (KS test p < {ks_pvalue_threshold}): {', '.join(drifted_cols)}."
                ),
                evidence={
                    "drifted_columns": drifted_cols,
                    "ks_pvalues": {col: drift_pvalues[col] for col in drifted_cols},
                    "threshold": ks_pvalue_threshold,
                },
                recommendation=(
                    "Feature distribution has shifted between reference and current data. "
                    "Retrain or recalibrate if performance has degraded."
                ),
                category="Data Quality",
                remediation_effort=RemediationEffort.HIGH,
                standards_refs=_DRIFT_STANDARDS,
            )
        ]

    return [
        AuditFinding(
            check_id="DRIFT-001",
            title="No significant feature drift detected",
            severity=Severity.PASSED,
            description=f"All {len(numeric_cols)} numeric features pass the KS drift test.",
            evidence={"features_checked": len(numeric_cols)},
            recommendation="",
            category="Data Quality",
        )
    ]


def _prediction_drift_finding(
    y_pred_ref: np.ndarray,
    y_pred_cur: np.ndarray,
    ks_pvalue_threshold: float,
) -> AuditFinding:
    ref = np.asarray(y_pred_ref)
    cur = np.asarray(y_pred_cur)

    try:
        _, pvalue = stats.ks_2samp(ref.astype(float), cur.astype(float))
        drifted = pvalue < ks_pvalue_threshold
        evidence = {
            "method": "kolmogorov_smirnov",
            "ks_pvalue": round(float(pvalue), 6),
            "threshold": ks_pvalue_threshold,
        }
        description = (
            "Prediction distribution drift between reference and current datasets "
            f"(KS p={pvalue:.4f}, threshold={ks_pvalue_threshold})."
        )
    except (TypeError, ValueError):
        ref_distribution = _value_distribution(ref)
        cur_distribution = _value_distribution(cur)
        tv_distance = _total_variation_distance(ref_distribution, cur_distribution)
        drifted = tv_distance > ks_pvalue_threshold
        evidence = {
            "method": "total_variation_distance",
            "reference_distribution": ref_distribution,
            "current_distribution": cur_distribution,
            "total_variation_distance": round(tv_distance, 4),
            "threshold": ks_pvalue_threshold,
        }
        description = (
            "Prediction distribution drift between reference and current datasets "
            f"(total variation distance={tv_distance:.4f}, threshold={ks_pvalue_threshold})."
        )

    return AuditFinding(
        check_id="DRIFT-002",
        title="Prediction distribution drift",
        severity=Severity.MEDIUM if drifted else Severity.PASSED,
        description=description,
        evidence=evidence,
        recommendation=(
            "Prediction distribution has shifted. Monitor per-group error rates and "
            "investigate whether model performance has degraded."
            if drifted
            else ""
        ),
        category="Data Quality",
        remediation_effort=RemediationEffort.HIGH,
        standards_refs=_DRIFT_STANDARDS,
    )


def _subgroup_drift_findings(
    reference_sensitive_features: pd.DataFrame,
    current_sensitive_features: pd.DataFrame,
    max_subgroup_proportion_diff: float,
) -> list[AuditFinding]:
    findings = []
    for col in reference_sensitive_features.columns:
        ref_distribution = _value_distribution(reference_sensitive_features[col].values)
        cur_distribution = _value_distribution(current_sensitive_features[col].values)
        groups = sorted(set(ref_distribution) | set(cur_distribution))
        differences = {
            group: round(cur_distribution.get(group, 0.0) - ref_distribution.get(group, 0.0), 4)
            for group in groups
        }
        tv_distance = _total_variation_distance(ref_distribution, cur_distribution)
        severity = _diff_severity(tv_distance, max_subgroup_proportion_diff)

        findings.append(
            AuditFinding(
                check_id="DRIFT-003",
                title=f"Sensitive feature distribution drift for '{col}'",
                severity=severity,
                description=(
                    f"Sensitive feature distribution drift in '{col}' has total variation "
                    f"distance {tv_distance:.3f} (threshold: {max_subgroup_proportion_diff})."
                ),
                evidence={
                    "reference_distribution": ref_distribution,
                    "current_distribution": cur_distribution,
                    "proportion_differences": differences,
                    "total_variation_distance": round(tv_distance, 4),
                    "threshold": max_subgroup_proportion_diff,
                },
                recommendation=(
                    "The monitored population mix has shifted across sensitive groups. "
                    "Review group coverage and evaluate performance for the changed groups."
                    if severity != Severity.PASSED
                    else ""
                ),
                category="Fairness",
                affected_group=col,
                remediation_effort=RemediationEffort.MEDIUM,
                standards_refs=_DRIFT_STANDARDS,
            )
        )
    return findings


def _group_error_rate_drift_findings(
    y_true_ref: np.ndarray,
    y_pred_ref: np.ndarray,
    y_true_cur: np.ndarray,
    y_pred_cur: np.ndarray,
    reference_sensitive_features: pd.DataFrame,
    current_sensitive_features: pd.DataFrame,
    max_group_error_rate_diff: float,
) -> list[AuditFinding]:
    findings = []
    for col in reference_sensitive_features.columns:
        ref_rates = _error_rates_by_group(
            y_true_ref,
            y_pred_ref,
            reference_sensitive_features[col].values,
        )
        cur_rates = _error_rates_by_group(
            y_true_cur,
            y_pred_cur,
            current_sensitive_features[col].values,
        )
        common_groups = sorted(set(ref_rates) & set(cur_rates))
        differences = {
            group: round(cur_rates[group]["error_rate"] - ref_rates[group]["error_rate"], 4)
            for group in common_groups
        }
        max_diff = max((abs(diff) for diff in differences.values()), default=0.0)
        severity = _diff_severity(max_diff, max_group_error_rate_diff)

        findings.append(
            AuditFinding(
                check_id="DRIFT-004",
                title=f"Error-rate drift by group for '{col}'",
                severity=severity,
                description=(
                    f"Maximum classification error-rate change across monitored groups in '{col}' "
                    f"is {max_diff:.3f} (threshold: {max_group_error_rate_diff})."
                ),
                evidence={
                    "reference_error_rates": ref_rates,
                    "current_error_rates": cur_rates,
                    "error_rate_differences": differences,
                    "max_absolute_error_rate_difference": round(max_diff, 4),
                    "threshold": max_group_error_rate_diff,
                },
                recommendation=(
                    "Classification error rates changed for one or more sensitive groups. "
                    "Investigate recent data and labels, then retrain or recalibrate as needed."
                    if severity != Severity.PASSED
                    else ""
                ),
                category="Fairness",
                affected_group=col,
                remediation_effort=RemediationEffort.HIGH,
                standards_refs=_DRIFT_STANDARDS,
            )
        )
    return findings


def _error_rates_by_group(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    group_values: np.ndarray,
) -> dict[str, dict[str, float | int]]:
    rates = {}
    normalized_groups = _normalize_values(group_values)
    for group in sorted(set(normalized_groups)):
        mask = normalized_groups == group
        if mask.sum() < 5:
            continue
        rates[group] = {
            "n": int(mask.sum()),
            "error_rate": round(float(np.mean(y_true[mask] != y_pred[mask])), 4),
        }
    return rates


def _value_distribution(values: np.ndarray) -> dict[str, float]:
    normalized = _normalize_values(values)
    if len(normalized) == 0:
        return {}
    counts = pd.Series(normalized).value_counts(normalize=True, dropna=False)
    return {str(group): round(float(proportion), 4) for group, proportion in counts.items()}


def _normalize_values(values: np.ndarray) -> np.ndarray:
    return pd.Series(np.asarray(values)).fillna("<missing>").astype(str).values


def _total_variation_distance(
    reference_distribution: dict[str, float],
    current_distribution: dict[str, float],
) -> float:
    groups = set(reference_distribution) | set(current_distribution)
    return 0.5 * sum(
        abs(reference_distribution.get(group, 0.0) - current_distribution.get(group, 0.0))
        for group in groups
    )


def _diff_severity(diff: float, threshold: float) -> Severity:
    if diff > threshold * 2:
        return Severity.HIGH
    if diff > threshold:
        return Severity.MEDIUM
    return Severity.PASSED


def _resolve_reference_sensitive_features(
    sensitive_features: pd.DataFrame | None,
    reference_sensitive_features: pd.DataFrame | None,
) -> pd.DataFrame | None:
    if sensitive_features is not None and reference_sensitive_features is not None:
        raise ValueError(
            "Use either sensitive_features or reference_sensitive_features, not both."
        )
    return (
        reference_sensitive_features
        if reference_sensitive_features is not None
        else sensitive_features
    )


def _validate_inputs(
    reference: pd.DataFrame,
    current: pd.DataFrame,
    reference_sensitive_features: pd.DataFrame | None,
    current_sensitive_features: pd.DataFrame | None,
    y_true_ref: np.ndarray | None,
    y_pred_ref: np.ndarray | None,
    y_true_cur: np.ndarray | None,
    y_pred_cur: np.ndarray | None,
) -> None:
    if not isinstance(reference, pd.DataFrame) or not isinstance(current, pd.DataFrame):
        raise TypeError("reference and current must be pandas DataFrames.")

    if (reference_sensitive_features is None) != (current_sensitive_features is None):
        raise ValueError(
            "reference_sensitive_features and current_sensitive_features must be provided together."
        )

    if reference_sensitive_features is not None and current_sensitive_features is not None:
        if list(reference_sensitive_features.columns) != list(current_sensitive_features.columns):
            raise ValueError("Reference and current sensitive feature columns must match.")
        if len(reference_sensitive_features) != len(reference):
            raise ValueError("Reference sensitive features must have one row per reference sample.")
        if len(current_sensitive_features) != len(current):
            raise ValueError("Current sensitive features must have one row per current sample.")

    _validate_batch_array("y_true_ref", y_true_ref, len(reference))
    _validate_batch_array("y_pred_ref", y_pred_ref, len(reference))
    _validate_batch_array("y_true_cur", y_true_cur, len(current))
    _validate_batch_array("y_pred_cur", y_pred_cur, len(current))

    if (y_pred_ref is None) != (y_pred_cur is None):
        raise ValueError("y_pred_ref and y_pred_cur must be provided together.")

    labels_supplied = (y_true_ref is not None, y_true_cur is not None)
    if labels_supplied[0] != labels_supplied[1]:
        raise ValueError("y_true_ref and y_true_cur must be provided together.")
    if y_true_ref is not None and (y_pred_ref is None or y_pred_cur is None):
        raise ValueError("Predictions are required when true labels are provided.")


def _validate_batch_array(name: str, value: np.ndarray | None, expected_length: int) -> None:
    if value is not None and len(value) != expected_length:
        raise ValueError(f"{name} must have {expected_length} values.")


class DriftAudit(BaseAudit):
    """Standalone drift and batch-monitoring audit."""

    def __init__(
        self,
        reference: pd.DataFrame,
        current: pd.DataFrame,
        reference_sensitive_features: pd.DataFrame | None = None,
        current_sensitive_features: pd.DataFrame | None = None,
        y_true_ref=None,
        y_pred_ref=None,
        y_true_cur=None,
        y_pred_cur=None,
        project_name: str = "ML Drift Audit",
        metadata: dict | None = None,
        thresholds: dict | None = None,
        persist: bool = True,
    ):
        self.reference = reference
        self.current = current
        self.reference_sensitive_features = reference_sensitive_features
        self.current_sensitive_features = current_sensitive_features
        self.y_true_ref = np.asarray(y_true_ref) if y_true_ref is not None else None
        self.y_pred_ref = np.asarray(y_pred_ref) if y_pred_ref is not None else None
        self.y_true_cur = np.asarray(y_true_cur) if y_true_cur is not None else None
        self.y_pred_cur = np.asarray(y_pred_cur) if y_pred_cur is not None else None
        self.project_name = project_name
        self.metadata = metadata or {}
        self.thresholds = thresholds or {}
        self.persist = persist

    def run(self) -> AuditReport:
        findings = drift_findings(
            reference=self.reference,
            current=self.current,
            reference_sensitive_features=self.reference_sensitive_features,
            current_sensitive_features=self.current_sensitive_features,
            y_true_ref=self.y_true_ref,
            y_pred_ref=self.y_pred_ref,
            y_true_cur=self.y_true_cur,
            y_pred_cur=self.y_pred_cur,
            ks_pvalue_threshold=self.thresholds.get("ks_pvalue_threshold", 0.05),
            max_subgroup_proportion_diff=self.thresholds.get(
                "max_subgroup_proportion_diff",
                0.10,
            ),
            max_group_error_rate_diff=self.thresholds.get("max_group_error_rate_diff", 0.10),
        )
        metadata = {
            **self.metadata,
            "reference_samples": len(self.reference),
            "current_samples": len(self.current),
            "sensitive_features": (
                list(self.reference_sensitive_features.columns)
                if self.reference_sensitive_features is not None
                else []
            ),
            "monitored_at": datetime.now(timezone.utc).isoformat(),
        }
        report = AuditReport(
            project_name=self.project_name,
            audit_type="tabular_drift_monitoring",
            risk_matrix=compute_risk_matrix(findings),
            findings=findings,
            metadata=metadata,
        )

        if self.persist:
            save_run(report.to_dict())

        return report
