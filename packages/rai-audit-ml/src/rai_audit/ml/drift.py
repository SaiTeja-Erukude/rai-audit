from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import stats

from rai_audit.core.findings import AuditFinding, RemediationEffort, Severity

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
) -> list[AuditFinding]:
    """
    Detect data drift between a reference and current dataset.
    Uses the Kolmogorov-Smirnov test for numeric features.
    """
    findings: list[AuditFinding] = []
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
        stat, pvalue = stats.ks_2samp(ref_vals, cur_vals)
        drift_pvalues[col] = round(float(pvalue), 6)
        if pvalue < ks_pvalue_threshold:
            drifted_cols.append(col)

    if drifted_cols:
        findings.append(
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
        )
    else:
        findings.append(
            AuditFinding(
                check_id="DRIFT-001",
                title="No significant feature drift detected",
                severity=Severity.PASSED,
                description=f"All {len(numeric_cols)} numeric features pass the KS drift test.",
                evidence={"features_checked": len(numeric_cols)},
                recommendation="",
                category="Data Quality",
            )
        )

    # Subgroup drift on sensitive features
    if sensitive_features is not None and y_pred_ref is not None and y_pred_cur is not None:
        for col in sensitive_features.columns:
            ref_rates = {}
            cur_rates = {}
            ref_groups = sensitive_features.loc[reference.index, col].astype(str) if col in sensitive_features.columns else None
            # simplified: compare prediction distribution across datasets
            _, pvalue = stats.ks_2samp(y_pred_ref.astype(float), y_pred_cur.astype(float))
            severity = Severity.MEDIUM if pvalue < ks_pvalue_threshold else Severity.PASSED
            findings.append(
                AuditFinding(
                    check_id="DRIFT-002",
                    title=f"Prediction distribution drift",
                    severity=severity,
                    description=(
                        f"Prediction distribution drift between reference and current datasets "
                        f"(KS p={pvalue:.4f}, threshold={ks_pvalue_threshold})."
                    ),
                    evidence={"ks_pvalue": round(float(pvalue), 6), "threshold": ks_pvalue_threshold},
                    recommendation=(
                        "Prediction distribution has shifted. "
                        "Monitor per-group error rates for responsible AI drift."
                    ) if pvalue < ks_pvalue_threshold else "",
                    category="Data Quality",
                    remediation_effort=RemediationEffort.HIGH,
                    standards_refs=_DRIFT_STANDARDS,
                )
            )
            break  # one overall prediction drift check

    return findings
