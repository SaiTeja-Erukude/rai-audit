from __future__ import annotations

import numpy as np
import pandas as pd

from rai_audit.core.findings import AuditFinding, RemediationEffort, Severity


def data_quality_findings(
    df: pd.DataFrame,
    y_true: np.ndarray | None = None,
    max_missing_pct: float = 0.05,
    max_constant_pct: float = 0.99,
    min_class_balance: float = 0.10,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    n_rows, n_cols = df.shape

    # Missing values
    missing = df.isnull().mean()
    high_missing = missing[missing > max_missing_pct]
    if not high_missing.empty:
        findings.append(
            AuditFinding(
                check_id="DQ-001",
                title="High missing value rate in features",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(high_missing)} column(s) have more than "
                    f"{max_missing_pct*100:.0f}% missing values."
                ),
                evidence={
                    "columns": {col: round(pct, 4) for col, pct in high_missing.items()},
                    "threshold": max_missing_pct,
                },
                recommendation="Investigate missing value causes. Impute or drop columns as appropriate.",
                category="Data Quality",
                remediation_effort=RemediationEffort.MEDIUM,
                standards_refs=["EU-AI-ACT-ART-10"],
            )
        )
    else:
        findings.append(
            AuditFinding(
                check_id="DQ-001",
                title="Missing values within acceptable range",
                severity=Severity.PASSED,
                description=f"All columns have less than {max_missing_pct*100:.0f}% missing values.",
                evidence={"max_missing_pct": round(float(missing.max()), 4)},
                recommendation="",
                category="Data Quality",
            )
        )

    # Duplicate rows
    dup_count = int(df.duplicated().sum())
    dup_pct = dup_count / n_rows if n_rows > 0 else 0
    if dup_pct > 0.01:
        findings.append(
            AuditFinding(
                check_id="DQ-002",
                title="Duplicate rows detected",
                severity=Severity.MEDIUM if dup_pct > 0.05 else Severity.LOW,
                description=f"{dup_count} duplicate rows found ({dup_pct*100:.1f}% of dataset).",
                evidence={"duplicate_count": dup_count, "duplicate_pct": round(dup_pct, 4)},
                recommendation="Review and remove duplicates before training or evaluation.",
                category="Data Quality",
                remediation_effort=RemediationEffort.LOW,
            )
        )
    else:
        findings.append(
            AuditFinding(
                check_id="DQ-002",
                title="No significant duplicate rows",
                severity=Severity.PASSED,
                description=f"{dup_count} duplicate rows ({dup_pct*100:.2f}%).",
                evidence={"duplicate_count": dup_count},
                recommendation="",
                category="Data Quality",
            )
        )

    # Constant / near-constant columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    near_constant = []
    for col in numeric_cols:
        top_pct = df[col].value_counts(normalize=True).iloc[0]
        if top_pct > max_constant_pct:
            near_constant.append((col, round(top_pct, 4)))

    if near_constant:
        findings.append(
            AuditFinding(
                check_id="DQ-003",
                title="Near-constant columns detected",
                severity=Severity.LOW,
                description=(
                    f"{len(near_constant)} column(s) have a single value in more than "
                    f"{max_constant_pct*100:.0f}% of rows. These are unlikely to be predictive."
                ),
                evidence={"columns": {col: pct for col, pct in near_constant}},
                recommendation="Consider removing near-constant columns unless they carry semantic meaning.",
                category="Data Quality",
                remediation_effort=RemediationEffort.LOW,
            )
        )
    else:
        findings.append(
            AuditFinding(
                check_id="DQ-003",
                title="No near-constant columns detected",
                severity=Severity.PASSED,
                description="All numeric columns have adequate variance.",
                evidence={},
                recommendation="",
                category="Data Quality",
            )
        )

    # Class imbalance (classification only)
    if y_true is not None:
        classes, counts = np.unique(y_true, return_counts=True)
        class_pcts = counts / counts.sum()
        min_pct = float(class_pcts.min())

        if min_pct < min_class_balance:
            minority_class = classes[class_pcts.argmin()]
            findings.append(
                AuditFinding(
                    check_id="DQ-004",
                    title="Class imbalance detected",
                    severity=Severity.MEDIUM if min_pct < 0.05 else Severity.LOW,
                    description=(
                        f"Minority class '{minority_class}' represents only "
                        f"{min_pct*100:.1f}% of samples (threshold: {min_class_balance*100:.0f}%)."
                    ),
                    evidence={
                        "class_distribution": {str(c): round(p, 4) for c, p in zip(classes, class_pcts)},
                        "minority_class": str(minority_class),
                        "minority_pct": round(min_pct, 4),
                    },
                    recommendation=(
                        "Imbalanced classes can lead to biased metrics. "
                        "Consider resampling, class weights, or stratified evaluation."
                    ),
                    category="Data Quality",
                    remediation_effort=RemediationEffort.MEDIUM,
                    standards_refs=["EU-AI-ACT-ART-10"],
                )
            )
        else:
            findings.append(
                AuditFinding(
                    check_id="DQ-004",
                    title="Class balance within acceptable range",
                    severity=Severity.PASSED,
                    description=f"Minority class is {min_pct*100:.1f}% of samples.",
                    evidence={"minority_pct": round(min_pct, 4)},
                    recommendation="",
                    category="Data Quality",
                )
            )

    # Feature correlation (potential leakage warning)
    if y_true is not None and len(numeric_cols) > 0:
        high_corr_cols = []
        for col in numeric_cols:
            try:
                corr = abs(float(np.corrcoef(df[col].fillna(0).values, y_true)[0, 1]))
                if corr > 0.95:
                    high_corr_cols.append((col, round(corr, 4)))
            except Exception:
                pass

        if high_corr_cols:
            findings.append(
                AuditFinding(
                    check_id="DQ-005",
                    title="Potential target leakage detected",
                    severity=Severity.HIGH,
                    description=(
                        f"{len(high_corr_cols)} feature(s) have suspiciously high correlation "
                        "with the target (>0.95). This may indicate data leakage."
                    ),
                    evidence={"high_correlation_features": {col: corr for col, corr in high_corr_cols}},
                    recommendation=(
                        "Investigate whether these features could be derived from or contain "
                        "the target variable. Remove them if leakage is confirmed."
                    ),
                    category="Data Quality",
                    remediation_effort=RemediationEffort.HIGH,
                    standards_refs=["EU-AI-ACT-ART-10"],
                )
            )

    return findings
