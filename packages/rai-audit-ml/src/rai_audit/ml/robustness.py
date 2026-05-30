from __future__ import annotations

import numpy as np
from sklearn.metrics import accuracy_score, brier_score_loss

from rai_audit.core.findings import AuditFinding, RemediationEffort, Severity


def robustness_findings_classification(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    n_bootstrap: int = 200,
    confidence_interval: float = 0.95,
    max_calibration_error: float = 0.10,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    rng = np.random.default_rng(42)

    # Bootstrap confidence interval for accuracy
    n = len(y_true)
    bootstrap_accs = []
    for _ in range(n_bootstrap):
        idx = rng.integers(0, n, size=n)
        bootstrap_accs.append(accuracy_score(y_true[idx], y_pred[idx]))

    alpha = 1 - confidence_interval
    lower = float(np.percentile(bootstrap_accs, alpha / 2 * 100))
    upper = float(np.percentile(bootstrap_accs, (1 - alpha / 2) * 100))
    ci_width = upper - lower
    base_acc = accuracy_score(y_true, y_pred)

    severity = Severity.MEDIUM if ci_width > 0.10 else Severity.PASSED
    findings.append(
        AuditFinding(
            check_id="ROB-CLS-001",
            title=f"Accuracy {int(confidence_interval*100)}% bootstrap confidence interval",
            severity=severity,
            description=(
                f"Bootstrap CI for accuracy: [{lower:.4f}, {upper:.4f}] "
                f"(width={ci_width:.4f}, n={n_bootstrap} resamples)."
            ),
            evidence={
                "accuracy": round(base_acc, 4),
                "ci_lower": round(lower, 4),
                "ci_upper": round(upper, 4),
                "ci_width": round(ci_width, 4),
                "n_bootstrap": n_bootstrap,
            },
            recommendation=(
                "A wide confidence interval suggests the model performance estimate is unreliable. "
                "Increase evaluation set size or use k-fold cross-validation."
            ) if ci_width > 0.10 else "",
            category="Robustness",
            remediation_effort=RemediationEffort.MEDIUM,
            standards_refs=["NIST-AI-RMF-MEASURE-2.6"],
        )
    )

    # Confidence calibration (Brier score)
    if y_prob.ndim == 2:
        probs_pos = y_prob[:, 1]
    else:
        probs_pos = y_prob

    brier = float(brier_score_loss(y_true, probs_pos))
    severity = Severity.MEDIUM if brier > max_calibration_error else Severity.PASSED

    findings.append(
        AuditFinding(
            check_id="ROB-CLS-002",
            title="Confidence calibration (Brier score)",
            severity=severity,
            description=(
                f"Brier score: {brier:.4f} (lower is better; threshold: {max_calibration_error}). "
                "A high Brier score indicates the model's predicted probabilities are unreliable."
            ),
            evidence={"brier_score": round(brier, 4), "threshold": max_calibration_error},
            recommendation=(
                "Apply Platt scaling or isotonic regression to calibrate probabilities."
            ) if brier > max_calibration_error else "",
            category="Robustness",
            remediation_effort=RemediationEffort.MEDIUM,
            standards_refs=["NIST-AI-RMF-MEASURE-2.6"],
        )
    )

    return findings
