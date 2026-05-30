import numpy as np
import pandas as pd
import pytest

from rai_audit.core.findings import Severity
from rai_audit.ml.fairness import (
    FairnessAudit,
    compute_group_metrics,
    fairness_findings_classification,
)


def _make_biased_data(n: int = 400, seed: int = 0):
    """Generate data where group B has higher false negative rate."""
    rng = np.random.default_rng(seed)
    group = np.array(["A"] * (n // 2) + ["B"] * (n // 2))
    y_true = rng.integers(0, 2, size=n)

    # Group A: ~10% FNR, Group B: ~40% FNR
    y_pred = y_true.copy()
    group_b_positives = np.where((group == "B") & (y_true == 1))[0]
    flip_idx = rng.choice(group_b_positives, size=int(len(group_b_positives) * 0.4), replace=False)
    y_pred[flip_idx] = 0

    return y_true, y_pred, pd.DataFrame({"group": group})


def test_compute_group_metrics():
    y_true, y_pred, sens = _make_biased_data()
    metrics = compute_group_metrics(y_true, y_pred, "group", sens["group"].values)
    assert len(metrics) == 2
    vals = {m.group_val: m for m in metrics}
    assert "A" in vals and "B" in vals
    assert vals["B"].false_negative_rate > vals["A"].false_negative_rate


def test_fairness_findings_biased():
    y_true, y_pred, sens = _make_biased_data()
    findings = fairness_findings_classification(y_true, y_pred, sens)
    fnr_finding = next(f for f in findings if f.check_id == "FAIR-CLS-003")
    assert fnr_finding.severity in (Severity.MEDIUM, Severity.HIGH)


def test_fairness_findings_unbiased():
    rng = np.random.default_rng(42)
    n = 400
    y_true = rng.integers(0, 2, n)
    y_pred = y_true.copy()
    group = np.array(["A"] * (n // 2) + ["B"] * (n // 2))
    sens = pd.DataFrame({"group": group})
    findings = fairness_findings_classification(y_true, y_pred, sens)
    dp_finding = next(f for f in findings if f.check_id == "FAIR-CLS-001")
    assert dp_finding.severity == Severity.PASSED


def test_fairness_audit_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    y_true, y_pred, sens = _make_biased_data()
    audit = FairnessAudit(y_true=y_true, y_pred=y_pred, sensitive_features=sens)
    report = audit.run()
    assert report.project_name == "Fairness Audit"
    assert len(report.findings) > 0
    assert len(report.risk_matrix) > 0
