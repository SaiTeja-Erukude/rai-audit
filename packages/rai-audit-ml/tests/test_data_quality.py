import numpy as np
import pandas as pd
import pytest

from rai_audit.core.findings import Severity
from rai_audit.ml.data_quality import data_quality_findings


def test_missing_values_flagged():
    df = pd.DataFrame({"a": [1, None, None, None, None, None, 1, 1, 1, 1]})
    findings = data_quality_findings(df)
    f = next(f for f in findings if f.check_id == "DQ-001")
    assert f.severity == Severity.MEDIUM


def test_no_missing_passes():
    df = pd.DataFrame({"a": [1, 2, 3, 4, 5]})
    findings = data_quality_findings(df)
    f = next(f for f in findings if f.check_id == "DQ-001")
    assert f.severity == Severity.PASSED


def test_duplicate_rows_flagged():
    df = pd.DataFrame({"a": [1] * 10, "b": [2] * 10})
    dup = pd.concat([df, df], ignore_index=True)
    findings = data_quality_findings(dup)
    f = next(f for f in findings if f.check_id == "DQ-002")
    assert f.severity in (Severity.LOW, Severity.MEDIUM)


def test_class_imbalance_flagged():
    y = np.array([0] * 95 + [1] * 5)
    df = pd.DataFrame({"feat": np.random.randn(100)})
    findings = data_quality_findings(df, y_true=y)
    f = next(f for f in findings if f.check_id == "DQ-004")
    assert f.severity in (Severity.LOW, Severity.MEDIUM)


def test_leakage_warning():
    n = 100
    y = np.array([0] * 50 + [1] * 50)
    df = pd.DataFrame({
        "leaked": y.astype(float) + np.random.normal(0, 0.001, n),
        "normal": np.random.randn(n),
    })
    findings = data_quality_findings(df, y_true=y)
    leakage = next((f for f in findings if f.check_id == "DQ-005"), None)
    assert leakage is not None
    assert leakage.severity == Severity.HIGH
