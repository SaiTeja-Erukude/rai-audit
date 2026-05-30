import numpy as np
import pandas as pd
import pytest

from rai_audit.core.findings import RiskLevel, Severity
from rai_audit.ml.classification import ClassificationAudit


def _make_data(n: int = 300, seed: int = 0):
    rng = np.random.default_rng(seed)
    y_true = rng.integers(0, 2, size=n)
    noise = rng.integers(0, 2, size=n)
    y_pred = np.where(rng.random(n) > 0.1, y_true, noise)
    y_prob = np.clip(rng.random(n), 0.05, 0.95)
    group = np.array(["A"] * (n // 2) + ["B"] * (n // 2))
    sens = pd.DataFrame({"group": group})
    df = pd.DataFrame({"feat1": rng.normal(size=n), "feat2": rng.normal(size=n)})
    return y_true, y_pred, y_prob, sens, df


def test_classification_audit_basic(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    y_true, y_pred, y_prob, sens, df = _make_data()
    audit = ClassificationAudit(
        y_true=y_true,
        y_pred=y_pred,
        y_prob=y_prob,
        sensitive_features=sens,
        data=df,
    )
    report = audit.run()
    assert report.audit_type == "tabular_classification"
    assert len(report.findings) > 0
    assert len(report.risk_matrix) > 0


def test_classification_audit_to_html(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    y_true, y_pred, y_prob, sens, df = _make_data()
    audit = ClassificationAudit(y_true=y_true, y_pred=y_pred, y_prob=y_prob, sensitive_features=sens)
    report = audit.run()
    out = tmp_path / "report.html"
    report.to_html(str(out))
    content = out.read_text()
    assert "<!DOCTYPE html>" in content


def test_classification_audit_to_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import json
    y_true, y_pred, _, _, _ = _make_data()
    audit = ClassificationAudit(y_true=y_true, y_pred=y_pred)
    report = audit.run()
    out = tmp_path / "report.json"
    report.to_json(str(out))
    data = json.loads(out.read_text())
    assert "findings" in data
    assert "risk_matrix" in data


def test_classification_audit_persist(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    y_true, y_pred, _, _, _ = _make_data()
    audit = ClassificationAudit(y_true=y_true, y_pred=y_pred, persist=True)
    audit.run()
    history_dir = tmp_path / ".rai-audit" / "history"
    assert history_dir.exists()
    assert len(list(history_dir.glob("*.json"))) == 1


def test_classification_audit_no_sensitive(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    y_true, y_pred, _, _, _ = _make_data()
    audit = ClassificationAudit(y_true=y_true, y_pred=y_pred)
    report = audit.run()
    assert report is not None
    perf = next(f for f in report.findings if f.check_id == "CLS-PERF-001")
    assert perf.severity == Severity.INFO
