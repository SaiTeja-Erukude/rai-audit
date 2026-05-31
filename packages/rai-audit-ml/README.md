# rai-audit-ml

Fairness, robustness, data quality, and production drift audits for tabular ML
models.

```python
from rai_audit.ml import ClassificationAudit, DriftAudit, RegressionAudit
```

`DriftAudit` compares a reference window with a current batch. It checks numeric
feature distributions, prediction distributions, sensitive-feature subgroup
composition, and classification error-rate changes per sensitive group.

See [`examples/ml_drift_monitoring/batch_monitor.py`](examples/ml_drift_monitoring/batch_monitor.py)
and [`examples/mlops_integrations/`](examples/mlops_integrations/) for monitoring examples.
