# Getting Started

## Install

```bash
pip install rai-audit-ml
```

## Run a Classification Audit

```python
import numpy as np
import pandas as pd
from rai_audit.ml import ClassificationAudit

report = ClassificationAudit(
    y_true=y_true,
    y_pred=y_pred,
    y_prob=y_prob,                                    # optional, for calibration checks
    sensitive_features=pd.DataFrame({"gender": g}),  # optional, for fairness checks
    data=X,                                           # optional, for data quality checks
    project_name="Loan Approval Model",
).run()

# Outputs
report.to_html("audit.html")          # rich HTML report with charts
report.to_json("audit-run.json")      # save for gate / diff / history
report.to_markdown("audit.md")
report.to_model_card("model-card.md") # HuggingFace-compatible
```

## CI/CD Gate

```bash
rai-audit gate audit-run.json --fail-on-critical
```

Exits `1` on any critical finding, `0` on pass. Use in GitHub Actions:

```yaml
- name: RAI Audit gate
  run: rai-audit gate audit-run.json --fail-on-critical
```

See `examples/ci-gate.yml` for a full example workflow.

## Export Model Card

```bash
rai-audit export model-card audit-run.json \
  --model-name "Loan Model v2" \
  --model-version "2.0.0" \
  --author "ML Team"
```
