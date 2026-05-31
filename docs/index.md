# RAI Audit Kit

**Evidence-grade audits for responsible, secure, and trustworthy AI systems.**

RAI Audit Kit is a Python toolkit that helps developers, researchers, and AI teams audit AI systems for fairness, robustness, security, transparency, and deployment readiness.

## Install

```bash
pip install rai-audit-kit          # everything
pip install rai-audit-ml           # ML audits only
pip install rai-audit-core         # engine and reports only
```

## Quick Example

```python
from rai_audit.ml import ClassificationAudit
import pandas as pd

report = ClassificationAudit(
    y_true=y_true,
    y_pred=y_pred,
    sensitive_features=pd.DataFrame({"gender": gender_col}),
    project_name="My Classifier",
).run()

report.to_html("audit-report.html")
report.to_model_card("model-card.md")
```

## Package Suite

| Package | Description | Status |
|---------|-------------|--------|
| `rai-audit-core` | Shared engine, findings, reports, CLI | ✅ v0.1.0 |
| `rai-audit-ml` | Tabular ML audits (classification, regression) | ✅ v0.1.0 |
| `rai-audit-kit` | Meta-package: installs core + ml | ✅ v0.1.0 |
| `rai-audit-dl` | Image, medical imaging, and scientific AI audits | ✅ Available |
| `rai-audit-llm` | LLM and RAG audits | ✅ Available |
| `rai-audit-agents` | Agent tool-use, memory, permission, and injection audits | ✅ Available |
