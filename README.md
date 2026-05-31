# RAI Audit Kit

**RAI** = **Responsible AI**. A Python package suite for evidence-grade audits of responsible, secure, and trustworthy AI systems.

Run fairness, data quality, robustness, compliance, LLM safety, and RAG security checks. Export HTML, Markdown, or JSON reports and gate CI pipelines on risk thresholds.

**Author:** Sai Teja Erukude · **License:** MIT

## Install

```bash
pip install rai-audit-kit          # core + tabular ML
pip install "rai-audit-kit[all]"   # all modules (dl, llm, agents)
```

## Quick start

```bash
rai-audit ml run --help
```

```python
from rai_audit.ml import ClassificationAudit

report = ClassificationAudit(
    y_true=y_true,
    y_pred=y_pred,
    sensitive_features=sensitive_df,
).run()

report.to_html("audit_report.html")
```

See [`packages/rai-audit-ml/examples/ml_fairness_audit/example.py`](packages/rai-audit-ml/examples/ml_fairness_audit/example.py) for a full fairness audit walkthrough.
See [`packages/rai-audit-ml/examples/ml_drift_monitoring/batch_monitor.py`](packages/rai-audit-ml/examples/ml_drift_monitoring/batch_monitor.py)
for batch drift monitoring and [`packages/rai-audit-ml/examples/mlops_integrations/`](packages/rai-audit-ml/examples/mlops_integrations/)
for MLflow and Airflow templates.
See [`packages/rai-audit-llm/examples/llm_audit_suite.yml`](packages/rai-audit-llm/examples/llm_audit_suite.yml) for a captured-response
LLM and RAG audit suite.

## Packages

| Package | Purpose |
|---------|---------|
| `rai-audit-core` | Audit engine, findings, reports, history, CI gates |
| `rai-audit-ml` | Tabular ML — fairness, drift, data quality, robustness |
| `rai-audit-dl` | Deep learning audits *(scaffold)* |
| `rai-audit-llm` | LLM and RAG safety, faithfulness, citation, and security audits |
| `rai-audit-agents` | Agentic AI audits *(scaffold)* |
| `rai-audit-kit` | Meta-package — installs core + ml, unified CLI |

## Development

```bash
pip install uv
uv sync
uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for monorepo layout and release workflow.
