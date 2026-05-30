# RAI Audit Kit

**RAI** = **Responsible AI**. A Python package suite for evidence-grade audits of responsible, secure, and trustworthy AI systems.

Run fairness, data quality, robustness, and compliance checks on ML models. Export HTML, Markdown, or JSON reports and gate CI pipelines on risk thresholds.

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

See [`examples/ml_fairness_audit/example.py`](examples/ml_fairness_audit/example.py) for a full fairness audit walkthrough.

## Packages

| Package | Purpose |
|---------|---------|
| `rai-audit-core` | Audit engine, findings, reports, history, CI gates |
| `rai-audit-ml` | Tabular ML — fairness, drift, data quality, robustness |
| `rai-audit-dl` | Deep learning audits *(scaffold)* |
| `rai-audit-llm` | LLM and RAG audits *(scaffold)* |
| `rai-audit-agents` | Agentic AI audits *(scaffold)* |
| `rai-audit-kit` | Meta-package — installs core + ml, unified CLI |

## Development

```bash
pip install uv
uv sync
uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for monorepo layout and release workflow.
