# RAI Audit Kit — Status

## Completed

### Infrastructure
- [x] `uv` workspaces monorepo
- [x] 6 packages scaffolded with independent `pyproject.toml`
- [x] Implicit namespace packages (`rai_audit.*`)
- [x] 7 GitHub Actions workflows (per-package test + publish)
- [x] PyPI trusted publishing via OIDC (no stored token)
- [x] 40+ passing tests (core + ml + smoke tests for all skeleton packages)

### `rai-audit-core` v0.1.0
- [x] `AuditFinding`, `CategoryRisk`, `AuditReport` dataclasses
- [x] Per-category risk matrix (no single aggregate score)
- [x] HTML, Markdown, JSON report rendering
- [x] Audit run history + `diff_runs()`
- [x] PII column detection
- [x] Reproducibility checks (seed, library versions, data hash)
- [x] Standards registry (EU AI Act, NIST AI RMF, ISO/IEC, OWASP)
- [x] CLI: `init`, `report`, `gate`, `diff`, `history` (Typer)
- [x] `gate_check()` with exit code 0/1 + JSON output for CI

### `rai-audit-ml` v0.1.0
- [x] `ClassificationAudit` — full audit runner
- [x] `RegressionAudit` — full audit runner
- [x] `FairnessAudit` — standalone fairness-only audit
- [x] Fairness: demographic parity, equal opportunity, FNR gap
- [x] Data quality: missing values, duplicates, imbalance, leakage detection
- [x] Robustness: bootstrap CI, Brier score calibration
- [x] Explainability: feature importance + optional SHAP
- [x] Drift: KS test per feature + prediction drift
- [x] CLI: `rai-audit ml run`

### `rai-audit-kit` v0.1.0 (meta-package)
- [x] Installs core + ml
- [x] Plugin-loading unified CLI entry point

### Skeletons (scaffolded, not implemented)
- [x] `rai-audit-dl` — placeholder + CLI stub
- [x] `rai-audit-llm` — placeholder + CLI stub
- [x] `rai-audit-agents` — placeholder + CLI stub

### Phase 2 — Reports and CI/CD Polish
- [x] Richer HTML report (SVG risk chart, group metric tables)
- [x] Model card export (`rai-audit export model-card`)
- [x] GitHub Actions example for CI/CD gate (`examples/ci-gate.yml`)
- [x] Docs site (MkDocs — `mkdocs.yml` + `docs/`)

### Phase 3 — ML Drift and Monitoring
- [x] Subgroup drift (sensitive feature distribution drift)
- [x] Error-rate drift per group
- [x] Batch monitoring examples
- [x] MLOps integration examples

---

## Pending

### Phase 4 — `rai-audit-llm`
- [ ] YAML test suite loader
- [ ] Prompt injection checks
- [ ] Unsafe output / toxicity checks
- [ ] RAG faithfulness + citation checks (LLM-as-judge required)
- [ ] RAG security checks
- [ ] OWASP LLM Top 10 mapping

### Phase 5 — `rai-audit-dl`
- [ ] Image classification audit
- [ ] Robustness under transformations
- [ ] Grad-CAM (PyTorch hooks + TF GradientTape)
- [ ] Medical imaging audit (patient leakage, site bias)
- [ ] Scientific AI examples

### Phase 6 — `rai-audit-agents`
- [ ] Canonical trace schema (OpenTelemetry GenAI aligned)
- [ ] Framework adapters (LangGraph, OpenAI Agents SDK, AutoGen)
- [ ] Tool-use audit
- [ ] Memory audit
- [ ] Permission audit
- [ ] Prompt injection via tools / retrieval / email / webpage
