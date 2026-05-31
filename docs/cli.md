# CLI Reference

All commands are available via `rai-audit` (installed by `rai-audit-core` or `rai-audit-kit`).

## `rai-audit init`

Scaffold a starter `audit.yaml` config file.

```
rai-audit init [--project NAME] [--output PATH]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--project` | `my-project` | Project name |
| `--output` | `audit.yaml` | Output config path |

---

## `rai-audit report`

Render an HTML, Markdown, or JSON report from a saved audit JSON.

```
rai-audit report AUDIT_RUN.JSON [--format html|markdown|json] [--output PATH]
```

---

## `rai-audit gate`

CI/CD deployment gate. Exits `1` on failure, `0` on pass.

```
rai-audit gate AUDIT_RUN.JSON [--fail-on-critical] [--min-score N] [--output-json PATH]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--fail-on-critical` | `true` | Fail if any critical findings exist |
| `--min-score` | `null` | Minimum required heuristic score |
| `--output-json` | — | Write gate result to JSON |

---

## `rai-audit diff`

Compare two audit runs and show what changed.

```
rai-audit diff RUN_A.JSON RUN_B.JSON [--output-json PATH]
```

---

## `rai-audit history`

List past audit runs from the history directory.

```
rai-audit history [--directory PATH]
```

Default directory: `.rai-audit/history`

---

## `rai-audit export model-card`

Export an audit run as a Markdown model card (HuggingFace-compatible).

```
rai-audit export model-card AUDIT_RUN.JSON [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--output` | `<input>.model-card.md` | Output `.md` path |
| `--model-name` | project name | Display name |
| `--model-version` | — | Semantic version string |
| `--author` | — | Author / team name |
| `--license-id` | `MIT` | SPDX license identifier |
| `--language` | `en` | ISO 639-1 language code |

---

## `rai-audit ml run`

Run a classification or regression audit from the command line (installed by `rai-audit-ml`).

```
rai-audit ml run --data predictions.csv --target label [OPTIONS]
```

---

## `rai-audit llm run`

Audit captured LLM or RAG responses from a YAML test suite (installed by `rai-audit-llm`).

```
rai-audit llm run --suite packages/rai-audit-llm/examples/llm_audit_suite.yml [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--audit-type` | `llm` | Audit type: `llm`, `rag`, or `rag-security` |
| `--out` | `llm_audit_report.html` | Output report path |
| `--format` | `html` | Report format: `html`, `markdown`, or `json` |
| `--persist` | `true` | Save the run under `.rai-audit/history/` |

---

## `rai-audit agents run`

Audit a captured canonical agent execution trace (installed by `rai-audit-agents`).

```
rai-audit agents run --trace agent-trace.json [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--allowed-tools` | - | Comma-separated tool allowlist |
| `--out` | `agent_audit_report.html` | Output report path |
| `--format` | `html` | Report format: `html`, `markdown`, or `json` |
| `--persist` | `true` | Save the run under `.rai-audit/history/` |

---

## `rai-audit dl run`

Audit recorded image classification predictions from CSV (installed by `rai-audit-dl`).

```
rai-audit dl run --data predictions.csv --task image [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--task` | `image` | Audit type: `image`, `medical`, or `scientific` |
| `--transformed-prefix` | `transform_` | Prefix for transformed prediction columns |
| `--patient-id` | - | Patient ID column for medical imaging leakage checks |
| `--split` | - | Dataset split column for medical imaging leakage checks |
| `--site` | - | Collection-site column for medical imaging bias checks |
| `--format` | `html` | Report format: `html`, `markdown`, or `json` |
