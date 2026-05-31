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
