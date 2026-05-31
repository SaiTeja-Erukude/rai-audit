# Contributing to RAI Audit Kit

**RAI** = **Responsible AI**.

## Repository Structure

This is a `uv` workspaces monorepo. Each package under `packages/` is an independently
published PyPI package that shares the `rai_audit` Python namespace.

```
packages/
  rai-audit-core/      # shared engine — every other package depends on this
  rai-audit-ml/        # tabular ML audits
  rai-audit-dl/        # deep learning audits
  rai-audit-llm/       # LLM and RAG audits
  rai-audit-agents/    # agentic AI audits
  rai-audit-kit/       # meta-package (installs all of the above)
```

## Setup

```bash
pip install uv
uv sync
```

Or install individual packages in editable mode:

```bash
pip install -e packages/rai-audit-core -e packages/rai-audit-ml
```

## Running Tests

```bash
# All packages
pytest packages/rai-audit-core/tests packages/rai-audit-ml/tests -v

# Single package
pytest packages/rai-audit-core/tests -v
```

## CI Workflows

Each package has its own GitHub Actions workflow:

| Workflow | Triggers on changes to |
|----------|------------------------|
| `test-core.yml` | `packages/rai-audit-core/**` |
| `test-ml.yml` | `packages/rai-audit-ml/**` or `packages/rai-audit-core/**` |
| `test-dl.yml` | `packages/rai-audit-dl/**` or `packages/rai-audit-core/**` |
| `test-llm.yml` | `packages/rai-audit-llm/**` or `packages/rai-audit-core/**` |
| `test-agents.yml` | `packages/rai-audit-agents/**` or `packages/rai-audit-core/**` |
| `test-kit.yml` | Any package + smoke-tests the CLI |
| `publish.yml` | Tag push only (see below) |

Note: changing `rai-audit-core` triggers the CI for all downstream packages
(`test-ml`, `test-dl`, etc.) because they all depend on core. This is intentional —
a breaking change in core should catch failures in all consumers.

## Releasing a Package

Each package is released independently via a git tag. The tag format is:

```
rai-audit-<package>-v<semver>
```

Examples:

```bash
# Bump the version in pyproject.toml first
# packages/rai-audit-ml/pyproject.toml: version = "0.2.0"

git add packages/rai-audit-ml/pyproject.toml
git commit -m "chore(rai-audit-ml): bump to 0.2.0"
git tag rai-audit-ml-v0.2.0
git push origin main
git push origin rai-audit-ml-v0.2.0
```

The `publish.yml` workflow detects the tag, verifies that the tag version matches
`pyproject.toml`, builds the wheel, and publishes to PyPI via trusted publishing (OIDC).
No PyPI token is stored in GitHub secrets.

Push release tags individually. GitHub does not emit tag push events when more than three tags are pushed at once.

## Version Policy

- Packages have independent version numbers.
- `rai-audit-core` follows semver strictly — a breaking change bumps the minor version.
- Downstream packages (`rai-audit-ml`, etc.) pin `rai-audit-core>=X.Y` in their
  dependencies. When core makes a breaking change, all dependents must be updated and released in the same PR.
- `rai-audit-kit` tracks the latest version of each module package.

## Adding a New Check

1. Choose the right package (`rai-audit-ml`, `rai-audit-dl`, etc.).
2. Add the check function to the relevant module (e.g. `fairness.py`).
3. Return a list of `AuditFinding` objects using severity levels from `rai_audit.core.findings`.
4. Register standards refs where applicable (`standards_refs=["EU-AI-ACT-ART-10"]`).
5. Add a test in `packages/<package>/tests/`.
6. The check will appear automatically in reports when the parent audit runs.

## Namespace Packages

All packages share the `rai_audit` namespace via implicit namespace packages (PEP 420).
There is intentionally **no** `__init__.py` at the `rai_audit/` root level inside any
package. Do not add one — it will break namespace package discovery.

Verify isolation by installing only one package and confirming other namespaces raise
a helpful `ImportError`:

```python
# With only rai-audit-ml installed:
from rai_audit.ml import FairnessAudit   # works
from rai_audit.llm import RAGAudit       # ImportError: Install rai-audit-llm
```
