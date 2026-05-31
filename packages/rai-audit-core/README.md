# rai-audit-core

Shared audit findings, evidence manifests, history, and reporting APIs.

Configured runs can include `standards-coverage` in `audit.report_formats` to
write a standalone JSON evidence-coverage artifact. History exports are available
from the CLI:

```text
rai-audit export standards-coverage audit-run.json
rai-audit export history-dashboard --directory .rai-audit/history
rai-audit export eu-post-market --directory .rai-audit/history
```

Standards coverage and EU AI Act-oriented post-market reports summarize recorded
evidence. They do not make a compliance claim.

Configs, audit reports, evidence manifests, agent traces, and LLM suites use
versioned JSON Schemas. Existing unversioned inputs are migrated to schema version
`1.0` during loading.
