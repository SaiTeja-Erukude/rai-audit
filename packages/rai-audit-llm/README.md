# rai-audit-llm

LLM and RAG audits for prompt injection, unsafe output, toxicity, faithfulness,
citations, retrieval quality, and retrieval security.

## CLI

Audit captured responses from a YAML suite:

```bash
rai-audit llm run --suite packages/rai-audit-llm/examples/llm_audit_suite.yml --format html
```

New suites should set `schema_version: "1.0"`. Existing unversioned suites and
the legacy `tests` key are migrated during loading.

Use `--audit-type rag` to run only RAG checks or `--audit-type rag-security` to
scan only retrieval security cases.

## Python API

```python
from rai_audit.llm import LLMAudit, load_test_suite

suite = load_test_suite("packages/rai-audit-llm/examples/llm_audit_suite.yml")
report = LLMAudit(suite, persist=False).run()
```

For live evaluation, pass `responder=lambda case: ...`. RAG faithfulness checks
require an LLM-as-judge verdict: provide `judge_result` in captured YAML or pass
`faithfulness_judge=lambda case, response: {"score": 0.9, "reasoning": "..."}`.

RAG suites can set `relevant_sources` and `retrieval_k` for recall@k and reciprocal
rank checks. Retrieved contexts support `document_id`, `tenant_id`, `updated_at`,
and `poisoned` metadata for provenance, tenant-isolation, freshness, and poisoned
document checks.

`OpenAIResponder` and `AnthropicResponder` capture latency, token usage, and
optional caller-supplied pricing. Suites can also run `structured_output`,
`pii_redaction`, `prompt_leakage`, `refusal_overblocking`, `rate_limit`,
`latency`, and `token_budget` checks. Use `rubric_judge` for configurable
LLM-as-judge scoring and `summarize_reports` for repeated-run benchmarks.

All findings include OWASP LLM Top 10 2025 references where applicable.
