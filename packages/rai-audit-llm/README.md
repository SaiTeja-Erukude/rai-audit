# rai-audit-llm

LLM and RAG audits for prompt injection, unsafe output, toxicity, faithfulness,
citations, and retrieval security.

## CLI

Audit captured responses from a YAML suite:

```bash
rai-audit llm run --suite packages/rai-audit-llm/examples/llm_audit_suite.yml --format html
```

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

All findings include OWASP LLM Top 10 2025 references where applicable.
