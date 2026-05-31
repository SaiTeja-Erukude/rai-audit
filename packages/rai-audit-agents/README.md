# rai-audit-agents

Agentic AI audits for tool use, memory, permissions, and prompt injection delivered
through tools, retrieval, email, or webpages.

Checks also cover instruction poisoning persisted into agent memory and bounded
tool-execution budgets. Agent findings include OWASP Agentic Top 10 2026 mappings
where applicable.

## Trace Schema

The canonical versioned JSON schema follows the current OpenTelemetry GenAI operation vocabulary.
New traces should set `"schema_version": "1.0"`; unversioned traces are migrated
during loading:
`invoke_agent`, `invoke_workflow`, `execute_tool`, and `retrieval`. Events emit aligned
attributes such as `gen_ai.agent.name`, `gen_ai.tool.name`, and
`gen_ai.data_source.id`.

OpenTelemetry currently marks its GenAI agent conventions as Development, so the
schema preserves a general `attributes` mapping alongside stable audit fields.

## CLI

```bash
rai-audit agents run \
  --trace packages/rai-audit-agents/examples/customer_support_trace.json \
  --allowed-tools lookup_order \
  --format html
```

## Python API

```python
from rai_audit.agents import AgentAudit, load_trace

trace = load_trace("packages/rai-audit-agents/examples/customer_support_trace.json")
report = AgentAudit(trace, allowed_tools=["lookup_order"], persist=False).run()
```

## Framework Adapters

Adapters normalize captured records without requiring framework installations:

```python
from rai_audit.agents import (
    adapt_autogen_messages,
    adapt_langgraph_events,
    adapt_openai_agents_trace,
)
```

References:

- [OpenTelemetry GenAI agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/)
- [OpenTelemetry GenAI spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/)
- [OpenAI Agents SDK tracing](https://openai.github.io/openai-agents-python/tracing/)
