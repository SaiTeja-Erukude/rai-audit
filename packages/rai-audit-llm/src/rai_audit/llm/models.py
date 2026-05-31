from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from rai_audit.core.schemas import SCHEMA_VERSION

SUPPORTED_CHECKS = frozenset(
    {
        "prompt_injection",
        "unsafe_output",
        "toxicity",
        "rag_faithfulness",
        "rag_citation",
        "rag_security",
    }
)


@dataclass(frozen=True)
class RAGContext:
    source: str
    content: str
    trusted: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "content": self.content,
            "trusted": self.trusted,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class LLMTestCase:
    id: str
    prompt: str
    checks: tuple[str, ...]
    response: str | None = None
    expected_refusal: bool = True
    forbidden_terms: tuple[str, ...] = ()
    contexts: tuple[RAGContext, ...] = ()
    expected_citations: tuple[str, ...] = ()
    judge_result: Mapping[str, Any] | bool | float | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "prompt": self.prompt,
            "checks": list(self.checks),
            "response": self.response,
            "expected_refusal": self.expected_refusal,
            "forbidden_terms": list(self.forbidden_terms),
            "contexts": [context.to_dict() for context in self.contexts],
            "expected_citations": list(self.expected_citations),
            "judge_result": self.judge_result,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class LLMTestSuite:
    name: str
    cases: tuple[LLMTestCase, ...]
    project_name: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "name": self.name,
            "project_name": self.project_name,
            "cases": [case.to_dict() for case in self.cases],
            "metadata": dict(self.metadata),
        }


ResponseProvider = Callable[[LLMTestCase], str]
FaithfulnessJudge = Callable[[LLMTestCase, str], Mapping[str, Any] | bool | float]
