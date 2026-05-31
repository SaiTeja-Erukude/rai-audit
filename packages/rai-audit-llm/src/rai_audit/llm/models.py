from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

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


@dataclass(frozen=True)
class LLMTestSuite:
    name: str
    cases: tuple[LLMTestCase, ...]
    project_name: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


ResponseProvider = Callable[[LLMTestCase], str]
FaithfulnessJudge = Callable[[LLMTestCase, str], Mapping[str, Any] | bool | float]
