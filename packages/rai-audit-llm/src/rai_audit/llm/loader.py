from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from rai_audit.llm.models import SUPPORTED_CHECKS, LLMTestCase, LLMTestSuite, RAGContext

_TYPE_CHECKS = {
    "prompt_injection": ("prompt_injection",),
    "unsafe_output": ("unsafe_output", "toxicity"),
    "rag": ("rag_faithfulness", "rag_citation", "rag_security"),
    "rag_faithfulness": ("rag_faithfulness",),
    "rag_citation": ("rag_citation",),
    "rag_security": ("rag_security",),
}


class SuiteValidationError(ValueError):
    """Raised when an LLM YAML suite does not match the supported schema."""


def load_test_suite(path: str | Path) -> LLMTestSuite:
    """Load and validate an LLM audit suite from YAML."""
    suite_path = Path(path)
    try:
        raw = yaml.safe_load(suite_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SuiteValidationError(f"Could not read suite {suite_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SuiteValidationError(f"Invalid YAML in {suite_path}: {exc}") from exc

    root = _mapping(raw, "suite")
    name = _required_text(root, "name", "suite")
    project_name = _optional_text(root.get("project_name"), "suite.project_name")
    defaults = _mapping(root.get("defaults", {}), "suite.defaults")
    default_forbidden = _text_tuple(
        defaults.get("forbidden_terms", ()), "suite.defaults.forbidden_terms"
    )

    raw_cases = root.get("cases", root.get("tests"))
    if not isinstance(raw_cases, list) or not raw_cases:
        raise SuiteValidationError("suite.cases must be a non-empty list")

    cases: list[LLMTestCase] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw_cases):
        label = f"suite.cases[{index}]"
        case = _mapping(item, label)
        case_id = _required_text(case, "id", label)
        if case_id in seen_ids:
            raise SuiteValidationError(f"Duplicate test case id: {case_id}")
        seen_ids.add(case_id)

        checks = _checks(case, label)
        contexts = _contexts(case.get("contexts", ()), label)
        if "rag_faithfulness" in checks and not contexts:
            raise SuiteValidationError(f"{label}.contexts is required for rag_faithfulness")

        cases.append(
            LLMTestCase(
                id=case_id,
                prompt=_required_text(case, "prompt", label),
                checks=checks,
                response=_optional_text(case.get("response"), f"{label}.response"),
                expected_refusal=_bool(
                    case.get("expected_refusal", True), f"{label}.expected_refusal"
                ),
                forbidden_terms=default_forbidden
                + _text_tuple(case.get("forbidden_terms", ()), f"{label}.forbidden_terms"),
                contexts=contexts,
                expected_citations=_text_tuple(
                    case.get("expected_citations", ()), f"{label}.expected_citations"
                ),
                judge_result=case.get("judge_result"),
                metadata=_mapping(case.get("metadata", {}), f"{label}.metadata"),
            )
        )

    return LLMTestSuite(
        name=name,
        project_name=project_name,
        cases=tuple(cases),
        metadata=_mapping(root.get("metadata", {}), "suite.metadata"),
    )


def _checks(case: Mapping[str, Any], label: str) -> tuple[str, ...]:
    raw_checks = case.get("checks")
    if raw_checks is None:
        case_type = _required_text(case, "type", label)
        if case_type not in _TYPE_CHECKS:
            supported = ", ".join(sorted(_TYPE_CHECKS))
            raise SuiteValidationError(f"{label}.type must be one of: {supported}")
        return _TYPE_CHECKS[case_type]

    checks = _text_tuple(raw_checks, f"{label}.checks")
    unknown = sorted(set(checks) - SUPPORTED_CHECKS)
    if unknown:
        raise SuiteValidationError(
            f"{label}.checks contains unsupported checks: {', '.join(unknown)}"
        )
    if not checks:
        raise SuiteValidationError(f"{label}.checks must not be empty")
    return checks


def _contexts(raw: Any, label: str) -> tuple[RAGContext, ...]:
    if not isinstance(raw, (list, tuple)):
        raise SuiteValidationError(f"{label}.contexts must be a list")
    contexts: list[RAGContext] = []
    for index, item in enumerate(raw):
        context_label = f"{label}.contexts[{index}]"
        if isinstance(item, str):
            contexts.append(RAGContext(source=f"context-{index + 1}", content=item))
            continue
        context = _mapping(item, context_label)
        contexts.append(
            RAGContext(
                source=_required_text(context, "source", context_label),
                content=_required_text(context, "content", context_label),
                trusted=_bool(context.get("trusted", False), f"{context_label}.trusted"),
                metadata=_mapping(context.get("metadata", {}), f"{context_label}.metadata"),
            )
        )
    return tuple(contexts)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SuiteValidationError(f"{label} must be a mapping")
    return value


def _required_text(value: Mapping[str, Any], key: str, label: str) -> str:
    text = _optional_text(value.get(key), f"{label}.{key}")
    if text is None:
        raise SuiteValidationError(f"{label}.{key} is required")
    return text


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise SuiteValidationError(f"{label} must be a non-empty string")
    return value.strip()


def _text_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise SuiteValidationError(f"{label} must be a list")
    result: list[str] = []
    for item in value:
        text = _optional_text(item, label)
        if text is None:
            raise SuiteValidationError(f"{label} entries must be non-empty strings")
        result.append(text)
    return tuple(result)


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise SuiteValidationError(f"{label} must be a boolean")
    return value
