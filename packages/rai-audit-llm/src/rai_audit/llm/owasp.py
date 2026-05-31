from __future__ import annotations

OWASP_LLM_TOP_10_2025: dict[str, str] = {
    "OWASP-LLM-01": "Prompt Injection",
    "OWASP-LLM-02": "Sensitive Information Disclosure",
    "OWASP-LLM-03": "Supply Chain",
    "OWASP-LLM-04": "Data and Model Poisoning",
    "OWASP-LLM-05": "Improper Output Handling",
    "OWASP-LLM-06": "Excessive Agency",
    "OWASP-LLM-07": "System Prompt Leakage",
    "OWASP-LLM-08": "Vector and Embedding Weaknesses",
    "OWASP-LLM-09": "Misinformation",
    "OWASP-LLM-10": "Unbounded Consumption",
}

CHECK_OWASP_REFS: dict[str, list[str]] = {
    "prompt_injection": ["OWASP-LLM-01", "OWASP-LLM-07"],
    "unsafe_output": ["OWASP-LLM-02", "OWASP-LLM-05"],
    "toxicity": ["OWASP-LLM-05"],
    "rag_faithfulness": ["OWASP-LLM-09"],
    "rag_citation": ["OWASP-LLM-08", "OWASP-LLM-09"],
    "rag_security": ["OWASP-LLM-01", "OWASP-LLM-04", "OWASP-LLM-08"],
}


def owasp_refs_for_check(check: str) -> list[str]:
    """Return OWASP LLM Top 10 2025 references associated with a check."""
    return list(CHECK_OWASP_REFS.get(check, ()))
