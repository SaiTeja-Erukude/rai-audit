from __future__ import annotations

STANDARDS_REGISTRY: dict[str, str] = {
    # EU AI Act
    "EU-AI-ACT-ART-9": "EU AI Act Article 9 — Risk management system",
    "EU-AI-ACT-ART-10": "EU AI Act Article 10 — Data and data governance",
    "EU-AI-ACT-ART-13": "EU AI Act Article 13 — Transparency and provision of information",
    "EU-AI-ACT-ART-14": "EU AI Act Article 14 — Human oversight",
    "EU-AI-ACT-ART-15": "EU AI Act Article 15 — Accuracy, robustness and cybersecurity",
    # NIST AI RMF
    "NIST-AI-RMF-GOVERN-1": "NIST AI RMF GOVERN 1 — Policies and processes for AI risk",
    "NIST-AI-RMF-MAP-1": "NIST AI RMF MAP 1 — Context is established for AI risk assessment",
    "NIST-AI-RMF-MEASURE-2.5": "NIST AI RMF MEASURE 2.5 — AI system fairness and bias",
    "NIST-AI-RMF-MEASURE-2.6": "NIST AI RMF MEASURE 2.6 — AI system robustness",
    "NIST-AI-RMF-MEASURE-2.7": "NIST AI RMF MEASURE 2.7 — AI system security",
    "NIST-AI-RMF-MANAGE-1": "NIST AI RMF MANAGE 1 — AI risk treatment",
    # ISO/IEC
    "ISO-42001-6.1": "ISO/IEC 42001 Clause 6.1 — AI risk assessment",
    "ISO-42001-8.4": "ISO/IEC 42001 Clause 8.4 — AI system impact assessment",
    "ISO-23894-6": "ISO/IEC 23894 Clause 6 — AI risk management process",
    # OWASP
    "OWASP-LLM-01": "OWASP LLM Top 10 2025 #1 — Prompt Injection",
    "OWASP-LLM-02": "OWASP LLM Top 10 2025 #2 — Sensitive Information Disclosure",
    "OWASP-LLM-03": "OWASP LLM Top 10 2025 #3 — Supply Chain",
    "OWASP-LLM-04": "OWASP LLM Top 10 2025 #4 — Data and Model Poisoning",
    "OWASP-LLM-05": "OWASP LLM Top 10 2025 #5 — Improper Output Handling",
    "OWASP-LLM-06": "OWASP LLM Top 10 2025 #6 — Excessive Agency",
    "OWASP-LLM-07": "OWASP LLM Top 10 2025 #7 — System Prompt Leakage",
    "OWASP-LLM-08": "OWASP LLM Top 10 2025 #8 — Vector and Embedding Weaknesses",
    "OWASP-LLM-09": "OWASP LLM Top 10 2025 #9 — Misinformation",
    "OWASP-LLM-10": "OWASP LLM Top 10 2025 #10 — Unbounded Consumption",
    "OWASP-ML-01": "OWASP ML Security Top 10 #1 — Input Manipulation Attack",
    "OWASP-ML-05": "OWASP ML Security Top 10 #5 — Model Inversion Attack",
}


def describe_ref(ref: str) -> str:
    return STANDARDS_REGISTRY.get(ref, ref)


def describe_refs(refs: list[str]) -> list[str]:
    return [describe_ref(r) for r in refs]
