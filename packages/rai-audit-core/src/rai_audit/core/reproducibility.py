from __future__ import annotations

import sys

from rai_audit.core.findings import AuditFinding, RemediationEffort, Severity


def check_reproducibility(metadata: dict) -> list[AuditFinding]:
    """
    Check metadata for reproducibility signals.

    Expected metadata keys (all optional but flagged if missing):
      random_seed, library_versions, data_hash, model_hash, python_version
    """
    findings: list[AuditFinding] = []

    if metadata.get("random_seed") is None:
        findings.append(
            AuditFinding(
                check_id="REPRO-001",
                title="Random seed not recorded",
                severity=Severity.MEDIUM,
                description=(
                    "No random seed was provided in the audit metadata. "
                    "Results may differ across runs."
                ),
                evidence={},
                recommendation="Set and record a random seed (e.g. numpy.random.seed(42)) before evaluation.",
                category="Reproducibility",
                remediation_effort=RemediationEffort.LOW,
                standards_refs=["ISO-42001-8.4"],
            )
        )
    else:
        findings.append(
            AuditFinding(
                check_id="REPRO-001",
                title="Random seed recorded",
                severity=Severity.PASSED,
                description=f"Random seed is set: {metadata['random_seed']}",
                evidence={"random_seed": metadata["random_seed"]},
                recommendation="",
                category="Reproducibility",
            )
        )

    if not metadata.get("library_versions"):
        findings.append(
            AuditFinding(
                check_id="REPRO-002",
                title="Library versions not recorded",
                severity=Severity.LOW,
                description="No library version information found in audit metadata.",
                evidence={"python_version": sys.version},
                recommendation=(
                    "Capture library versions using pip freeze or "
                    "importlib.metadata and include them in audit metadata."
                ),
                category="Reproducibility",
                remediation_effort=RemediationEffort.LOW,
                standards_refs=["ISO-42001-8.4"],
            )
        )
    else:
        findings.append(
            AuditFinding(
                check_id="REPRO-002",
                title="Library versions recorded",
                severity=Severity.PASSED,
                description="Library version information is present.",
                evidence={"library_versions": metadata["library_versions"]},
                recommendation="",
                category="Reproducibility",
            )
        )

    if not metadata.get("data_hash"):
        findings.append(
            AuditFinding(
                check_id="REPRO-003",
                title="Data hash not recorded",
                severity=Severity.MEDIUM,
                description="No hash of the evaluation dataset was provided. Dataset identity cannot be verified.",
                evidence={},
                recommendation=(
                    "Compute a hash of the evaluation data "
                    "(e.g. hashlib.md5(df.to_csv().encode()).hexdigest()) and record it."
                ),
                category="Reproducibility",
                remediation_effort=RemediationEffort.LOW,
                standards_refs=["ISO-42001-8.4"],
            )
        )
    else:
        findings.append(
            AuditFinding(
                check_id="REPRO-003",
                title="Data hash recorded",
                severity=Severity.PASSED,
                description="Evaluation dataset hash is present.",
                evidence={"data_hash": metadata["data_hash"]},
                recommendation="",
                category="Reproducibility",
            )
        )

    return findings
