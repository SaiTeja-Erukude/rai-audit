from __future__ import annotations

import numpy as np
from rai_audit.core.findings import AuditFinding, RemediationEffort, Severity
from rai_audit.dl.image import ImageClassificationAudit, _validated_labels

_MEDICAL_STANDARDS = ["EU-AI-ACT-ART-10", "NIST-AI-RMF-MEASURE-2.5"]


def patient_leakage_finding(patient_ids, splits) -> AuditFinding:
    """Detect patients represented in more than one dataset split."""
    patients = np.asarray(patient_ids).astype(str)
    split_names = np.asarray(splits).astype(str)
    if patients.ndim != 1 or split_names.ndim != 1 or len(patients) != len(split_names):
        raise ValueError("patient_ids and splits must be one-dimensional arrays of equal length")
    patient_splits: dict[str, set[str]] = {}
    for patient, split in zip(patients, split_names):
        patient_splits.setdefault(patient, set()).add(split)
    leaked = {
        patient: sorted(values) for patient, values in patient_splits.items() if len(values) > 1
    }
    return AuditFinding(
        check_id="MED-LEAK-001",
        title="Patient leakage across dataset splits" if leaked else "No patient split leakage",
        severity=Severity.CRITICAL if leaked else Severity.PASSED,
        description=(
            f"{len(leaked)} patient(s) appear in multiple dataset splits."
            if leaked
            else "Each patient appears in only one dataset split."
        ),
        evidence={"leaked_patients": leaked, "leaked_patient_count": len(leaked)},
        recommendation=(
            "Split medical imaging datasets at the patient level before training or evaluation."
            if leaked
            else ""
        ),
        category="Data Leakage",
        remediation_effort=RemediationEffort.HIGH,
        standards_refs=_MEDICAL_STANDARDS,
    )


def site_bias_finding(
    y_true,
    y_pred,
    sites,
    max_site_accuracy_diff: float = 0.10,
    min_site_samples: int = 5,
) -> AuditFinding:
    """Compare classification accuracy across medical imaging collection sites."""
    truth, predictions = _validated_labels(y_true, y_pred)
    site_values = np.asarray(sites).astype(str)
    if site_values.ndim != 1 or len(site_values) != len(truth):
        raise ValueError("sites must contain one value per prediction")
    accuracy_by_site = {}
    samples_by_site = {}
    for site in np.unique(site_values):
        mask = site_values == site
        samples_by_site[site] = int(mask.sum())
        if mask.sum() >= min_site_samples:
            accuracy_by_site[site] = round(float(np.mean(truth[mask] == predictions[mask])), 4)
    accuracy_diff = (
        max(accuracy_by_site.values()) - min(accuracy_by_site.values())
        if len(accuracy_by_site) >= 2
        else 0.0
    )
    if accuracy_diff > max_site_accuracy_diff * 2:
        severity = Severity.HIGH
    elif accuracy_diff > max_site_accuracy_diff:
        severity = Severity.MEDIUM
    else:
        severity = Severity.PASSED
    return AuditFinding(
        check_id="MED-SITE-001",
        title=(
            "Medical imaging site bias"
            if severity != Severity.PASSED
            else "Site accuracy parity"
        ),
        severity=severity,
        description=(
            f"Maximum accuracy difference across eligible sites is {accuracy_diff:.3f} "
            f"(threshold: {max_site_accuracy_diff})."
        ),
        evidence={
            "accuracy_by_site": accuracy_by_site,
            "samples_by_site": samples_by_site,
            "max_accuracy_difference": round(accuracy_diff, 4),
            "threshold": max_site_accuracy_diff,
            "min_site_samples": min_site_samples,
        },
        recommendation=(
            "Review acquisition protocols and evaluate domain adaptation for underperforming sites."
            if severity != Severity.PASSED
            else ""
        ),
        category="Fairness",
        remediation_effort=RemediationEffort.HIGH,
        standards_refs=_MEDICAL_STANDARDS,
    )


class MedicalImagingAudit(ImageClassificationAudit):
    """Image classification audit with patient leakage and site-bias checks."""

    audit_type = "medical_image_classification"

    def __init__(self, *args, patient_ids=None, splits=None, sites=None, **kwargs):
        self.patient_ids = patient_ids
        self.splits = splits
        self.sites = sites
        super().__init__(*args, **kwargs)

    def _additional_findings(self) -> list[AuditFinding]:
        findings = []
        if (self.patient_ids is None) != (self.splits is None):
            raise ValueError("patient_ids and splits must be provided together")
        if self.patient_ids is not None:
            if len(self.patient_ids) != len(self.y_true):
                raise ValueError("patient_ids and splits must contain one value per prediction")
            findings.append(patient_leakage_finding(self.patient_ids, self.splits))
        if self.sites is not None:
            findings.append(
                site_bias_finding(
                    self.y_true,
                    self.y_pred,
                    self.sites,
                    max_site_accuracy_diff=self.thresholds.get(
                        "max_site_accuracy_diff",
                        0.10,
                    ),
                    min_site_samples=self.thresholds.get("min_site_samples", 5),
                )
            )
        return findings

    def _additional_metadata(self) -> dict:
        return {
            "patient_leakage_checked": self.patient_ids is not None,
            "site_bias_checked": self.sites is not None,
        }
