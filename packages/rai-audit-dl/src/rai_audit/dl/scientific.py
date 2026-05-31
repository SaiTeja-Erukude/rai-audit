from __future__ import annotations

from rai_audit.dl.image import ImageClassificationAudit


class ScientificAIAudit(ImageClassificationAudit):
    """Image audit with scientific domain metadata for reproducible evaluations."""

    audit_type = "scientific_image_classification"

    def __init__(self, *args, scientific_domain: str = "scientific imaging", **kwargs):
        self.scientific_domain = scientific_domain
        super().__init__(*args, **kwargs)

    def _additional_metadata(self) -> dict:
        return {"scientific_domain": self.scientific_domain}
