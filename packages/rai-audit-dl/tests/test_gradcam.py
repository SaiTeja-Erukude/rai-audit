import importlib

import numpy as np
import pytest
from rai_audit.dl.gradcam import _normalize_heatmaps, pytorch_grad_cam, tensorflow_grad_cam


def test_normalize_heatmaps_scales_each_sample():
    heatmaps = np.array([[[0.0, 2.0]], [[0.0, 0.0]]])
    normalized = _normalize_heatmaps(heatmaps)
    np.testing.assert_array_equal(normalized, np.array([[[0.0, 1.0]], [[0.0, 0.0]]]))


@pytest.mark.parametrize(
    ("backend", "function"),
    [("torch", pytorch_grad_cam), ("tensorflow", tensorflow_grad_cam)],
)
def test_gradcam_backends_explain_missing_optional_dependency(monkeypatch, backend, function):
    original_import = importlib.import_module

    def missing_framework(name):
        if name == backend:
            raise ModuleNotFoundError(name)
        return original_import(name)

    monkeypatch.setattr(importlib, "import_module", missing_framework)
    with pytest.raises(ImportError, match=f"rai-audit-dl\\[{backend}\\]"):
        function(None, None, None)
