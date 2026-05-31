"""Smoke tests for rai-audit-dl (Phase 5 scaffold)."""
import rai_audit.dl as dl_pkg


def test_dl_importable():
    assert hasattr(dl_pkg, "__all__")


def test_dl_all_empty_until_phase5():
    assert isinstance(dl_pkg.__all__, list)
