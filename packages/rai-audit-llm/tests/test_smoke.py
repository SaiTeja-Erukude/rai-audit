"""Smoke tests for rai-audit-llm (Phase 4 scaffold)."""
import rai_audit.llm as llm_pkg


def test_llm_importable():
    assert hasattr(llm_pkg, "__all__")


def test_llm_all_empty_until_phase4():
    assert isinstance(llm_pkg.__all__, list)
