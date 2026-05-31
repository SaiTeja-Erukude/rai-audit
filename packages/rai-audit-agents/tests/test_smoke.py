"""Smoke tests for rai-audit-agents (Phase 6 scaffold)."""
import rai_audit.agents as agents_pkg


def test_agents_importable():
    assert hasattr(agents_pkg, "__all__")


def test_agents_all_empty_until_phase6():
    assert isinstance(agents_pkg.__all__, list)
