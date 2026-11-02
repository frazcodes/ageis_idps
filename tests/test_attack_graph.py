"""Unit tests for InteractiveAttackGraphWidget."""

from __future__ import annotations

import os
import pytest

from PySide6.QtWidgets import QApplication

from aegis_desktop.app import create_application
from aegis_desktop.widgets.attack_graph import InteractiveAttackGraphWidget

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def test_attack_graph_widget_initialization(app: QApplication) -> None:
    """Attack graph widget initializes with 5-stage default topology."""
    widget = InteractiveAttackGraphWidget()
    assert len(widget._nodes) == 5
    assert len(widget._edges) == 4

    # Verify key kill-chain nodes exist
    assert "attacker" in widget._nodes
    assert "port" in widget._nodes
    assert "detection" in widget._nodes
    assert "host" in widget._nodes
    assert "process" in widget._nodes

    # Test dynamic loading from incident
    widget.load_from_incident(
        incident_id="INC-TEST-99",
        attacker_ip="10.0.0.55",
        target_port="3389",
        rule_name="RDP BRUTE FORCE",
        host_name="CORP-DC-01",
        process_name="lsass.exe",
        severity="CRITICAL",
    )

    assert widget._nodes["attacker"].sublabel == "10.0.0.55"
    assert "3389" in widget._nodes["port"].sublabel
    assert widget._nodes["detection"].sublabel == "RDP BRUTE FORCE"

    # Test animation tick advances particle pulses
    p0 = widget._edges[0].particles[0]
    widget._on_tick()
    p1 = widget._edges[0].particles[0]
    assert p1 != p0
