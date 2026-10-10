"""Unit tests for the Audio Alert Service in Aegis IDPS."""

from __future__ import annotations

import time

from aegis_desktop.services.audio_alert import AudioAlertService, get_audio_alert_service


def test_audio_alert_singleton() -> None:
    s1 = get_audio_alert_service()
    s2 = get_audio_alert_service()
    assert s1 is s2


def test_audio_alert_finds_default_sound() -> None:
    service = AudioAlertService()
    sound_file = service.find_sound_file()
    assert sound_file is not None
    assert sound_file.exists()
    assert sound_file.stat().st_size > 0


def test_audio_alert_mute_unmute() -> None:
    service = AudioAlertService()
    service.set_muted(False)
    assert not service.is_muted

    new_state = service.toggle_mute()
    assert new_state is True
    assert service.is_muted

    # When muted, play_alarm returns False
    res = service.play_alarm(duration_seconds=1.0)
    assert res is False

    service.toggle_mute()
    assert not service.is_muted


def test_audio_alert_play_and_stop() -> None:
    service = AudioAlertService()
    service.set_muted(False)

    # Play for 0.4 seconds
    played = service.play_alarm(duration_seconds=0.4)
    assert played is True
    assert service.is_playing is True

    # Immediate stop
    service.stop_alarm()
    assert not service.is_playing


def test_audio_alert_auto_stop() -> None:
    import sys

    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    service = AudioAlertService()
    service.set_muted(False)

    played = service.play_alarm(duration_seconds=0.2)
    assert played is True
    time.sleep(0.3)
    app.processEvents()
    assert not service.is_playing
