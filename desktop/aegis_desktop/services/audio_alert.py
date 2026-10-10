"""Audio alert service for Aegis IDPS.

Plays acoustic alarm tones for high-severity cyber attacks and threat
simulation playbooks. Supports user-supplied audio files (.wav or .mp3)
placed in the ``assets/sounds`` folder, with an automated fallback tone.
"""

from __future__ import annotations

import contextlib
import logging
import sys
import threading
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, QUrl, Signal

logger = logging.getLogger(__name__)

# Preferred sound file paths to check (in order of priority)
_SOUNDS_DIR = Path(__file__).resolve().parent.parent / "assets" / "sounds"
_CUSTOM_WAV = _SOUNDS_DIR / "alert.wav"
_ALT_WAV = _SOUNDS_DIR / "alarm.wav"
_DEFAULT_WAV = _SOUNDS_DIR / "default_alert.wav"
_CUSTOM_MP3 = _SOUNDS_DIR / "alert.mp3"


class _QtAudioBridge(QObject):
    """Qt-thread bridge to safely manipulate QMediaPlayer on the GUI event loop."""

    request_play = Signal(str)
    request_stop = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._player: object | None = None
        self._output: object | None = None
        self.request_play.connect(self._on_play)
        self.request_stop.connect(self._on_stop)

    def _ensure_player(self) -> object:
        if self._player is None:
            from PySide6.QtMultimedia import QAudioOutput, QMediaPlayer

            self._player = QMediaPlayer(self)
            self._output = QAudioOutput(self)
            player = self._player
            if hasattr(player, "setAudioOutput"):
                player.setAudioOutput(self._output)
            if hasattr(self._output, "setVolume"):
                self._output.setVolume(0.9)
        return self._player

    def _on_play(self, file_path: str) -> None:
        try:
            from PySide6.QtMultimedia import QMediaPlayer

            player = self._ensure_player()
            if hasattr(player, "setSource"):
                player.setSource(QUrl.fromLocalFile(file_path))
            if hasattr(player, "setLoops"):
                infinite_val = getattr(getattr(QMediaPlayer, "Loops", None), "Infinite", -1)
                player.setLoops(infinite_val)
            if hasattr(player, "play"):
                player.play()
        except Exception as exc:
            logger.warning("Qt player playback failed: %s", exc)

    def _on_stop(self) -> None:
        if self._player is not None:
            with contextlib.suppress(Exception):
                if hasattr(self._player, "stop"):
                    self._player.stop()


class AudioAlertService(QObject):
    """Manages audio alerts when cyber attacks or critical threats occur.

    Features:
    - Non-blocking asynchronous playback (uses Windows winsound or QtMultimedia).
    - Configurable auto-stop duration (default 15 seconds, customizable 10-20s).
    - User file override: Drop your file at ``assets/sounds/alert.wav`` or ``alert.mp3``.
    - Built-in fallback tone if no user file is present.
    - Global Mute toggle and instant Stop.
    - Fully thread-safe timer handling for Qt Multimedia integration.
    """

    alarm_started = Signal(str)
    alarm_stopped = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._muted: bool = False
        self._is_playing: bool = False
        self._timer: QTimer | None = None
        self._lock = threading.Lock()
        self._bridge: _QtAudioBridge | None = None

    def _ensure_bridge(self) -> _QtAudioBridge:
        if self._bridge is None:
            self._bridge = _QtAudioBridge(self)
        return self._bridge

    @property
    def sounds_directory(self) -> Path:
        """The absolute path to the directory where alert sounds should be placed."""
        return _SOUNDS_DIR

    @property
    def is_muted(self) -> bool:
        """Whether audio alerts are currently muted."""
        return self._muted

    @property
    def is_playing(self) -> bool:
        """Whether an alarm tone is currently sounding."""
        return self._is_playing

    def set_muted(self, muted: bool) -> None:
        """Mute or unmute the audio alarm."""
        self._muted = muted
        if muted and self._is_playing:
            self.stop_alarm()

    def toggle_mute(self) -> bool:
        """Toggle mute state and return the new state."""
        self.set_muted(not self._muted)
        return self._muted

    def find_sound_file(self) -> Path | None:
        """Return the highest priority sound file that exists on disk."""
        candidates = [_CUSTOM_WAV, _ALT_WAV, _CUSTOM_MP3, _DEFAULT_WAV]
        for p in candidates:
            if p.is_file() and p.stat().st_size > 0:
                return p
        return None

    def play_alarm(self, duration_seconds: float = 15.0) -> bool:
        """Play an attack alarm tone asynchronously for the specified duration.

        Args:
            duration_seconds: Duration before auto-stopping (default: 15s).

        Returns:
            True if playback was initiated, False if muted or already playing.
        """
        if self._muted:
            logger.debug("Audio alert skipped: muted by operator")
            return False

        with self._lock:
            # Stop any ongoing auto-stop timer cleanly
            if self._timer is not None:
                with contextlib.suppress(Exception):
                    self._timer.stop()
                self._timer = None

            sound_file = self.find_sound_file()
            self._is_playing = True

            try:
                self._start_playback(sound_file)
            except Exception as exc:
                logger.warning("Failed to start audio alarm: %s", exc)
                self._is_playing = False
                return False

            # Auto-stop timer on the Qt main loop via QTimer.singleShot
            ms = int(duration_seconds * 1000)
            QTimer.singleShot(ms, self.stop_alarm)
            self.alarm_started.emit(sound_file.name if sound_file else "alert")
            return True

    def stop_alarm(self) -> None:
        """Immediately silence any currently playing alarm."""
        with self._lock:
            if self._timer is not None:
                with contextlib.suppress(Exception):
                    self._timer.stop()
                self._timer = None

            self._stop_playback()
            self._is_playing = False
            self.alarm_stopped.emit()

    # -- Internal playback backends ----------------------------------------

    def _start_playback(self, sound_path: Path | None) -> None:
        """Start async sound using winsound or QtMultimedia."""
        is_win_wav = (
            sound_path is not None
            and sound_path.suffix.lower() == ".wav"
            and sys.platform == "win32"
        )
        if is_win_wav and sound_path is not None:
            import winsound

            flags = (
                winsound.SND_FILENAME
                | winsound.SND_ASYNC
                | winsound.SND_LOOP
            )
            winsound.PlaySound(str(sound_path), flags)
            return

        # MP3 or non-Windows playback via Qt event-loop bridge
        if sound_path is not None and sound_path.exists():
            bridge = self._ensure_bridge()
            bridge.request_play.emit(str(sound_path))
            return

        # Ultimate fallback: Windows console beep in a daemon thread
        if sys.platform == "win32":
            threading.Thread(target=self._beep_loop, daemon=True).start()

    def _stop_playback(self) -> None:
        """Stop sounds on all backends."""
        if sys.platform == "win32":
            with contextlib.suppress(Exception):
                import winsound
                winsound.PlaySound(None, winsound.SND_PURGE)

        if self._bridge is not None:
            self._bridge.request_stop.emit()

    def _beep_loop(self) -> None:
        """Synthetic alert beeps when no audio files are available."""
        import time
        import winsound

        while self._is_playing and not self._muted:
            try:
                winsound.Beep(1000, 150)
                winsound.Beep(1400, 150)
                time.sleep(0.2)
            except Exception:
                break


# Singleton instance
_INSTANCE: AudioAlertService | None = None


def get_audio_alert_service() -> AudioAlertService:
    """Return the global AudioAlertService instance."""
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = AudioAlertService()
    return _INSTANCE


__all__ = ["AudioAlertService", "get_audio_alert_service"]
