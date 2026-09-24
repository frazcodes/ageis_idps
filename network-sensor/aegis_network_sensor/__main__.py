"""Entry point for ``python -m aegis_network_sensor``.

Commands
--------
``status``
    Show sensor configuration status (default when no command is given).
``interfaces``
    List available capture interfaces (read-only; no privileges required).
``capture``
    Perform one short, bounded passive capture. Does nothing unless capture is
    explicitly enabled (``AEGIS_SENSOR_CAPTURE_ENABLED=true`` and
    ``AEGIS_SENSOR_INTERFACE`` set).

The sensor never injects or modifies traffic. Packet capture may require
elevated privileges (Npcap on Windows, root/CAP_NET_RAW on Linux).
"""

from __future__ import annotations

import argparse
import json
import sys

from aegis_network_sensor.capture import CaptureUnavailableError
from aegis_network_sensor.config import SensorSettings, get_sensor_settings
from aegis_shared.config import get_settings
from aegis_shared.logging import configure_logging, get_logger
from aegis_shared.version import __version__


def _configure_logging() -> None:
    global_settings = get_settings()
    configure_logging(
        level=global_settings.log_level,
        json_output=global_settings.log_json,
        service="aegis-network-sensor",
    )


def _run_status() -> int:
    """Report configuration status without capturing anything."""
    settings = get_sensor_settings()
    logger = get_logger("aegis_network_sensor")

    logger.info("Aegis network sensor %s", __version__)
    logger.info("Interface: %s", settings.interface or "<unset>")
    if settings.capture_enabled:
        logger.warning(
            "Capture is ENABLED on %r; run 'python -m aegis_network_sensor capture' "
            "for a bounded capture.",
            settings.interface,
        )
    else:
        logger.info("Packet capture is disabled.")

    print("Run 'python -m aegis_network_sensor interfaces' to list capture interfaces.")
    return 0


def _run_interfaces(*, as_json: bool) -> int:
    """List capture interfaces without capturing."""
    try:
        from aegis_network_sensor.capture import list_interfaces

        interfaces = list_interfaces()
    except CaptureUnavailableError as exc:
        print(f"Interface listing unavailable: {exc}")
        return 1

    if as_json:
        print(json.dumps({"interfaces": list(interfaces)}, indent=2))
        return 0

    if interfaces:
        print(f"Available interfaces ({len(interfaces)}):")
        for name in interfaces:
            print(f"  {name}")
    else:
        print("No interfaces reported (is scapy/Npcap installed?).")
    return 0


def _run_capture(*, as_json: bool, interface: str | None, count: int | None) -> int:
    """Run one bounded passive capture, but only if explicitly enabled."""
    settings = get_sensor_settings()
    if interface:
        settings = SensorSettings(**{**settings.model_dump(), "interface": interface})

    if not settings.capture_enabled:
        print(
            "Packet capture is disabled. Set AEGIS_SENSOR_CAPTURE_ENABLED=true and "
            "AEGIS_SENSOR_INTERFACE, then run 'capture' again."
        )
        return 0
    if not settings.interface.strip():
        print("No capture interface configured (set AEGIS_SENSOR_INTERFACE or pass --interface).")
        return 0

    from aegis_network_sensor.sensor import NetworkSensor

    sensor = NetworkSensor(settings)
    try:
        summary = sensor.capture(count=count)
    except Exception as exc:
        print(f"Capture failed: {exc}")
        print(
            "Packet capture usually requires elevated privileges "
            "(Npcap on Windows, root/CAP_NET_RAW on Linux)."
        )
        return 1

    if as_json:
        print(json.dumps(summary.to_json_dict(), indent=2, sort_keys=True))
    else:
        print(f"Aegis network sensor capture summary (interface={summary.interface})")
        print(
            f"  observed={summary.observed} normalized={summary.normalized} "
            f"skipped={summary.skipped} accepted={summary.accepted} "
            f"rejected={summary.rejected} buffered={summary.buffered}/{summary.capacity}"
        )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis_network_sensor",
        description="Aegis IDPS network sensor (passive, read-only).",
    )
    parser.add_argument(
        "--version", action="version", version=f"aegis-network-sensor {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Show sensor configuration status.")

    interfaces_parser = subparsers.add_parser(
        "interfaces", help="List available capture interfaces."
    )
    interfaces_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON.")

    capture_parser = subparsers.add_parser(
        "capture", help="Run one short bounded passive capture (only if enabled)."
    )
    capture_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON.")
    capture_parser.add_argument(
        "--interface", default=None, metavar="IFACE", help="Override the configured interface."
    )
    capture_parser.add_argument(
        "--count",
        type=int,
        default=None,
        metavar="N",
        help="Maximum packets to capture (bounded by configuration).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the requested sensor command."""
    args = _build_parser().parse_args(argv)
    _configure_logging()

    if args.command == "interfaces":
        return _run_interfaces(as_json=bool(args.as_json))
    if args.command == "capture":
        return _run_capture(as_json=bool(args.as_json), interface=args.interface, count=args.count)
    return _run_status()


if __name__ == "__main__":
    sys.exit(main())
