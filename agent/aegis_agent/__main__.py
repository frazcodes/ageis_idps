"""Entry point for ``python -m aegis_agent``.

Commands
--------
``status``
    Show agent configuration status (default when no command is given).
``inventory``
    Collect and print the local system inventory (``--json`` for machine output).
``processes``
    Take a single read-only process snapshot (``--json`` for machine output).
``ports``
    Take a single read-only listening-port snapshot (``--json`` for machine output).
``files``
    Take a single read-only file-integrity snapshot (``--json``, ``--path`` repeatable).
``events``
    Run a deterministic, in-memory host-event-pipeline demonstration (``--json``).
``detect``
    Run the deterministic rule-based detection engine over synthetic events (``--json``).
``risk``
    Run the explainable risk engine over synthetic findings (``--json``).

Every command performs one action and exits; the agent is not a background
daemon yet, and no monitoring feature is enabled by default. Continuous
monitoring is not exposed on the CLI - each command is a one-shot inspection.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime

from aegis_agent.config import get_agent_settings
from aegis_agent.inventory import SystemInventory, collect_system_inventory
from aegis_agent.monitors.file_integrity import (
    FileCollector,
    FileRecord,
    FileSnapshot,
    build_file_event,
)
from aegis_agent.monitors.port import PortMonitor, PortRecord, PortSnapshot, build_port_event
from aegis_agent.monitors.process import (
    ProcessMonitor,
    ProcessRecord,
    ProcessSnapshot,
    build_process_event,
)
from aegis_agent.pipeline import EventEnvelope, HostEventPipeline, PipelineStats
from aegis_shared.config import get_settings
from aegis_shared.detection import DetectionEngine, DetectionFinding, DetectionSettings
from aegis_shared.enums import (
    AddressFamily,
    EventType,
    FileType,
    HashStatus,
    NetworkDirection,
    Platform,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import (
    FileContext,
    HostRef,
    NetworkContext,
    ProcessContext,
    SecurityEvent,
    SocketContext,
    SourceRef,
)
from aegis_shared.logging import configure_logging, get_logger
from aegis_shared.risk import RiskAssessment, RiskEngine
from aegis_shared.version import __version__


def _configure_logging() -> None:
    global_settings = get_settings()
    configure_logging(
        level=global_settings.log_level,
        json_output=global_settings.log_json,
        service="aegis-agent",
    )


def _run_status() -> int:
    """Report configuration status without collecting anything sensitive."""
    settings = get_agent_settings()
    logger = get_logger("aegis_agent")

    logger.info("Aegis endpoint agent %s", __version__)
    logger.info("Backend target: %s", settings.backend_url)

    monitors = settings.enabled_monitors
    if monitors:
        logger.warning(
            "Monitors enabled (%s) but collection is not implemented yet.",
            ", ".join(monitors),
        )
    else:
        logger.info("No monitors enabled; only system inventory is available.")

    print("Run 'python -m aegis_agent inventory' to collect the local system inventory.")
    return 0


def _format_inventory(inventory: SystemInventory) -> str:
    """Render the inventory as aligned human-readable text."""

    def show(value: object | None) -> str:
        return "unknown" if value is None else str(value)

    os_line = f"{inventory.os_name} {inventory.os_version or ''}".rstrip()
    boot_time = inventory.boot_time.isoformat() if inventory.boot_time else "unknown"

    lines = [
        "Aegis endpoint system inventory",
        f"  host_id            : {inventory.host_id}",
        f"  hostname           : {inventory.hostname}",
        f"  platform           : {inventory.platform.value}",
        f"  os                 : {os_line}",
        f"  architecture       : {inventory.architecture}",
        f"  python_version     : {inventory.python_version}",
        f"  agent_version      : {inventory.agent_version}",
        f"  cpu_count          : {show(inventory.cpu_count)}",
        f"  total_memory_bytes : {show(inventory.total_memory_bytes)}",
        f"  boot_time          : {boot_time}",
        f"  collected_at       : {inventory.collected_at.isoformat()}",
    ]
    return "\n".join(lines)


def _run_inventory(*, as_json: bool) -> int:
    """Collect and print the inventory, then exit successfully."""
    inventory = collect_system_inventory()
    if as_json:
        print(json.dumps(inventory.to_json_dict(), indent=2, sort_keys=True))
    else:
        print(_format_inventory(inventory))
    return 0


def _format_process_snapshot(snapshot: ProcessSnapshot) -> str:
    """Render a process snapshot as a fixed-width table."""

    def cell(value: object | None, width: int, *, right: bool = False) -> str:
        text = "?" if value is None else str(value)
        text = text[:width]
        return f"{text:>{width}}" if right else f"{text:<{width}}"

    lines = [
        f"Aegis process snapshot ({len(snapshot.processes)} processes) "
        f"at {snapshot.captured_at.isoformat()}",
        f"  {cell('PID', 8, right=True)}  {cell('PPID', 8, right=True)}  "
        f"{cell('NAME', 24)}  {cell('USER', 20)}  STARTED",
    ]
    for record in snapshot.processes:
        started = record.create_time.isoformat() if record.create_time else "unknown"
        lines.append(
            f"  {cell(record.pid, 8, right=True)}  {cell(record.ppid, 8, right=True)}  "
            f"{cell(record.name, 24)}  {cell(record.username, 20)}  {started}"
        )
    return "\n".join(lines)


def _run_processes(*, as_json: bool) -> int:
    """Take a single read-only process snapshot, print it, and exit."""
    snapshot = ProcessMonitor().snapshot()
    if as_json:
        print(json.dumps(snapshot.to_json_dict(), indent=2, sort_keys=True))
    else:
        print(_format_process_snapshot(snapshot))
    return 0


def _format_port_snapshot(snapshot: PortSnapshot) -> str:
    """Render a listening-port snapshot as an aligned table.

    The LOCAL column is sized to its widest endpoint so long IPv6 addresses
    (link-local, for example) are never truncated and the port - taken from the
    structured ``local_port`` field - is always visible.
    """

    def cell(value: object | None, width: int, *, right: bool = False) -> str:
        text = "?" if value is None else str(value)
        text = text[:width]
        return f"{text:>{width}}" if right else f"{text:<{width}}"

    local_width = max(
        len("LOCAL"),
        max((len(record.endpoint) for record in snapshot.ports), default=0),
    )

    lines = [
        f"Aegis listening-port snapshot ({len(snapshot.ports)} endpoints) "
        f"at {snapshot.captured_at.isoformat()}",
        f"  {cell('PROTO', 5)}  {cell('FAMILY', 6)}  {cell('LOCAL', local_width)}  "
        f"{cell('PID', 8, right=True)}  {cell('PROCESS', 24)}  STATUS",
    ]
    for record in snapshot.ports:
        lines.append(
            f"  {cell(record.protocol.value, 5)}  {cell(record.address_family.value, 6)}  "
            f"{cell(record.endpoint, local_width)}  {cell(record.pid, 8, right=True)}  "
            f"{cell(record.process_name, 24)}  {record.status or '-'}"
        )
    return "\n".join(lines)


def _run_ports(*, as_json: bool) -> int:
    """Take a single read-only listening-port snapshot, print it, and exit."""
    snapshot = PortMonitor().snapshot()
    if as_json:
        print(json.dumps(snapshot.to_json_dict(), indent=2, sort_keys=True))
    else:
        print(_format_port_snapshot(snapshot))
    return 0


def _format_file_snapshot(snapshot: FileSnapshot) -> str:
    """Render a file-integrity snapshot as an aligned table."""

    def cell(value: object | None, width: int, *, right: bool = False) -> str:
        text = "?" if value is None else str(value)
        text = text[:width]
        return f"{text:>{width}}" if right else f"{text:<{width}}"

    path_width = max(
        len("PATH"),
        max((len(record.path) for record in snapshot.files), default=0),
    )
    status_width = max(
        len("HASH STATUS"),
        max((len(record.hash_status.value) for record in snapshot.files), default=0),
    )

    lines = [
        f"Aegis file-integrity snapshot ({len(snapshot.files)} objects) "
        f"at {snapshot.captured_at.isoformat()}",
        f"  {cell('TYPE', 9)}  {cell('SIZE', 12, right=True)}  {cell('MODIFIED', 20)}  "
        f"{cell('SHA256', 16)}  {cell('HASH STATUS', status_width)}  {cell('PATH', path_width)}",
    ]
    for record in snapshot.files:
        modified = record.modified_at.strftime("%Y-%m-%dT%H:%M:%SZ") if record.modified_at else "-"
        digest = record.sha256[:16] if record.sha256 else "-"
        lines.append(
            f"  {cell(record.file_type.value, 9)}  "
            f"{cell(record.size_bytes, 12, right=True)}  {cell(modified, 20)}  "
            f"{cell(digest, 16)}  {cell(record.hash_status.value, status_width)}  {record.path}"
        )
    return "\n".join(lines)


def _run_files(*, as_json: bool, paths: list[str] | None) -> int:
    """Take a single read-only file-integrity snapshot, print it, and exit."""
    settings = get_agent_settings()
    targets = paths if paths else settings.file_integrity_paths

    if not targets:
        print(
            "File integrity monitoring is disabled and no paths are configured. "
            "Set AEGIS_AGENT_FILE_INTEGRITY_PATHS or pass --path."
        )
        return 0

    collector = FileCollector(
        paths=targets,
        max_hash_bytes=settings.file_integrity_max_hash_bytes,
        symlink_policy=settings.file_integrity_symlink_policy,
    )
    snapshot = collector.collect()

    if as_json:
        print(json.dumps(snapshot.to_json_dict(), indent=2, sort_keys=True))
    else:
        print(_format_file_snapshot(snapshot))
    return 0


_DEMO_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)


def _demo_events() -> list[SecurityEvent]:
    """Build a deterministic set of canonical events from local, synthetic records.

    Uses the real monitor event builders so the demonstration exercises the same
    mapping the runtime will use - but no process table, sockets or filesystem are
    inspected and nothing is transmitted. Event IDs and timestamps are fixed so
    repeated runs are byte-for-byte reproducible.
    """
    source = SourceRef(kind=SourceKind.AGENT, id="agent-demo")
    host = HostRef(host_id="host-demo", hostname="demo-host", platform=Platform.UNKNOWN)

    process_record = ProcessRecord(
        pid=4242,
        ppid=4,
        name="demo.exe",
        executable_path="C:\\demo\\demo.exe",
        username="demo",
        create_time=_DEMO_TIMESTAMP,
    )
    port_record = PortRecord(
        protocol=TransportProtocol.TCP,
        address_family=AddressFamily.IPV4,
        local_address="127.0.0.1",
        local_port=8080,
        status="LISTEN",
        pid=4242,
        process_name="demo.exe",
        process_create_time=_DEMO_TIMESTAMP,
    )
    file_record = FileRecord(
        path="C:\\demo\\config.ini",
        file_type=FileType.REGULAR,
        size_bytes=42,
        modified_at=_DEMO_TIMESTAMP,
        sha256="ab" * 32,
        hash_status=HashStatus.HASHED,
    )

    events = [
        build_process_event(
            process_record,
            event_type=EventType.PROCESS_STARTED,
            source=source,
            host=host,
            timestamp=_DEMO_TIMESTAMP,
        ),
        build_port_event(
            port_record,
            event_type=EventType.PORT_LISTENING,
            source=source,
            host=host,
            timestamp=_DEMO_TIMESTAMP,
        ),
        build_file_event(
            file_record,
            event_type=EventType.FILE_MODIFIED,
            source=source,
            host=host,
            timestamp=_DEMO_TIMESTAMP,
        ),
    ]
    return [
        event.model_copy(update={"event_id": f"demo-{index:04d}"})
        for index, event in enumerate(events, start=1)
    ]


def _format_event_pipeline(stats: PipelineStats, envelopes: list[EventEnvelope]) -> str:
    """Render pipeline stats and drained events as aligned text."""
    lines = [
        "Aegis host event pipeline (in-memory demonstration; no transmission)",
        f"  capacity={stats.capacity} accepted={stats.accepted} rejected={stats.rejected} "
        f"dropped={stats.dropped} duplicates={stats.duplicates} buffered={stats.buffered}",
        f"Drained events ({len(envelopes)}):",
    ]
    for envelope in envelopes:
        event = envelope.event
        host_id = event.host.host_id if event.host else "-"
        lines.append(
            f"  #{envelope.sequence}  {event.event_type.value}  "
            f"severity={event.severity.value}  host={host_id}  id={event.event_id}"
        )
    return "\n".join(lines)


def _run_events(*, as_json: bool) -> int:
    """Run a deterministic, read-only, in-memory pipeline demonstration."""
    settings = get_agent_settings()
    pipeline = HostEventPipeline(max_events=settings.event_buffer_max_events)

    events = _demo_events()
    pipeline.submit_all(events)
    # A repeated event_id is rejected as an exact duplicate (bounded dedup).
    pipeline.submit(events[0])

    stats = pipeline.stats
    envelopes = pipeline.drain()

    if as_json:
        print(
            json.dumps(
                {
                    "stats": stats.to_json_dict(),
                    "events": [envelope.to_json_dict() for envelope in envelopes],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(_format_event_pipeline(stats, envelopes))
    return 0


def _demo_detection_settings() -> DetectionSettings:
    """Explicit demonstration criteria - never hard-coded production defaults."""
    return DetectionSettings(
        suspicious_listen_ports=[8080],
        sensitive_file_patterns=["*secrets*"],
        executable_extensions=[".exe"],
        executable_watch_paths=[os.path.join("demo", "watch")],
        suspicious_process_path_patterns=["*public*"],
        suspicious_network_endpoints=["203.0.113.9:4444"],
    )


def _demo_detection_events() -> list[SecurityEvent]:
    """Deterministic synthetic events: five matches and one benign event."""
    agent_source = SourceRef(kind=SourceKind.AGENT, id="agent-demo")
    sensor_source = SourceRef(kind=SourceKind.SENSOR, id="sensor-demo")
    host = HostRef(host_id="host-demo", hostname="demo-host", platform=Platform.UNKNOWN)
    ts = _DEMO_TIMESTAMP

    return [
        SecurityEvent.create(
            event_id="detect-0001",
            event_type=EventType.PORT_LISTENING,
            source=agent_source,
            host=host,
            timestamp=ts,
            socket=SocketContext(
                local_address="127.0.0.1",
                local_port=8080,
                address_family=AddressFamily.IPV4,
                protocol=TransportProtocol.TCP,
                status="LISTEN",
            ),
            process=ProcessContext(pid=4242, name="demo.exe"),
        ),
        SecurityEvent.create(
            event_id="detect-0002",
            event_type=EventType.FILE_MODIFIED,
            source=agent_source,
            host=host,
            timestamp=ts,
            file=FileContext(
                path=os.path.join("demo", "secrets", "config.ini"),
                operation="modified",
                file_type=FileType.REGULAR,
                hash_status=HashStatus.HASHED,
            ),
        ),
        SecurityEvent.create(
            event_id="detect-0003",
            event_type=EventType.FILE_CREATED,
            source=agent_source,
            host=host,
            timestamp=ts,
            file=FileContext(
                path=os.path.join("demo", "watch", "payload.exe"),
                operation="created",
                file_type=FileType.REGULAR,
            ),
        ),
        SecurityEvent.create(
            event_id="detect-0004",
            event_type=EventType.PROCESS_STARTED,
            source=agent_source,
            host=host,
            timestamp=ts,
            process=ProcessContext(
                pid=4243,
                name="payload.exe",
                executable_path=os.path.join("demo", "public", "payload.exe"),
            ),
        ),
        SecurityEvent.create(
            event_id="detect-0005",
            event_type=EventType.NETWORK_PACKET_OBSERVED,
            source=sensor_source,
            timestamp=ts,
            network=NetworkContext(
                src_ip="10.0.0.5",
                dst_ip="203.0.113.9",
                dst_port=4444,
                protocol=TransportProtocol.TCP,
                direction=NetworkDirection.OUTBOUND,
                ip_version=AddressFamily.IPV4,
                flow_id="demo-flow-0001",
            ),
        ),
        # Benign: a normal HTTPS listener must not match anything.
        SecurityEvent.create(
            event_id="detect-0006",
            event_type=EventType.PORT_LISTENING,
            source=agent_source,
            host=host,
            timestamp=ts,
            socket=SocketContext(
                local_address="127.0.0.1",
                local_port=443,
                address_family=AddressFamily.IPV4,
                protocol=TransportProtocol.TCP,
                status="LISTEN",
            ),
        ),
    ]


def _format_findings(findings: tuple[DetectionFinding, ...], evaluated: int) -> str:
    """Render findings as aligned text."""
    lines = [f"Aegis detection demonstration ({len(findings)} findings from {evaluated} events)"]
    if not findings:
        lines.append("  (no findings)")
        return "\n".join(lines)

    for finding in findings:
        lines.append(
            f"  [{finding.rule_id}] {finding.title}  "
            f"severity={finding.severity.value}  event={finding.event_id}"
        )
        if finding.evidence:
            evidence = " ".join(f"{key}={value}" for key, value in finding.evidence.items())
            lines.append(f"      {evidence}")
    return "\n".join(lines)


def _run_detect(*, as_json: bool) -> int:
    """Evaluate deterministic synthetic events through the detection engine."""
    engine = DetectionEngine.from_settings(_demo_detection_settings())
    events = _demo_detection_events()
    findings = engine.evaluate_many(events)

    if as_json:
        print(
            json.dumps(
                {
                    "events_evaluated": len(events),
                    "finding_count": len(findings),
                    "findings": [finding.to_json_dict() for finding in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(_format_findings(findings, len(events)))
    return 0


def _risk_demo_items() -> list[tuple[SecurityEvent, tuple[DetectionFinding, ...]]]:
    """Deterministic cases: zero, medium, high and multiple findings."""
    ts = _DEMO_TIMESTAMP
    agent_source = SourceRef(kind=SourceKind.AGENT, id="agent-demo")
    host = HostRef(host_id="host-demo", hostname="demo-host", platform=Platform.UNKNOWN)

    def port_event(event_id: str, port: int) -> SecurityEvent:
        return SecurityEvent.create(
            event_id=event_id,
            event_type=EventType.PORT_LISTENING,
            source=agent_source,
            host=host,
            timestamp=ts,
            socket=SocketContext(
                local_address="127.0.0.1",
                local_port=port,
                address_family=AddressFamily.IPV4,
                protocol=TransportProtocol.TCP,
                status="LISTEN",
            ),
        )

    def finding(
        event: SecurityEvent,
        *,
        rule_id: str,
        rule_name: str,
        severity: Severity,
    ) -> DetectionFinding:
        return DetectionFinding(
            finding_id=f"{rule_id}:{event.event_id}",
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            title=rule_name,
            description=f"Demonstration finding for {rule_name}.",
            event_id=event.event_id,
            event_type=event.event_type,
            category=event.category,
            timestamp=event.timestamp,
            host_id=event.host.host_id if event.host is not None else None,
            evidence={"demo": "true"},
            tags=("demo",),
        )

    benign = port_event("risk-0001", 443)
    medium_event = port_event("risk-0002", 8080)
    high_event = port_event("risk-0003", 8443)
    multi_event = port_event("risk-0004", 9000)

    return [
        (benign, ()),
        (
            medium_event,
            (
                finding(
                    medium_event,
                    rule_id="AEGIS-LISTEN-001",
                    rule_name="Unexpected listening port",
                    severity=Severity.MEDIUM,
                ),
            ),
        ),
        (
            high_event,
            (
                finding(
                    high_event,
                    rule_id="AEGIS-PROC-001",
                    rule_name="Process launched from configured path",
                    severity=Severity.HIGH,
                ),
            ),
        ),
        (
            multi_event,
            (
                finding(
                    multi_event,
                    rule_id="AEGIS-LISTEN-001",
                    rule_name="Unexpected listening port",
                    severity=Severity.MEDIUM,
                ),
                finding(
                    multi_event,
                    rule_id="AEGIS-FILE-001",
                    rule_name="Configured sensitive file modified",
                    severity=Severity.HIGH,
                ),
            ),
        ),
    ]


def _format_risk(assessments: tuple[RiskAssessment, ...]) -> str:
    """Render risk assessments as aligned text."""
    lines = [f"Aegis risk assessment demonstration ({len(assessments)} assessments)"]
    for assessment in assessments:
        lines.append(
            f"  event={assessment.event_id} score={assessment.risk_score} "
            f"level={assessment.risk_level.value} severity={assessment.severity.value} "
            f"contributors={len(assessment.contributors)}"
        )
        for contributor in assessment.contributors:
            lines.append(f"      {contributor.reason}")
    return "\n".join(lines)


def _run_risk(*, as_json: bool) -> int:
    """Assess deterministic synthetic events/findings with the risk engine."""
    engine = RiskEngine()
    assessments = engine.assess_many(_risk_demo_items())

    if as_json:
        print(
            json.dumps(
                {
                    "count": len(assessments),
                    "assessments": [assessment.to_json_dict() for assessment in assessments],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(_format_risk(assessments))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis_agent",
        description="Aegis IDPS endpoint agent (single-shot commands).",
    )
    parser.add_argument("--version", action="version", version=f"aegis-agent {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Show agent configuration status.")

    inventory_parser = subparsers.add_parser(
        "inventory", help="Collect and print the local system inventory."
    )
    inventory_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON instead of human-readable text.",
    )

    processes_parser = subparsers.add_parser(
        "processes", help="Take a single read-only process snapshot."
    )
    processes_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON instead of human-readable text.",
    )

    ports_parser = subparsers.add_parser(
        "ports", help="Take a single read-only listening-port snapshot."
    )
    ports_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON instead of human-readable text.",
    )

    files_parser = subparsers.add_parser(
        "files", help="Take a single read-only file-integrity snapshot."
    )
    files_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON instead of human-readable text.",
    )
    files_parser.add_argument(
        "--path",
        action="append",
        dest="paths",
        metavar="PATH",
        help="Path to inspect (repeatable). Overrides configured paths.",
    )

    events_parser = subparsers.add_parser(
        "events", help="Run a deterministic in-memory host-event-pipeline demonstration."
    )
    events_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON instead of human-readable text.",
    )

    detect_parser = subparsers.add_parser(
        "detect", help="Run the deterministic detection engine over synthetic events."
    )
    detect_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON instead of human-readable text.",
    )

    risk_parser = subparsers.add_parser(
        "risk", help="Run the explainable risk engine over synthetic findings."
    )
    risk_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON instead of human-readable text.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the requested agent command."""
    args = _build_parser().parse_args(argv)
    _configure_logging()

    if args.command == "inventory":
        return _run_inventory(as_json=bool(args.as_json))
    if args.command == "processes":
        return _run_processes(as_json=bool(args.as_json))
    if args.command == "ports":
        return _run_ports(as_json=bool(args.as_json))
    if args.command == "files":
        return _run_files(as_json=bool(args.as_json), paths=args.paths)
    if args.command == "events":
        return _run_events(as_json=bool(args.as_json))
    if args.command == "detect":
        return _run_detect(as_json=bool(args.as_json))
    if args.command == "risk":
        return _run_risk(as_json=bool(args.as_json))
    return _run_status()


if __name__ == "__main__":
    sys.exit(main())
