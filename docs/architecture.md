# Architecture

Aegis IDPS is a monorepo of cooperating components. They share one vocabulary and
one event envelope, defined in [`shared/`](../shared) and imported everywhere.

## Components

| Component | Path | Responsibility | Runs |
| --- | --- | --- | --- |
| Shared contracts | `shared/aegis_shared` | Event schema, enums, config and logging bases. | Everywhere |
| Endpoint agent | `agent/aegis_agent` | Host telemetry: processes, ports, files, YARA, inventory. | Endpoints |
| Network sensor | `network-sensor/aegis_network_sensor` | Passive capture, packet normalization, telemetry events. | Network taps |
| ML engine | `ml-engine/aegis_ml_engine` | Feature extraction, anomaly detection, risk scoring. | Backend host |
| Response engine | `response-engine/aegis_response_engine` | Policy-gated IPS actions. | Backend/endpoints |
| Backend | `backend/aegis_backend` | Ingestion, persistence, correlation, auth/RBAC, API. | Server |
| Desktop console | `desktop/aegis_desktop` | Native administrator GUI (PySide6/Qt); read-only views. | Desktop |

## Data flow

```
 agent ─┐
        ├─► POST /api/v1/events ─► backend ingestion ─► PostgreSQL
 sensor ┘                              │
                                       ▼
                              ML engine risk scoring
                                       │
                                       ▼
                            correlation ─► alerts / incidents
                                       │
                                       ▼
                          response engine (policy gated)
                                       │
                                       ▼
                        native desktop console (read-only views)
```

Everything crossing a component boundary is a
`aegis_shared.events.SecurityEvent`. Components never invent their own event
shape; sensor-specific detail travels in the event's `raw` and `labels` fields.

## Administrator console

The primary user interface is the native desktop application in
[`desktop/`](../desktop) (PySide6/Qt), launched with `python -m aegis_desktop`.
It is read-only: it consumes existing configuration and inventory and starts no
monitor, no packet capture and no response.

The FastAPI backend remains the service/API layer for agent communication, event
APIs and future remote administration. It does not serve a browser UI.

## Module boundaries

* **Shared** has no dependencies on other Aegis packages and must stay that way.
* **Sensors and agent** depend on `shared` only, never on the backend.
* **Backend** depends on `shared`; it orchestrates engines but does not contain
  detection logic.
* **Desktop console** reads configuration/inventory read-only and performs no
  response; the backend remains the API/service layer.

## Endpoint agent: system inventory

`agent/aegis_agent/inventory` is the first implemented agent capability. It is
read-only and always available - it does not require a monitor to be enabled.

* **Collected:** stable host id, hostname, OS name/version, platform, architecture,
  Python version, agent version, boot time, logical CPU count, total memory and
  the UTC collection timestamp.
* **Not collected:** usernames, environment variables, files/documents, browser
  data, credentials, private keys, tokens or hardware fingerprints (MAC address,
  disk serial, Windows `MachineGuid`).
* **Host identity** is resolved in order: `AEGIS_AGENT_ID` if set; otherwise a
  previously persisted identifier; otherwise a new UUIDv4 generated once and
  written atomically to the agent's application state directory
  (`%LOCALAPPDATA%\Aegis\agent` on Windows, `$XDG_STATE_HOME/aegis/agent` or
  `~/.local/state/aegis/agent` on Linux, `~/Library/Application Support/Aegis/agent`
  on macOS). It is stable across restarts; deleting the state file mints a new one.
* **Consumption:** later modules (process, port, file-integrity, YARA) reuse
  `collect_system_inventory()` and the resolved identity so every event carries the
  same `host_id` and platform. `SystemInventory.to_json_dict()` is JSON-safe for
  transport to the backend.

## Endpoint agent: process and port monitoring

Both monitors are read-only, single-shot friendly and daemon-free; a caller
drives `start()` / `snapshot()` / `poll()` / `stop()`. They reuse the canonical
`SecurityEvent` and the stable host identity from inventory.

**Process monitoring** (`agent/aegis_agent/monitors/process`) enumerates running
processes and diffs snapshots into `host.process.started` / `host.process.stopped`.
Identity is PID + creation time, so a reused PID is reported as one process
stopping and another starting.

**Port monitoring** (`agent/aegis_agent/monitors/port`) discovers local listening
endpoints and diffs them into `host.port.listening` / `host.port.closed`.

* **TCP vs UDP:** only TCP sockets in `LISTEN` are collected. UDP has no
  TCP-style `LISTEN`, so a bound UDP socket with a non-zero local port is treated
  as an endpoint - this can include unconnected client sockets.
* **Ownership correlation:** when a socket exposes an owning PID, the monitor
  resolves its name and creation time through a per-snapshot PID cache (one
  lookup per PID, not per socket) and reuses the process monitor's
  `(pid, create_time)` identity.
* **Port identity:** `protocol | address_family | local_address | local_port |
  owner`. Because ownership is part of the identity, a port changing owner is
  reported as the old endpoint closing and the new one opening. Owner degrades to
  `unowned` when unavailable, so identity stays deterministic without privileges.
* **Addresses:** stored as structured fields and rendered unambiguously
  (`0.0.0.0:8000`, `[::1]:8000`). Remote peers are not recorded - this is
  listening-port discovery, not traffic inspection.
* **Permission limits:** socket enumeration or PID resolution may require
  elevated privileges. `AccessDenied`/`OSError` degrade gracefully (empty
  snapshot, or an unknown owner); unexpected errors still surface.
* **Not done here:** no firewall, IP/port blocking, process termination, packet
  capture, DNS or traffic inspection, no elevation request. Prevention belongs to
  the later Response Engine.

## Endpoint agent: file integrity monitoring

`agent/aegis_agent/monitors/file_integrity` detects changes to **explicitly
configured** files and directories. It is read-only and detection-only - it never
writes, deletes, quarantines, executes or remediates a file.

* **Scope:** only paths in `AEGIS_AGENT_FILE_INTEGRITY_PATHS` (or CLI `--path`).
  There is no implicit filesystem scanning. A configured directory is traversed
  recursively; symlinked directories are never traversed, so a scan cannot escape
  the configured tree or loop.
* **Change detection:** a baseline snapshot is diffed by normalized path into
  `host.file.created` / `host.file.modified` / `host.file.deleted`. A path present
  in both snapshots is *modified* when its type/size/mtime/hash/status signature
  differs. Rename detection is intentionally not attempted - polling has no
  reliable rename signal, so a rename is reported honestly as delete + create.
* **Identity:** the normalized path (case-folded on case-insensitive platforms).
  File contents are never part of identity.
* **Hashing:** streaming SHA-256 in 1 MiB chunks (bounded memory). Files above
  `AEGIS_AGENT_FILE_INTEGRITY_MAX_HASH_BYTES` are not hashed. A missing hash is
  never treated as "unchanged": `hash_status` records `skipped_size`,
  `permission_denied`, `unsupported`, `error` or `not_applicable`. The digest is
  recomputed each poll, so a content change is caught even when size and mtime are
  unchanged.
* **Symlinks:** `skip` (default) ignores them, `report` records the link itself,
  `follow` describes the target (files only; directories are not traversed).
* **Limitations:** polling-based, so a create-then-delete between two polls is
  missed; above the size cap only metadata changes are detected.
* **Not done here:** no YARA, no quarantine, no deletion, no remediation. Those
  belong to later steps and the Response Engine.

## Host event pipeline

`agent/aegis_agent/pipeline` is an internal, in-memory transport for the
canonical `SecurityEvent` produced by the host monitors. It is **not** a SIEM,
database, detection engine or response system, and it never transmits anything.

* **Canonical events only:** the pipeline wraps `SecurityEvent` in a minimal
  `EventEnvelope` (monotonic `sequence` + `enqueued_at`); it defines no second
  schema and duplicates no event fields.
* **Validation:** deterministic schema/data checks - non-empty `event_id`, a
  compatible `schema_version` major, a valid `event_type`/`category` pairing, a
  timezone-aware `timestamp`, and the context block required by the event type.
  Invalid events are rejected and counted, never admitted. This is correctness,
  not threat detection.
* **Bounded buffer:** a thread-safe FIFO `EventBuffer` with a configurable
  capacity (`AEGIS_AGENT_EVENT_BUFFER_MAX_EVENTS`, default 1000). When full the
  **oldest** event is dropped, so memory stays bounded and recent telemetry is
  kept. `drain()` returns events in insertion order.
* **Ordering:** events are appended and drained in submission order; they are
  never reordered by timestamp, and equal timestamps keep insertion order. The
  pipeline makes no claim about global distributed ordering.
* **Deduplication:** only an exact repeat of a previously seen `event_id` is
  rejected (the contract treats IDs as unique). There is no heuristic or
  content-based dedup, so legitimate events are never silently dropped. The dedup
  window is bounded and evicts oldest-first.
* **Counters:** `accepted`, `rejected`, `dropped`, `duplicates`, `buffered`,
  `capacity`, `next_sequence` via `pipeline.stats`.
* **Monitor integration:** `collect_monitor_events()` adapts process/port/file
  change sets into events; the monitors remain independently usable.
* **Limitation:** in-memory only - events are lost on process exit until a future
  exporter/backend is added. No disk, network, database or remediation.

## Network sensor (telemetry only)

`network-sensor/aegis_network_sensor` is a passive, read-only telemetry
foundation. **Network telemetry is not network threat detection** - no scanning,
DoS, C2, DNS or anomaly logic lives here.

* **Capture is disabled by default** and no interface is selected by default.
  Enabling capture without naming an interface is a configuration error, because
  guessing an interface could capture the wrong link. `capture` is always a single
  bounded run (`count` packets, `store=False`); there is no unbounded loop.
* **Read-only:** the sensor only observes frames. It never injects, forges,
  modifies or redirects traffic, never changes firewall/routing/DNS state and
  never shells out to network tools.
* **Supported protocols:** IPv4, IPv6, TCP, UDP, ICMP/ICMPv6. Unknown or malformed
  frames are skipped, never crash the sensor.
* **Normalized fields:** timestamp, interface, IP version, source/destination IP
  and ports, transport protocol, packet length, direction and a deterministic flow
  id. Ports are marked not-applicable for non-TCP/UDP, and unknown ports are
  `None` - never a misleading `0`. IPv6 endpoints are bracketed (`[::1]:443`).
* **Privacy:** no payloads, credentials or application content are stored - only
  header metadata.
* **Direction:** classified only when configured `local_addresses` prove it;
  otherwise it stays `unknown`. Source is never assumed inbound.
* **Flow handling:** packet-level telemetry only. Each record carries a
  deterministic directional flow id; aggregation is deferred to the detection
  step (see `flows/`).
* **Pipeline:** normalized records become canonical `NETWORK_PACKET_OBSERVED`
  events submitted to a `NetworkEventPipeline`, which reuses the shared in-memory
  transport (`aegis_shared.pipeline`). Host and network pipelines share validation
  and buffering and can be unified later.
* **Privileges:** listing interfaces and all tests need no privileges; live
  capture needs Npcap (Windows) or root/CAP_NET_RAW (Linux).

## Detection engine (rules, not confirmation)

`shared/aegis_shared/detection` turns canonical events into deterministic
`DetectionFinding` objects with evidence. It is passive and stateless: it never
blocks, kills, deletes, quarantines or executes anything. **A finding is data.**

* **Architecture:** `DetectionRule` (definition) -> rule `matches`/`evidence`
  (evaluation) -> `DetectionFinding` (representation) -> `DetectionEngine`
  (orchestration). Call `engine.evaluate(event)` or `engine.evaluate_many(events)`;
  the engine is independently callable and the event pipeline never detects.
* **Initial rules:** unexpected listening port (A), configured sensitive file
  modified (B), executable created in a monitored location (C), process launched
  from a configured path (D), configured suspicious endpoint observed (E).
* **Configuration-driven:** every "suspicious" criterion lives under
  `AEGIS_DETECTION_*` and defaults to empty (executable extensions have a small
  default list). Aegis ships no hard-coded malicious ports, IPs or paths and never
  scans the system on its own. A rule with empty criteria never matches.
* **Multiple findings:** one event may match several rules; all matches are
  returned, ordered deterministically by `rule_id`.
* **Findings:** deterministic `finding_id` (`rule_id:event_id`), severity, title,
  description, `event_id` traceability, host id, evidence and tags; timestamps are
  timezone-aware UTC.
* **Severity semantics:** a rule's default severity is a deterministic label, not
  a computed risk score - risk scoring is a later step.
* **Limitations:** rules match configured criteria only; they do not prove
  compromise and cannot detect unknown threats. Detection is per-event and
  stateless - no correlation, no ML, no response.

## Risk scoring (explainable, deterministic)

`shared/aegis_shared/risk` turns detection findings into a bounded 0-100
`RiskAssessment` with per-finding contributors. It is separate from detection
because *how risky an observation is* is a policy decision distinct from *whether
a rule matched*. It is deterministic, stateless, passive and performs no I/O, ML
or response.

* **Algorithm (version `1`):** each finding contributes
  `min(severity_weight, max_contribution_per_finding)`; contributions are summed
  and clamped to `0-100`. The additive formula is bounded by both a per-finding
  cap and the hard total cap, so many findings cannot produce unbounded or
  negative risk.
* **Weights / thresholds:** info 0, low 10, medium 25, high 40, critical 60; the
  score maps to `RiskLevel` at low 10 / medium 25 / high 40 / critical 60. All
  values are configurable under `AEGIS_RISK_*` and validated (non-negative,
  strictly increasing thresholds).
* **Explainability:** every non-zero score lists contributors (finding ID, rule
  ID, severity, contribution, reason) and `finding_ids`; the full finding is never
  copied.
* **Zero findings:** score 0, level `informational`, empty contributors/reasons,
  still traceable by `event_id`. Risk is never invented.
* **Determinism:** same event + findings + configuration gives the same
  assessment; contributors are ordered by `finding_id`. Duplicate finding IDs and
  findings belonging to another event are rejected, never silently double-counted.
* **Future ML:** an `AnomalySignal` (`source`, `score`, `confidence`,
  `model_version`, `reason`) is a typed extension point requiring no ML library; a
  supplied signal is recorded but does not affect the score yet.
* **Limitations:** no ML, no cross-event correlation, no response. A risk
  assessment is not proof of compromise.

**Detection finding != risk assessment != confirmed compromise.**

## Safety model

Security-sensitive behaviour is opt-in and off by default:

* The endpoint agent performs only read-only inventory by default; every monitor
  (process, port, file integrity, YARA) is disabled until explicitly enabled.
* The network sensor does not capture packets unless `AEGIS_SENSOR_CAPTURE_ENABLED=true`.
* The response engine starts in `monitor` mode with `dry_run=true` and
  `require_approval=true`; it will not modify a host or network until explicitly
  placed in `enforce` mode with dry-run disabled.

See [`development.md`](development.md) for how to run the components locally.
