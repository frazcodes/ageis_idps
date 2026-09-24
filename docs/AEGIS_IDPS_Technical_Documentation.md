# AEGIS IDPS — Technical Documentation

> Complete implementation reference for all built components.
> Version: 0.1.0 | Steps 1–35 Completed

---

## Table of Contents

1. [Implementation Status](#1-implementation-status)
2. [Shared Package — Foundation Layer](#2-shared-package--foundation-layer)
3. [Agent Package — Host Monitoring](#3-agent-package--host-monitoring)
4. [Network Sensor — Packet Capture](#4-network-sensor--packet-capture)
5. [ML Engine — Anomaly Detection](#5-ml-engine--anomaly-detection)
6. [Runtime — Orchestrator](#6-runtime--orchestrator)
7. [Response Engine — IPS Actions](#7-response-engine--ips-actions)
8. [Desktop Console — SOC UI](#8-desktop-console--soc-ui)
9. [Backend — API Layer](#9-backend--api-layer)
10. [Configuration System](#10-configuration-system)
11. [Test Suite](#11-test-suite)

---

## 1. Implementation Status

### Completed Steps (1–35)

| Step | Feature | Status |
|---|---|---|
| 1 | Monorepo structure (8 packages) | Done |
| 2 | Shared enums (18 StrEnum classes) | Done |
| 3 | SecurityEvent model (frozen, immutable) | Done |
| 4 | Event pipeline (bounded, dedup) | Done |
| 5 | Host monitors (process, port, FIM) | Done |
| 6 | System inventory collector | Done |
| 7 | Network sensor (scapy capture) | Done |
| 8 | Packet normalization (header-only) | Done |
| 9 | Flow aggregation (bounded 4096) | Done |
| 10 | Detection engine (6 per-event rules) | Done |
| 11 | Behavioral rules (4 window-based) | Done |
| 12 | Risk scoring engine (0-100) | Done |
| 13 | ML anomaly detection (Isolation Forest) | Done |
| 14 | Host anomaly model | Done |
| 15 | IOC/threat intel matching | Done |
| 16 | Communication analyzer (multi-signal) | Done |
| 17 | Correlation engine (incidents) | Done |
| 18 | Host-network cross-domain correlation | Done |
| 19 | Asset registry | Done |
| 20 | Response policy engine (fail-closed) | Done |
| 21 | Windows Firewall adapter (netsh) | Done |
| 22 | Response executor (5 guards) | Done |
| 23 | Response workflow (approval states) | Done |
| 24 | Audit trail | Done |
| 25 | Runtime orchestrator (1309 lines) | Done |
| 26 | Desktop PySide6 console | Done |
| 27 | 11 sidebar pages | Done |
| 28 | Dark SOC theme | Done |
| 29 | Splash screen | Done |
| 30 | Live network activity table | Done |
| 31 | Detection/investigation pages | Done |
| 32 | Network monitoring page | Done |
| 33 | SOC Posture Row (3 premium cards) | Done |
| 34 | Active Threat Investigation Feed | Done |
| 35 | System Health Bar + Action Center interactivity | Done |

### Code Metrics

| Metric | Count |
|---|---|
| Total Python files | 220 |
| Total test files | 45 |
| Total test cases | 901 |
| Desktop pages | 11 |
| Detection rules | 12 |
| Desktop services | 19 |
| Enum classes | 18 |

---

## 2. Shared Package — Foundation Layer

**Location:** `shared/aegis_shared/` (45 files)

### 2.1 Enums (`enums.py`)

18 StrEnum classes defining the platform vocabulary:

| Class | Values | Purpose |
|---|---|---|
| `EventCategory` | HOST, NETWORK, DETECTION, CORRELATION, RESPONSE, SYSTEM | Event classification |
| `EventType` | 30+ values across host/network/detection/correlation/response/system | Specific event types |
| `Severity` | INFO, LOW, MEDIUM, HIGH, CRITICAL | Severity ranking (0-4) |
| `SourceKind` | AGENT, SENSOR, BACKEND, ML_ENGINE, RESPONSE_ENGINE, CORRELATOR | Event origin |
| `Platform` | WINDOWS, LINUX, MACOS, UNKNOWN | Operating system |
| `NetworkDirection` | INBOUND, OUTBOUND, LATERAL, UNKNOWN | Traffic direction |
| `TransportProtocol` | TCP, UDP, ICMP, OTHER | Transport layer |
| `AddressFamily` | IPV4, IPV6, UNIX, OTHER, UNKNOWN | Address family |
| `FileType` | REGULAR, DIRECTORY, SYMLINK, OTHER | File type |
| `HashStatus` | HASHED, SKIPPED_SIZE, PERMISSION_DENIED, UNSUPPORTED, ERROR, NOT_APPLICABLE | Hash status |
| `AlertStatus` | OPEN, ACKNOWLEDGED, CLOSED, SUPPRESSED | Alert lifecycle |
| `IncidentStatus` | OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE | Incident lifecycle |
| `IndicatorType` | IP, DOMAIN, FILE_HASH | IOC type |
| `ResponseMode` | MONITOR, DRY_RUN, ENFORCE | Response mode |
| `ActionType` | LOG_ONLY, NOTIFY, RATE_LIMIT, BLOCK_IP, UNBLOCK_IP, BLOCK_PORT, QUARANTINE_FILE, KILL_PROCESS, HOST_ISOLATE, HOST_RESTORE | Response actions |
| `ActionStatus` | PROPOSED, APPROVED, DENIED, EXECUTED, FAILED, ROLLED_BACK | Action lifecycle |
| `RiskBand` | NEGLIGIBLE, LOW, ELEVATED, HIGH, SEVERE | Risk bands |
| `RiskLevel` | INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL | Risk levels |

### 2.2 SecurityEvent Model (`events.py`)

Frozen Pydantic model — immutable, no extra fields allowed.

```
SecurityEvent
├── Identity: event_id, schema_version, event_type, category, severity
├── Time: timestamp, ingested_at
├── Provenance: source (SourceRef), host (HostRef), actor (ActorRef)
├── Context Blocks:
│   ├── network (NetworkContext) — 19 fields: 5-tuple, flow_id, volume, domain
│   ├── socket (SocketContext) — local/port/protocol/status
│   ├── process (ProcessContext) — pid/name/path/command_line/hashes
│   ├── file (FileContext) — path/operation/type/size/hashes/yara
│   ├── risk (RiskAssessment) — score/model/factors/band
│   └── correlation (CorrelationRef) — incident_id/related_events
└── Extensibility: message, labels, raw
```

**Factory:** `SecurityEvent.create()` — derives category from event_type automatically.

### 2.3 Detection Engine (`detection/`)

#### Per-Event Rules (6)

| Rule ID | Class | Severity | Trigger |
|---|---|---|---|
| `AEGIS-LISTEN-001` | `SuspiciousListeningPortRule` | MEDIUM | `PORT_LISTENING` (TCP on suspicious port) |
| `AEGIS-FILE-001` | `SensitiveFileModificationRule` | HIGH | `FILE_MODIFIED` (matches sensitive path) |
| `AEGIS-EXEC-001` | `ExecutableCreationRule` | MEDIUM | `FILE_CREATED` (.exe in watched path) |
| `AEGIS-PROC-001` | `SuspiciousProcessPathRule` | HIGH | `PROCESS_STARTED` (from suspicious path) |
| `AEGIS-NET-001` | `SuspiciousNetworkEndpointRule` | HIGH | `NETWORK_PACKET`/`FLOW_SUMMARY` (bad endpoint) |
| `AEGIS-NET-002` | `HighNetworkVolumeRule` | MEDIUM | `FLOW_SUMMARY` (exceeds volume threshold) |

#### Behavioral Rules (4)

| Rule ID | Window Metric | Threshold |
|---|---|---|
| `AEGIS-NET-003` | Distinct flows in window | Flow burst |
| `AEGIS-NET-004` | Repeated same src→dst | Repeated communication |
| `AEGIS-NET-005` | Distinct destinations from source | Destination fanout |
| `AEGIS-NET-006` | Distinct ports from source | Port breadth |

#### Advanced Rules (2)

| Rule ID | Evaluated By |
|---|---|
| `AEGIS-IOC-001` | `IOCMatcher` (threat intel) |
| `AEGIS-NET-007` | `SuspiciousCommunicationAnalyzer` (multi-signal) |

#### DetectionEngine API

```python
engine = DetectionEngine.from_settings(settings)
findings = engine.evaluate(event)           # Single event
findings = engine.evaluate_many(events)     # Multiple events
```

### 2.4 Risk Engine (`risk/`)

#### Scoring Algorithm (Version 1)

```
Per-finding contribution:
  weight[INFO] = 0
  weight[LOW] = 5
  weight[MEDIUM] = 15
  weight[HIGH] = 30
  weight[CRITICAL] = 50
  contribution = min(weight[severity], max_per_finding)

Total = sum(all contributions)
Score = clamp(0, total, 100)

Level mapping:
  score >= 80 → CRITICAL
  score >= 60 → HIGH
  score >= 40 → MEDIUM
  score >= 20 → LOW
  else       → INFORMATIONAL
```

#### RiskEngine API

```python
engine = RiskEngine(settings)
assessment = engine.assess(event, findings, anomaly_signal=None)
assessments = engine.assess_many(items, anomaly_signals=None)
```

### 2.5 Correlation Engine (`correlation/`)

#### IncidentCorrelator

Groups related findings into incidents:
- Groups by `host_id`
- Clusters within `window_seconds` time window
- Requires `min_findings` to create incident
- Deterministic incident IDs: `INC-{sha1[:16]}`

#### HostNetworkCorrelator

Cross-domain correlation:
- Finds hosts with both host AND network findings
- Creates `HostNetworkCorrelation` objects
- Deterministic IDs: `HNC-{sha1[:16]}`

### 2.6 Pipeline (`pipeline/`)

- Bounded in-memory event buffer
- Sequence-cursor based (never drains, desktop observes read-only)
- Deduplication by event_id
- Configurable max capacity

### 2.7 Threat Intel (`threat_intel/`)

- `IOCMatcher`: matches observables against local indicators
- Supports IP, DOMAIN, FILE_HASH indicator types
- Returns `IOCMatch` objects with confidence scores

### 2.8 Assets (`assets/`)

- `AssetRegistry`: tracks hosts, services, peers
- Deterministic host identity from inventory
- IP address tracking across events

---

## 3. Agent Package — Host Monitoring

**Location:** `agent/aegis_agent/` (29 files)

### 3.1 Process Monitor (`monitors/process/`)

| File | Purpose |
|---|---|
| `monitor.py` | `ProcessMonitor` — snapshot-diffing orchestrator |
| `collector.py` | psutil-based process collection |
| `models.py` | `ProcessSnapshot`, `ProcessChanges`, `ProcessRecord` |
| `events.py` | SecurityEvent builders for process events |
| `commandline.py` | Command-line analysis utilities |

**Architecture:**
```
psutil.process_iter()
    → current snapshot
    → Diff with baseline
    → ProcessChanges{started=[...], stopped=[...]}
    → SecurityEvents
```

**Key Model:**
```python
ProcessChanges(
    started: tuple[ProcessRecord, ...],  # New processes
    stopped: tuple[ProcessRecord, ...],  # Terminated processes
)
```

### 3.2 Port Monitor (`monitors/port/`)

| File | Purpose |
|---|---|
| `monitor.py` | `PortMonitor` — snapshot-diffing orchestrator |
| `collector.py` | psutil-based connection collection |
| `models.py` | `PortSnapshot`, `PortChanges`, `PortRecord` |
| `events.py` | SecurityEvent builders for port events |
| `addressing.py` | Address-family handling utilities |

**Architecture:**
```
psutil.net_connections()
    → current snapshot
    → Diff with baseline
    → PortChanges{started=[...], stopped=[...]}
    → SecurityEvents
```

### 3.3 File Integrity Monitor (`monitors/file_integrity/`)

| File | Purpose |
|---|---|
| `monitor.py` | `FileIntegrityMonitor` — snapshot-diffing with SHA-256 |
| `collector.py` | File system scanning and hashing |
| `models.py` | `FileSnapshot`, `FileChanges`, `FileModification` |
| `events.py` | SecurityEvent builders for file events |

**Architecture:**
```
Scan configured paths
    → Current snapshot with SHA-256 hashes
    → Diff with baseline
    → FileChanges{created=[...], modified=[...], deleted=[...]}
    → SecurityEvents
```

**Key Features:**
- Streaming SHA-256 (memory-efficient)
- Path pattern matching (glob support)
- Size-based skip optimization

### 3.4 System Inventory (`inventory/`)

| File | Purpose |
|---|---|
| `collector.py` | `SystemInventory` — host identity collection |
| `identity.py` | Host identity resolution |
| `models.py` | Inventory data models |

**Collected Data:** hostname, platform, OS, architecture, CPU count, memory, boot time, Python version, agent version.

---

## 4. Network Sensor — Packet Capture

**Location:** `network-sensor/aegis_network_sensor/` (14 files)

### 4.1 Packet Capture (`capture/__init__.py`)

**Class:** `PacketCapture`

```python
capture = PacketCapture(
    interface="Wi-Fi",
    packet_filter="(ip or ip6) and not port 5353 ...",
    promiscuous=False,
)
capture.capture(
    count=50,
    on_packet=handle_func,
    timeout=0.15,
)
```

**Key Points:**
- `store=False` — scapy retains nothing in RAM
- `timeout` — prevents blocking the main thread
- `filter` — BPF filter drops noise at driver level

### 4.2 Network Sensor (`sensor.py`)

**Class:** `NetworkSensor`

```python
sensor = NetworkSensor(settings)
summary = sensor.capture()   # One bounded capture cycle
```

**Pipeline:**
```
PacketCapture → normalize_packet → PacketRecord → FlowAggregator → Pipeline
```

### 4.3 Packet Normalization (`normalization.py`)

**Key Functions:**

| Function | Purpose |
|---|---|
| `normalize_packet()` | Main entry: raw scapy packet → PacketRecord |
| `compute_flow_id()` | Deterministic flow ID from 5-tuple |
| `detect_direction()` | INBOUND/OUTBOUND based on local addresses |

**What We Extract (Headers Only):**
```python
PacketRecord(
    timestamp, interface, ip_version,
    src_ip, dst_ip, protocol,
    src_port, dst_port, packet_length,
    direction, flow_id,
)
```

**What We NEVER Read:**
- ❌ Payload data
- ❌ Application content
- ❌ Credentials
- ❌ HTTP bodies
- ❌ DNS queries (beyond header)

### 4.4 Flow Aggregation (`flows/aggregator.py`)

**Class:** `FlowAggregator`

```python
aggregator = FlowAggregator(max_flows=4096)
aggregator.observe_many(packet_records)
changed = aggregator.drain_changed()  # Only changed flows
all_flows = aggregator.snapshot()     # All tracked flows
```

**Key Methods:**
| Method | Purpose |
|---|---|
| `observe(record)` | Fold one packet into its flow |
| `observe_many(records)` | Fold many packets |
| `drain_changed()` | Return only changed flows (batching primitive) |
| `snapshot()` | Return all tracked flows |
| `clear()` | Drop all flows |

**FlowRecord Model:**
```python
FlowRecord(
    flow_id, ip_version, protocol,
    src_ip, dst_ip, src_port, dst_port,
    direction, interface,
    packet_count, byte_count,
    first_seen, last_seen,
)
```

---

## 5. ML Engine — Anomaly Detection

**Location:** `ml-engine/aegis_ml_engine/` (9 files)

### 5.1 Network Anomaly Model (`anomaly/model.py`)

**Class:** `NetworkAnomalyModel` (Isolation Forest)

```python
model = NetworkAnomalyModel(contamination=0.1)
model.fit(features)
result = model.score(feature)
```

**Feature Vector (6 features):**
```python
NetworkBehaviorFeatures(
    packet_count, byte_count, duration_ms,
    packets_per_second, bytes_per_second,
    average_packet_size,
)
```

**Scoring:**
```
anomaly_score = 1 / (1 + decision_function)
is_anomaly = anomaly_score > 0.5
```

### 5.2 Host Anomaly Model (`anomaly/host_model.py`)

**Class:** `HostAnomalyModel` (Isolation Forest)

**Feature Vector (10 features):**
```python
HostBehaviorFeatures(
    process_count, listening_port_count, file_change_count,
    new_process_count, terminated_process_count,
    new_listening_port_count, removed_listening_port_count,
    file_created_count, file_modified_count, file_deleted_count,
)
```

### 5.3 Feature Extraction (`features/`)

| File | Purpose |
|---|---|
| `flow_features.py` | `extract_flow_features()` — FlowRecord → NetworkBehaviorFeatures |
| `host_features.py` | `extract_host_features()` — Host telemetry → HostBehaviorFeatures |

---

## 6. Runtime — Orchestrator

**Location:** `runtime/aegis_runtime/runtime.py` (1309 lines)

### 6.1 AegisRuntime Class

```python
runtime = AegisRuntime()
runtime.start()           # Initialize all monitors
result = runtime.poll_once()  # One bounded cycle
runtime.stop()            # Cleanup
```

### 6.2 poll_once() — The Complete Cycle

```
Phase 1: Host Monitors
    process_monitor.poll() → ProcessChanges
    port_monitor.poll() → PortChanges
    file_monitor.poll() → FileChanges
    → Submit to pipeline

Phase 2: Network Capture
    network_sensor.capture()
    → scapy.sniff(50 packets, 0.15s timeout)
    → normalize → aggregate → pipeline

Phase 3: Pipeline Cursor
    peek() → new envelopes since last cursor
    → Update cursor position

Phase 4: Asset Registry
    Update host/port/network assets

Phase 5: Anomaly Scoring
    NetworkAnomalyModel.score() on flows
    HostAnomalyModel.score() on host behavior
    → AnomalySignal objects

Phase 6: Behavior Findings
    NetworkBehaviorAnalyzer → AEGIS-NET-003/004/005/006

Phase 7: IOC Matching
    IOCMatcher → AEGIS-IOC-001

Phase 8: Detection + Risk
    DetectionEngine.evaluate() → Findings
    RiskEngine.assess() → RiskAssessments

Phase 9: Communication Analysis
    SuspiciousCommunicationAnalyzer → AEGIS-NET-007

Phase 10: Correlation
    HostNetworkCorrelator → Cross-domain links
    IncidentCorrelator → Incidents
```

### 6.3 Key Properties

| Property | Type | Description |
|---|---|---|
| `state` | `RuntimeState` | STOPPED or RUNNING |
| `is_running` | `bool` | Convenience check |
| `pipeline` | `RuntimeEventPipeline` | Event buffer |
| `detection_engine` | `DetectionEngine` | Rule engine |
| `risk_engine` | `RiskEngine` | Scoring engine |
| `network_flows` | `tuple[FlowRecord, ...]` | Current flows |
| `network_capture_state` | `str` | "active" / "inactive" / "error" |
| `network_capture_error` | `str \| None` | Last capture error |

---

## 7. Response Engine — IPS Actions

**Location:** `response-engine/aegis_response_engine/` (17 files)

### 7.1 Policy Engine (`policy/engine.py`)

**Class:** `ResponsePolicyEngine`

```python
engine = ResponsePolicyEngine(settings)
decision = engine.evaluate(request)
# ResponseDecision.ALLOWED / DENIED / REQUIRES_APPROVAL / NOT_APPLICABLE
```

**Decision Flow:**
```
1. Action type supported? → NOT_APPLICABLE if not
2. Target valid? → DENIED if not
3. Context check → DENIED if not met
4. Engine enabled? → DENIED if not
5. Action in allowed list? → DENIED if not
6. Risk threshold met? → REQUIRES_APPROVAL if high
7. Dry-run mode? → REQUIRES_APPROVAL
8. → ALLOWED
```

### 7.2 Response Executor (`executors/executor.py`)

**Class:** `ResponseExecutor`

```python
executor = ResponseExecutor(firewall_adapter)
result = executor.execute(request, workflow_status=APPROVED, dry_run=False)
```

**5 Guards Before Execution:**
1. Action must be `BLOCK_IP`
2. Workflow status must be `APPROVED`
3. Policy must permit
4. If dry_run, would_apply=True
5. Target must be valid IP

### 7.3 Windows Firewall Adapter (`firewall/windows.py`)

**Class:** `WindowsFirewallAdapter`

```python
adapter = WindowsFirewallAdapter()
adapter.block_ip("192.168.1.100")     # Creates firewall rule
adapter.unblock_ip("192.168.1.100")   # Removes firewall rule
adapter.is_blocked("192.168.1.100")   # Checks rule exists
```

**Implementation:**
- Uses `netsh advfirewall` (no shell=True)
- Idempotent operations
- Rule prefix: `AEGIS-BLOCK-IP-`
- Timeout protection on all subprocess calls

### 7.4 Response Workflow (`desktop/aegis_desktop/services/response_workflow.py`)

**States:**
```
draft → dry_run_completed → pending_approval
    → approved → executed / execution_failed
    → rejected (terminal)
    → cancelled (from any pre-approved state)
```

**Key API:**
```python
mgr = get_workflow_manager()
mgr.create_request(action, target, finding_ids, ...)
mgr.run_dry_run(request_id)
mgr.request_approval(request_id)
mgr.approve(request_id)
mgr.reject(request_id, reason)
mgr.execute(request_id)
```

---

## 8. Desktop Console — SOC UI

**Location:** `desktop/aegis_desktop/` (39 files)

### 8.1 Application Bootstrap (`app.py`)

```python
from aegis_desktop.app import run
run()  # Creates QApplication, splash screen, MainWindow
```

### 8.2 Main Window (`window.py`)

- `QMainWindow` with header, sidebar, stacked widget, status bar
- `QTimer` drives monitoring cycle (2000ms interval)
- `MonitoringController` bridges GUI to runtime

### 8.3 Navigation (`navigation.py`)

11 sidebar pages:

| Key | Title | Description |
|---|---|---|
| `dashboard` | Dashboard | Overview console |
| `assets` | Assets | Asset inventory |
| `processes` | Processes | Process monitoring |
| `network` | Network | Port/flow monitoring |
| `files` | File Integrity | FIM changes |
| `events` | Events | Event feed |
| `detections` | Detections | Findings |
| `incidents` | Incidents | Correlated incidents |
| `response` | Response Center | IPS workflow |
| `risk` | Risk | Risk assessments |
| `settings` | Settings | Configuration |

### 8.4 Dashboard Page (`pages/dashboard.py` — 1650 lines)

**Visible Sections:**
1. **Toolbar** — Refresh + timestamp
2. **System Health Bar** — Compact dot indicators
3. **Security Posture** — 3 premium cards (Risk, Threats, Actions)
4. **Threat Feed** — Scrollable threat investigation feed
5. **Live Network Activity** — Sortable packet table
6. **Network Summary** — 6 metric cards
7. **Contextual Telemetry** — 2 line graphs

**Hidden Containers (test backward-compat):**
- Findings, Incidents, Explanation, Relationships
- Risk gauge, Alert container
- Host card, Network card

**Key Methods:**
| Method | Purpose |
|---|---|
| `build_content()` | Constructs entire layout |
| `refresh_live()` | QTimer tick handler |
| `_update_posture_cards()` | Updates risk/threat/action cards |
| `_update_health_bar()` | Syncs compact indicators |
| `_update_threat_feed()` | Rebuilds threat feed |
| `_update_live_network()` | Populates network table |
| `_update_graphs()` | Pushes telemetry to graphs |
| `_sample_tlemetry()` | Captures telemetry sample |
| `_detect_alerts()` | Feeds AlertService |

### 8.5 Other Pages

| Page | Key Features |
|---|---|
| `AssetsPage` | Asset rows, services, peers, network identity |
| `ProcessesPage` | Process snapshot, started/stopped changes |
| `NetworkPage` | Port table, flow table, monitoring status |
| `FilesPage` | FIM changes, file integrity config |
| `EventsPage` | Event feed, pipeline posture |
| `DetectionsPage` | Finding rows, behavioral analysis, communication patterns |
| `IncidentsPage` | Incident rows, finding/event relationships |
| `ResponseCenterPage` | Policy view, workflow requests, audit trail |
| `RiskPage` | Risk assessments, anomaly signals |
| `SettingsPage` | Configuration viewer (all settings) |

### 8.6 Theme (`theme.py`)

Dark SOC theme:
```
Background:   #0d1117 (deep dark)
Surface:      #161b22 (card background)
Border:       #30363d
Text:         #e6edf3 (primary)
Text Muted:   #7d8590
Accent:       #00ff41 (green)
OK:           #00ff41 (green)
Warn:         #d29922 (amber)
High:         #f85149 (red)
Critical:     #ff4444 (bright red)
Info:         #58a6ff (blue)
```

### 8.7 Services (19 files)

Read-only adapters bridging runtime data to UI:

| Service | Provides |
|---|---|
| `dashboard.py` | `DashboardSnapshot`, `InventoryView`, `MonitorState` |
| `detections.py` | `FindingRow`, `DetectionPosture`, `InvestigationView` |
| `incidents.py` | `IncidentRow`, `IncidentSnapshotView` |
| `risk.py` | `RiskPosture`, `RiskSnapshotView` |
| `response_workflow.py` | `ResponseRequestView`, approval workflow |
| `response_policy.py` | `ResponsePolicyView` |
| `alerts.py` | `AlertService`, `SecurityAlert` |
| `telemetry.py` | `TelemetrySample`, `TelemetryHistory` |
| `live_network.py` | `LiveNetworkActivity`, `LiveNetworkTableModel` |
| `monitoring.py` | `MonitoringController`, `MonitoringStatus` |
| `network.py` | `PortRow`, `PortSnapshotView` |
| `processes.py` | `ProcessRow`, `ProcessSnapshotView` |
| `files.py` | `FileRow`, `FileSnapshotView` |
| `events.py` | `EventRow`, `EventSnapshotView` |
| `assets.py` | `AssetRow`, `AssetSnapshotView` |
| `settings.py` | `SettingsView`, `ConfigSection` |
| `correlation.py` | `CorrelationEvidence` |
| `threat_intel.py` | `IOCMatchView`, `ThreatIntelView` |

---

## 9. Backend — API Layer

**Location:** `backend/aegis_backend/` (16 files, scaffolded)

```
FastAPI application
    ├── /api/v1/health  — Health check endpoint
    ├── PostgreSQL + SQLAlchemy (configured, not active)
    └── CORS middleware configured
```

**Status:** Scaffolded for future multi-host deployment. Currently not used by desktop console.

---

## 10. Configuration System

### 10.1 Base Settings (`shared/aegis_shared/config.py`)

All settings extend `AegisSettings` (pydantic-settings):
- `env_prefix = "AEGIS_"`
- `env_file = ".env"`
- Environment variables override defaults

### 10.2 Sensor Settings (`network-sensor/aegis_network_sensor/config.py`)

| Field | Default | Env Var |
|---|---|---|
| `interface` | `""` | `AEGIS_SENSOR_INTERFACE` |
| `capture_enabled` | `False` | `AEGIS_SENSOR_CAPTURE_ENABLED` |
| `capture_filter` | BPF string | `AEGIS_SENSOR_CAPTURE_FILTER` |
| `max_packets_per_run` | `200` | `AEGIS_SENSOR_MAX_PACKETS_PER_RUN` |
| `capture_timeout_seconds` | `0.2` | `AEGIS_SENSOR_CAPTURE_TIMEOUT_SECONDS` |
| `promiscuous` | `False` | `AEGIS_SENSOR_PROMISCUOUS` |
| `flow_window_seconds` | `10` | `AEGIS_SENSOR_FLOW_WINDOW_SECONDS` |
| `local_addresses` | `[]` | `AEGIS_SENSOR_LOCAL_ADDRESSES` |

### 10.3 Agent Settings (`agent/aegis_agent/config.py`)

| Field | Default | Env Var |
|---|---|---|
| `enable_process_monitor` | `False` | `AEGIS_AGENT_ENABLE_PROCESS_MONITOR` |
| `enable_port_monitor` | `False` | `AEGIS_AGENT_ENABLE_PORT_MONITOR` |
| `enable_file_integrity` | `False` | `AEGIS_AGENT_ENABLE_FILE_INTEGRITY` |
| `file_integrity_paths` | `[]` | `AEGIS_AGENT_FILE_INTEGRITY_PATHS` |
| `event_buffer_max_events` | `5000` | `AEGIS_AGENT_EVENT_BUFFER_MAX_EVENTS` |

### 10.4 Detection Settings (`shared/aegis_shared/detection/config.py`)

| Field | Default | Env Var |
|---|---|---|
| `enabled` | `True` | `AEGIS_DETECTION_ENABLED` |
| `suspicious_ports` | `[]` | `AEGIS_DETECTION_SUSPICIOUS_PORTS` |
| `sensitive_file_patterns` | `[]` | `AEGIS_DETECTION_SENSITIVE_FILE_PATTERNS` |
| `suspicious_process_paths` | `[]` | `AEGIS_DETECTION_SUSPICIOUS_PROCESS_PATHS` |
| `suspicious_endpoints` | `[]` | `AEGIS_DETECTION_SUSPICIOUS_ENDPOINTS` |

### 10.5 Risk Settings (`shared/aegis_shared/risk/config.py`)

| Field | Default | Env Var |
|---|---|---|
| `severity_weights` | `{INFO:0, LOW:5, MEDIUM:15, HIGH:30, CRITICAL:50}` | `AEGIS_RISK_SEVERITY_WEIGHTS` |
| `max_contribution_per_finding` | `50` | `AEGIS_RISK_MAX_CONTRIBUTION_PER_FINDING` |
| `threshold_low` | `20` | `AEGIS_RISK_THRESHOLD_LOW` |
| `threshold_medium` | `40` | `AEGIS_RISK_THRESHOLD_MEDIUM` |
| `threshold_high` | `60` | `AEGIS_RISK_THRESHOLD_HIGH` |
| `threshold_critical` | `80` | `AEGIS_RISK_THRESHOLD_CRITICAL` |

### 10.6 Response Settings (`response-engine/aegis_response_engine/config.py`)

| Field | Default | Env Var |
|---|---|---|
| `mode` | `MONITOR` | `AEGIS_RESPONSE_MODE` |
| `dry_run` | `True` | `AEGIS_RESPONSE_DRY_RUN` |
| `require_approval` | `True` | `AEGIS_RESPONSE_REQUIRE_APPROVAL` |
| `enforcement_enabled` | `False` | `AEGIS_RESPONSE_ENFORCEMENT_ENABLED` |

### 10.7 ML Settings (`ml-engine/aegis_ml_engine/config.py`)

| Field | Default | Env Var |
|---|---|---|
| `contamination` | `0.1` | `AEGIS_ML_CONTAMINATION` |
| `risk_threshold` | `0.5` | `AEGIS_ML_RISK_THRESHOLD` |
| `host_baseline_min_observations` | `20` | `AEGIS_ML_HOST_BASELINE_MIN_OBSERVATIONS` |

---

## 11. Test Suite

### 11.1 Summary

| Metric | Count |
|---|---|
| Test files | 45 |
| Test cases | 901 |
| Packages tested | 8 |

### 11.2 Test Files by Package

| Package | Test Files | Key Tests |
|---|---|---|
| shared | 12 | detection, risk, correlation, events, pipeline, threat_intel, assets, communication, behavior |
| agent | 5 | process_monitor, port_monitor, file_integrity, inventory, event_pipeline |
| network-sensor | 4 | capture, normalization, flows, config |
| ml-engine | 3 | anomaly_model, flow_features, host_features |
| runtime | 2 | runtime_lifecycle, runtime_anomaly |
| response-engine | 4 | firewall, policy, workflow, audit |
| desktop | 14 | dashboard, all 11 pages, theme, soc_console, live_soc |
| backend | 1 | health |

### 11.3 Running Tests

```bash
# All tests
pytest tests/ -x -q

# Specific package
pytest tests/test_dashboard.py tests/test_network_sensor.py -x -q

# Verbose
pytest tests/test_detection.py -v

# Skip integration tests
pytest tests/ -x -q -m "not integration"
```

---

## Appendix: File Tree

```
aegis-idps/
├── shared/aegis_shared/              # 45 files
│   ├── enums.py                      # 18 StrEnum classes
│   ├── events.py                     # SecurityEvent + 9 context models
│   ├── config.py                     # Base settings
│   ├── logging.py                    # Structured logging
│   ├── version.py                    # Version constant
│   ├── detection/                    # Engine + 12 rules
│   │   ├── engine.py                 # DetectionEngine
│   │   ├── rules.py                  # 6 per-event rule classes
│   │   ├── behavior.py               # 4 behavioral rules
│   │   ├── communication.py          # Multi-signal analyzer
│   │   ├── models.py                 # DetectionFinding
│   │   └── config.py                 # DetectionSettings
│   ├── risk/                         # Risk scoring
│   │   ├── engine.py                 # RiskEngine
│   │   ├── scoring.py                # Scoring functions
│   │   ├── models.py                 # RiskAssessment
│   │   └── config.py                 # RiskSettings
│   ├── correlation/                  # Incident correlation
│   │   ├── engine.py                 # IncidentCorrelator
│   │   ├── host_network.py           # HostNetworkCorrelator
│   │   ├── models.py                 # SecurityIncident
│   │   └── config.py                 # CorrelationSettings
│   ├── pipeline/                     # Event buffer
│   │   ├── pipeline.py               # EventPipeline
│   │   ├── buffer.py                 # Bounded buffer
│   │   └── validation.py             # Event validation
│   ├── threat_intel/                 # IOC matching
│   │   ├── matcher.py                # IOCMatcher
│   │   ├── models.py                 # IOCMatch
│   │   └── config.py                 # ThreatIntelSettings
│   ├── assets/                       # Asset registry
│   │   ├── registry.py               # AssetRegistry
│   │   └── models.py                 # Asset models
│   └── baseline/                     # Observation baseline
│       └── baseline.py               # BoundedObservationBaseline
│
├── agent/aegis_agent/                # 29 files
│   ├── config.py                     # AgentSettings
│   ├── monitors/
│   │   ├── process/                  # ProcessMonitor
│   │   ├── port/                     # PortMonitor
│   │   └── file_integrity/           # FileIntegrityMonitor
│   └── inventory/                    # SystemInventory
│
├── network-sensor/aegis_network_sensor/  # 14 files
│   ├── config.py                     # SensorSettings
│   ├── sensor.py                     # NetworkSensor
│   ├── normalization.py              # Packet normalization
│   ├── capture/__init__.py           # PacketCapture
│   └── flows/                        # FlowAggregator
│
├── ml-engine/aegis_ml_engine/        # 9 files
│   ├── config.py                     # MLSettings
│   ├── anomaly/
│   │   ├── model.py                  # NetworkAnomalyModel
│   │   └── host_model.py             # HostAnomalyModel
│   └── features/
│       ├── flow_features.py          # Flow feature extraction
│       └── host_features.py          # Host feature extraction
│
├── runtime/aegis_runtime/            # 4 files
│   ├── runtime.py                    # AegisRuntime (1309 lines)
│   ├── pipeline.py                   # RuntimeEventPipeline
│   └── models.py                     # RuntimeState, PollResult
│
├── response-engine/aegis_response_engine/  # 17 files
│   ├── config.py                     # ResponseSettings
│   ├── policy/engine.py              # ResponsePolicyEngine
│   ├── executors/executor.py         # ResponseExecutor
│   ├── firewall/
│   │   ├── base.py                   # FirewallAdapter ABC
│   │   └── windows.py                # WindowsFirewallAdapter
│   └── audit/                        # Audit trail
│
├── desktop/aegis_desktop/            # 39 files
│   ├── app.py                        # Application bootstrap
│   ├── window.py                     # MainWindow
│   ├── theme.py                      # Dark SOC theme
│   ├── splash.py                     # Splash screen
│   ├── navigation.py                 # Sidebar (11 pages)
│   ├── pages/
│   │   ├── dashboard.py              # DashboardPage (1650 lines)
│   │   ├── assets.py                 # AssetsPage
│   │   ├── processes.py              # ProcessesPage
│   │   ├── network.py                # NetworkPage
│   │   ├── files.py                  # FilesPage
│   │   ├── events.py                 # EventsPage
│   │   ├── detections.py             # DetectionsPage
│   │   ├── incidents.py              # IncidentsPage
│   │   ├── response_center.py        # ResponseCenterPage
│   │   ├── risk.py                   # RiskPage
│   │   ├── settings.py               # SettingsPage
│   │   ├── graphs.py                 # LineGraphWidget, RiskGaugeWidget
│   │   └── base.py                   # BasePage
│   └── services/                     # 19 service adapters
│
├── backend/aegis_backend/            # 16 files (scaffolded)
│   ├── main.py                       # FastAPI app
│   └── api/v1/                       # REST endpoints
│
├── tests/                            # 45 files, 901 tests
├── docs/                             # Documentation
├── scripts/                          # Bootstrap scripts
├── .env                              # Runtime configuration
├── pyproject.toml                    # Project metadata
└── README.md                         # Project readme
```
