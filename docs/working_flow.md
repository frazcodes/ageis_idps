# Aegis IDPS — End-to-End Working Flow

> Companion guide that explains what happens from **launch** until you see data on every page, and how the response (IPS) pipeline completes a kill-chain. See [`architecture.md`](./architecture.md) for the component-level map.

---

## TL;DR

1. **Launch** → splash screen → read-only window appears (monitoring **off**)
2. **Start Monitoring** → Preflight checklist (admin, Npcap driver, ML engine)
3. **Runtime starts** → collects events from endpoint agents and/or packet capture
4. **Every 2 s**: detect → score → correlate → publish findings / incidents
5. **Each page** pulls from the in-process registries and repaints
6. **Response** (Block IP) needs three human gates: **Dry Run → Approve → Execute**
7. **Demo mode** (`🧪 Simulate Threat`) injects synthetic data through the same pipeline — no real network contact
8. **Stop Monitoring** → clears the live pipelines but leaves demo data visible

---

## 1. Launch & Startup

| Step | What happens | Where |
|---|---|---|
| 1. Entry | `python -m aegis_desktop` calls `main()` → `aegis_desktop.app.run(splash=True)` | `desktop/aegis_desktop/__main__.py:12` |
| 2. App bootstrap | Creates one process-wide `QApplication`, applies the enterprise dark QSS theme once | `desktop/aegis_desktop/app.py:32` |
| 3. Splash | ~2.8 s animated loading screen, then reveals the main window | `desktop/aegis_desktop/splash.py` |
| 4. Main window | Builds header, sidebar (11 pages), `QStackedWidget` page stack, and a 2000 ms `QTimer` — **nothing is started yet** | `desktop/aegis_desktop/window.py:49` |
| 5. Status bar | Initially shows `Monitoring disabled \| UI infrastructure only \| no response actions` | `window.py:39` |

> ⚠️ Opening the app alone does **not** load any security engine, driver, or packet capture. All heavy imports are lazy.

---

## 2. After You Click **Start Monitoring**

The button is wired to `MainWindow.toggle_monitoring` which either starts or stops the runtime. When **Start** is pressed the following sequence executes:

### 2.1 Preflight diagnostics

```
[PreflightDialog]
   ├─ Admin privileges?      ✅ / ⚠️ / ❌
   ├─ Network driver (Npcap)? ✅ / ⚠️ / ❌
   └─ ML engine ready?        ✅ / ⚠️ / ❌
```

* Driven by `preflight.py` (one-shot per tick).  
* Controlled by env var `AEGIS_PREFLIGHT_ENABLED` — set to `0/false/off` to skip the gate (used by automated tests).  
* If any required check fails, the dialog still lets you start but records the error as a warning you can review later.  
* On cancel (Esc / Cancel), monitoring does **not** start.

### 2.2 Runtime start (`AegisRuntime.start()`)

| Action | Detail | Source |
|---|---|---|
| Create monitors | Only the monitors **explicitly enabled in config** are instantiated (see § 6 defaults) | `runtime/aegis_runtime/runtime.py:364` |
| Publish to registries | Sets the single `pipeline`, `detection engine`, `risk engine`, and clears stale incidents/correlations/assets | same, lines 377–384 |
| Mark RUNNING | Internal state moves to `RuntimeState.RUNNING` | same, line 395 |

> The runtime **never touches the network on start** — capture only runs inside the timed poll loop below.

### 2.3 Poll loop (fires every 2000 ms)

```
QTimer._on_tick
   ├── controller.poll()
   │     └── runtime.poll_once()
   ├── _update_monitoring_ui()          ← button text, header badge, status bar
   └── _refresh_current_page_live()     ← current page repaint
```

**One `poll_once` cycle** (`runtime.py:440`):

```
_poll_host_monitors()         ← agent polls (process / port / file-integrity)
   └── pipeline.submit_monitor_changes(...)

_poll_network_sensor()        ← Npcap capture if enabled
   ├── network.capture()
   └── drain_sensor_into_pipeline()
_submit_flow_events()         ← aggregated flow summaries as canonical events

_envelopes = pipeline.peek(cursor..newest)

_update_assets(events)        ← identity/context lookup
_score_network_flows(events)  ← ML anomaly model on flows
_update_host_behavior(errors) ← ML anomaly model on host

behavior_findings = _behavior_findings(events)   ← behavioral network rules
ioc_matches       = _ioc_matches(events)         ← IOC matching
findings, assessments = _detect_and_assess(...)  ← rule-based detection + risk scoring

_correlate(events)           ← IncidentCorrelator + HostNetworkCorrelator
```

**Registry publishes happening inside each cycle** (best-effort, never aborts the loop):

| Registry | What is published |
|---|---|
| `active_pipeline` | the canonical event queue |
| `active_engine` | detection engine instance (pages pull current findings) |
| `active_risk_engine` | risk engine instance |
| `active_anomaly_signals` | latest anomaly signal map |
| `active_incidents` | OPEN incidents |
| `active_host_network_correlations` | host ↔ network evidence bonds |
| `active_ioc_matches` | IOC hits |
| `active_asset_snapshot` | best-effort asset identity |

### 2.4 Page repaint (pull-based, no Qt signals)

Every page implements `refresh()` (full snapshot) and optionally `refresh_live()` (fast incremental). The timer calls `refresh_live()` on the visible page each tick. Navigation manually triggers a full refresh via `handle_navigate()`.

> This is intentional: avoids complex signal wiring across 11 independent pages.

---

## 3. Data flow — one observation's life-cycle

```
HOST / NETWORK EVENT ──┐
                       ▼
         aegis_shared.events.SecurityEvent  (immutable, schema-driven)
                       │
                       ▼
             RuntimeEventPipeline  (in-memory, bounded)
                       │
                       ▼
    DetectionEngine.evaluate_many()   ──► DetectionFinding[]   (HIGH / CRITICAL)
                       │
                       ▼
    RiskEngine.assess_many()          ──► RiskAssessment[]
                       │
                       ▼
    IncidentCorrelator()              ──► SecurityIncident (OPEN)
    HostNetworkCorrelator()           ──► HostNetworkCorrelation
                       │
                       ▼
    Desktop services (collect_finding_view, etc.)
                       │
                       ▼
    Table models → QTableView → UI repaint
```

The pipeline is **cursor-based** (`_cursor` in `runtime.py`) so detection/risk only advance over *new* envelopes per cycle; old envelopes remain inspectable in the Events page.

### 3.1 Encrypted Domain Discovery (TLS/SNI Flow)
1. **Packet Capture:** Scapy sniffs raw TCP packets on Port 443.
2. **Zero-Crash Parser:** `extract_tls_sni(payload)` inspects TLS Record 22 / Handshake 1 / Extension 0 (`server_name`) conforming to RFC 6066.
3. **Model & Flow Normalization:** `PacketRecord.sni` is populated. `FlowAggregator.observe()` preserves the domain on bidirectional flows across ACKs/data packets without overwrite.
4. **UI & Event Propagation:** `NetworkContext.domain` carries the hostname into SIEM events, and the Live Network Activity Table displays the domain name next to destination IPs.

### 3.2 Subnet Asset Discovery & MITM Defense (ARP Radar Flow)
1. **Host & Subnet Profiling:** `ArpRadarService` resolves host IP, default gateway, and CIDR subnet range.
2. **Concurrent Active Sweep:** Launches a 64-worker `ThreadPoolExecutor` unicast ping sweep across the `/24` subnet. Unicast frames pass through gateway routers (bypassing Wi-Fi AP Client Isolation and waking up mobile phones from 802.11 DTIM sleep).
3. **Cache Harvesting & Vendor Identification:** Gathers OS ARP table entries (`arp -a`) and matches MAC prefixes against the in-memory IEEE OUI database (Huawei, Vivo Mobile, Samsung, Apple, Realtek, Cisco, etc.).
4. **MITM & Spoofing Defense:** `ArpTracker` tracks IP-to-MAC associations. Any rogue MAC claiming the default gateway IP triggers an immediate `GATEWAY_SPOOFING` crimson alert banner on the `📡 ARP Radar` tab.

---

## 4. Response (IPS) Pipeline

After a finding/incident is correlated, an operator may choose to **respond**. The full workflow lives in `response-engine/` + `desktop/services/response_workflow.py`.

```
CREATE REQUEST (draft)          from Detections page (single finding)
      │                         or Incidents page (incident context)
      ▼
DRY RUN                         ResponseDryRunEngine.simulate()
      │  returns "would_apply"   → policy permits action
      ▼
SUBMIT FOR APPROVAL             status → pending_approval
      │  (auto-triggered when dry-run would apply)
      ▼
APPROVE                         human decision; status → approved
      │  (no execution yet)
      ▼
EXECUTE                         ResponseExecutor → WindowsFirewallAdapter
      │  netsh advfirewall add rule name=AEGIS-BLOCK-IP-<addr>
      │  idempotent: re-checks rule existence
      ▼
VERIFY                          re-reads firewall rule; sets verified flag
      ▼
AUDIT                           ResponseAuditRecord (action, target, status,
                                  decision, dry-run, verification)
      │  persisted in-process audit history
      ▼
UI                              Response Center shows EXECUTED — Windows Firewall — VERIFIED
                                  Audit table shows the record row
```

**Guards checked before execution** (`executor.py`):

| Guard | Condition | Reject reason shown |
|---|---|---|
| Action type | must be `BLOCK_IP` | "action is not supported by Step 30" |
| Workflow state | must be `approved` | "workflow is not approved" |
| Policy decision | must be `allowed` or `requires_approval` | `denied` gets rejected |
| Dry-run result | must be `would_apply` | other dry-run statuses blocked |
| Target kind | must be a valid IP address | non-IP targets rejected |

**Fail-safe**: on failure at any step the entry status becomes `execution_failed`; the firewall is **not modified**. Audit still records the attempt.

---

## 5. Demo / Simulation Path (Step 39)

When **real hardware or policy should not be involved**, the Threat Simulation playbook lets you exercise the entire UI flow against **synthetic data**:

1. Dashboard toolbar → `🧪 Simulate Threat`
2. Pick **External Port Scan** (one HIGH network finding) or **C2 Beaconing** (host + network finding → correlated incident)
3. `threat_sim.run_scenario()` builds fake `SecurityEvent`-like `DetectionFinding` objects tagged `simulated` (RFC 5737 TEST-NET-3 IPs like `185.15.44.17`)
4. Findings flow through the **same services** as real data (alerts, augment-snapshot, detection overlay)
5. For C2: a canned `RiskAssessment(risk_score=91, CRITICAL)` is injected and the real `IncidentCorrelator` produces an OPEN incident
6. A draft **Block IP** request is opened automatically in the response workflow against the simulated attacker IP. The request uses a **demo policy engine** (`response_enabled=True` but approval + dry-run still required) so the full Dry-Run → Approve → Execute path is clickable without changing any global env setting
7. **Stop Monitoring** does **not** erase this data — the demo state lives in separate module-level registries

Tests validate every stage (`tests/test_threat_sim.py`): injection, registries, snapshot overlay, double-count regression, dialog, dashboard action-center integration, cross-page consistency, persistence after stop, and the full response pipeline walk-through.

---

## 6. Safety Defaults (what is off by default)

| Feature | Default | Enabling switch |
|---|---|---|
| Packet capture | **Off** (`sensor.capture_enabled = False`) | `AEGIS_SENSOR_CAPTURE_ENABLED=true` + explicit `AEGIS_SENSOR_INTERFACE=<name>` |
| Agent monitors | **All off** (process / port / file-integrity / YARA) | `AEGIS_AGENT_ENABLE_PROCESS_MONITOR=true`, etc. |
| File integrity paths | **Empty list** | `AEGIS_AGENT_FILE_INTEGRITY_PATHS=C:\folder` |
| Response engine (live) | **Off** (`response_policy.response_enabled = False`) | `AEGIS_RESPONSE_POLICY_RESPONSE_ENABLED=true` |
| Preflight gate | **On** | Set `AEGIS_PREFLIGHT_ENABLED=0` |
| Auto-execute | **Never** | Not available in production; approval always required |

> Everything invasive requires an **explicit human decision** (dry run + approval + Admin session). The default state is strictly read-only.

---

## 7. Component Map (where to find things)

| Concern | Key file(s) |
|---|---|
| App entry & splash | `desktop/aegis_desktop/app.py`, `__main__.py` |
| Main window & timer | `desktop/aegis_desktop/window.py` |
| Preflight checks | `desktop/aegis_desktop/preflight.py` |
| Event pipeline | `runtime/aegis_runtime/pipeline.py`, `models.py` |
| Runtime lifecycle | `runtime/aegis_runtime/runtime.py` (start/stop/poll_once) |
| Detection rules | `shared/aegis_shared/detection/…` |
| Risk scoring | `shared/aegis_shared/risk/…`, `ml-engine/aegis_ml_engine/scoring/…` |
| Correlation | `shared/aegis_shared/correlation/…` |
| Network sensor | `network-sensor/aegis_network_sensor/sensor.py`, `flows/aggregator.py` |
| Response policy | `response-engine/aegis_response_engine/policy/…` |
| Dry-run engine | `response-engine/aegis_response_engine/policy/dryrun.py` |
| Executor + firewall | `response-engine/aegis_response_engine/executors/executor.py`, `firewall/windows.py` |
| Audit trail | `response-engine/aegis_response_engine/audit/history.py` |
| Demo playbooks | `desktop/aegis_desktop/threat_sim.py` |
| Test coverage | `tests/test_*.py` (run `pytest tests/`) |

---

## 8. Quick Reference — Command Flow

```
pip install -e ".[desktop]"                 # install console
python -m aegis_desktop                    # launch
   → preflight dialog                     # admin / Npcap / ML
   → click Start Monitoring               # runtime.start()
   → timer ticks every 2 s                # poll → detect → correlate → refresh
   → watch Dashboard / Detections / Incidents
   → Response Center: dry-run → approve → execute  (admin required)
   → Stop Monitoring                      # clears pipeline; demo data stays
```

Environment overrides go into `.env` (see `.env.example`) or as literal env vars prefixed with `AEGIS_SENSOR_`, `AEGIS_AGENT_`, `AEGIS_RESPONSE_POLICY_`, `AEGIS_PREFLIGHT_ENABLED`.

---

*Generated against codebase HEAD at the time of writing. Line numbers referenced in § 2 / § 3 point to the committed source tree.*
