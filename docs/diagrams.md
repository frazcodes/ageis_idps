# Aegis IDPS — Visual Flow Diagrams

> Readable as plain text AND as Mermaid diagrams (rendered by GitHub / GitLab / VS Code + Mermaid extension).  
> See [`working_flow.md`](./working_flow.md) for the full step-by-step prose.

---

## 1. System Topology

```mermaid
graph TB
    subgraph Desktop["🖥  Aegis Desktop Console"]
        W[MainWindow] -->|QTimer 2 s| Ctrl[MonitoringController]
        Ctrl -->|poll_once| RT[AegisRuntime]
        W -->|start| PF[PreflightDialog]
        W -->|Simulate Threat| DS[Threat Simulation]
        W --> Nav[Navigation: 11 Pages]
    end

    subgraph Runtime["⚙ Aegis Runtime"]
        RT --> D[Detection Engine]
        RT --> R[Risk Engine]
        RT --> C[Correlators]
        RT --> Ioc[IOC Matcher]
        RT --> B[Behavioral Analyzer]
    end

    subgraph Sources["📡 Telemetry Sources"]
        AG[Agent Monitors\nprocess / port / file / YARA]
        NS[Network Sensor\nNpcap + Scapy + FlowAgg]
        DL["Disabled by default\n(opt-in via .env)"]
        AG & NS --> PE[RuntimeEventPipeline]
    end

    subgraph Response["🔒 Response Engine"]
        RE[ResponsePolicyEngine]
        DR[ResponseDryRunEngine]
        EX[ResponseExecutor]
        FW[WindowsFirewallAdapter\nnetsh advfirewall]
        AUD[AuditHistory]
    end

    subgraph Shared["🧩 aegis_shared Contracts"]
        EVT[SecurityEvent schema]
        ENUM[EventCategory / EventType / Severity]
        REG[Active Registries\npipeline / engine / risk / incidents]
    end

    PE --> D & R
    D --> EVT
    R --> EVT
    C --> REG
    RT --> REG
    DS -.->|fake data| D & C
    Nav --- RegPull[collect_*_view() services]
    RegPull --> NAV
    RT -- approved request --> EX
    EX -- netsh rule --> FW
    FW --> AUD
```

---

## 2. Start Monitoring — Sequence

```mermaid
sequenceDiagram
    participant U as 👤 User
    participant UI as 🪟 MainWindow
    participant PF as 🛡 PreflightDialog
    participant MC as ⏱ MonitoringController
    participant RT as 🔄 AegisRuntime
    participant SRC as 📡 Source Monitors
    participant DL as 🚦 Safety Switches

    U->>UI: open app
    Note over UI: nothing starts yet — lazy imports

    U->>UI: click "Start Monitoring"
    UI->>PF: show diagnostics
    alt AEGIS_PREFLIGHT_ENABLED ≠ 0
        PF->>DL: check Admin privileges
        PF->>DL: check Npcap driver
        PF->>DL: check ML engine
        DL-->>PF: report ✅/⚠️/❌
        PF-->>U: accept or cancel
    else env var = 0 / false
        Note over PF: gate skipped (tests)
    end
    U->>UI: confirm

    UI->>MC: start()
    MC->>RT: AegisRuntime()  ← constructed here (lazy)
    RT->>DL: read AgentSettings / SensorSettings
    alt enable_process_monitor == true
        RT->>SRC: start ProcessMonitor
    else
        Note right of DL: default = False
    end
    alt capture_enabled == true AND interface set
        RT->>SRC: start NetworkSensor (Npcap)
    else
        Note right of DL: default = off + no interface
    end

    RT->>RT: publish pipeline / engines to registries
    RT->>RT: state = RUNNING
    UI->>UI: button → "Stop Monitoring", status → "RUNNING"
    UI->>UI: start 2 s QTimer
```

---

## 3. The Poll Loop (every 2 seconds)

```mermaid
stateDiagram-v2
    [*] --> IDLE : app open
    IDLE --> PREFLIGHT : Start click
    PREFLIGHT --> STARTING : checks pass
    STARTING --> RUNNING : runtime.start()
    RUNNING --> TICK : QTimer fires

    TICK --> HOST_POLL : _poll_host_monitors()
    HOST_POLL --> NET_POLL : events submitted to pipeline
    NET_POLL --> CAPTURE : _poll_network_sensor()
    CAPTURE --> FLOW_EV : drain_sensor_into_pipeline()
    FLOW_EV --> FEATURE : submit_flow_events()

    FEATURE --> ASSETS : update_assets()
    ASSETS --> ANOMALY_NET : score_network_flows()
    ANOMALY_NET --> ANOMALY_HOST : update_host_behavior()
    ANOMALY_HOST --> FIND_BEHAV : _behavior_findings()
    FIND_BEHAV --> FIND_IOC : _ioc_matches()
    FIND_IOC --> DETECT_RISK : _detect_and_assess()
    DETECT_RISK --> CORRELATE : findings + assessments
    CORRELATE --> REPUBLISH : publish incident/correlation registries
    REPUBLISH --> TICK : _cursor advanced, cycle repeats

    RUNNING --> STOPPING : Stop click
    STOPPING --> CLEAN : runtime.stop() → set_active_*…(None)
    CLEAN --> IDLE
```

**One tick output (summary):**

| Metric | Source |
|---|---|
| Host events collected | `_poll_host_monitors()` |
| Network events collected | `_poll_network_sensor()` |
| Findings emitted | `_cycle_findings` |
| Risk assessments emitted | `_cycle_assessments` |
| Errors isolated (never abort) | `_record("...", exc, errors)` |

---

## 4. Event → Finding → Incident → Response

```mermaid
flowchart TD
    subgraph S1["① Ingest"]
        EVT[SecurityEvent]
    end

    subgraph S2["② Detection"]
        DET[Evaluation Engine\nAEGIS-NET-xxx / AEGIS-EXEC-xxx rules]
        BEH[Behavioral Analyzer\nnetwork flow patterns]
        IOC[IOC Matcher\nlocal threat intel]
    end

    subgraph S3["③ Risk"]
        RISK[RiskEngine.assess_many()\n+ ML anomaly signals]
        RA[RiskAssessment\nscore 0-100 / level]
    end

    subgraph S4["④ Correlation"]
        INC[IncidentCorrelator\n→ OPEN incident]
        HNC[HostNetworkCorrelator\n→ evidence bond]
    end

    subgraph S5["⑤ Response"]
        REQ[draft Request\nBLOCK_IP target]
        DR[Dry Run\nResponseDryRunEngine\nwould_apply?]
        APP[Approval\nhuman operator]
        EXE[Execute\nResponseExecutor + WindowsFW]
        AUD[Audit record\nResponseAuditHistory]
        VER[Verify\nis_blocked re-check]
    end

    EVT --> DET & BEH & IOC
    DET & BEH & IOC --> FINDING[DetectionFinding []]
    FINDING --> RISK
    RISK --> RA
    FINDING --> INC
    RA --> INC
    FINDING --> HNC

    INC -. initiate response .-> REQ
    REQ --> DR
    DR -- would_apply --> APP
    APP -- approve --> EXE
    EXE -- netsh add rule --> FW[(Windows Firewall)]
    FW --> VER
    VER --> AUD
```

**Guards before Execute (`executor.py`):**

| Guard | Reject if |
|---|---|
| Action | not `BLOCK_IP` |
| Workflow | not `approved` |
| Policy decision | `denied` |
| Dry-run result | not `would_apply` |
| Target kind | not valid IP |

---

## 5. Demo / Simulation Parallel Path

```mermaid
flowchart LR
    DT[🧪 Simulate Threat Dialog]
    SC[Scenario picker\nPort Scan / C2 Beacon]
    INJ[Build synthetic findings\n- RFC 5737 IPs\n- simulated tag\n- fake host]
    SHADOW[Same registries as real\nalert_service / augment_snapshot\noverlay_services]
    RESP[Auto-open draft BLOCK_IP\nresponse_request_id]
    DEMO_POLICY[Demo policy engine\nresponse_enabled=True\ndry-run + approval still required]

    DT --> SC --> INJ
    INJ --> SHADOW
    INJ -.->|C2 only| INC_CORR[IncidentCorrelator\n+ canned RiskAssessment 91/CRITICAL]
    INC_CORR --> SHADOW
    INJ --> RESP
    RESP -- engine --> DEMO_POLICY
    DEMO_POLICY -. "would_apply" .-> UI_SHOW[Action Center = 1 Pending\nResponse Center row visible]
```

**Key guarantees:**

- ❌ No packet capture, no malware, no network change
- ✅ Same UI pages, same widgets, same tests
- 🔁 Re-running creates new rows (request ids are unique)
- 🧹 `clear_simulated()` + `mgr.clear()` resets everything

---

## 6. Safety Stack (Fail-Closed Design)

```mermaid
graph BT
    SW[🔒 Safety Switches]

    NETCAP["capture_enabled=false\n+ explicit interface required"]
    MONS["enable_process/ Port / connection /\nfile_integrity / yara = false"]
    FI_PATHS["file_integrity_paths = empty"]
    RESP_OFF["response_enabled=false\napproval_required=true\ndry_run_required=true\nautomatic_execution=false"]
    PREFLIGHT["AEGIS_PREFLIGHT_ENABLED\ngate admin & driver checks"]

    SW --> NETCAP
    SW --> MONS
    SW --> FI_PATHS
    SW --> RESP_OFF
    SW --> PREFLIGHT

    NOTE1["Enabling any switch requires\nsetting AEGIS_* env vars"]
    NOTE2["Response execution ONLY after\n: Dry Run → Approve → human press Execute"]

    NOTE1 & NOTE2 -. show.-> SAFETY_MSG[⚠ "Nothing invasive happens\nunless explicitly enabled"]
```

**Defaults at a glance:**

| Env var | Default | Effect when set |
|---|---|---|
| `AEGIS_SENSOR_CAPTURE_ENABLED` | `false` | Packet capture on selected interface |
| `AEGIS_SENSOR_INTERFACE` | *(empty)* | Interface name (required when capture on) |
| `AEGIS_AGENT_ENABLE_PROCESS_MONITOR` | `false` | Track process start/stop |
| `AEGIS_AGENT_ENABLE_PORT_MONITOR` | `false` | Track listening ports |
| `AEGIS_AGENT_FILE_INTEGRITY` | `false` | Hash monitored files |
| `AEGIS_AGENT_FILE_INTEGRITY_PATHS` | *(empty)* | Paths to watch |
| `AEGIS_RESPONSE_POLICY_RESPONSE_ENABLED` | `false` | Allow firewall rule changes |
| `AEGIS_PREFLIGHT_ENABLED` | `true` | Show preflight checklist |

---

## 7. Page Overview (11 screens)

```mermaid
graph LR
    subgraph NAV["Sidebar Navigation"]
        DASH[D: Dashboard\nposture cards / threat feed]
        ASSET[Assets]
        PROC[Processes]
        NET[Network]
        FILE[File Integrity]
        EVENT[Events]
        DET[Detections]
        INC[Incidents]
        RESP[Response Center\nworkflow stepper]
        RISK[Risk]
        SET[Settings]
    end

    subgraph SERVICE_LAYER["Services (pull-based, lazy import)"]
        DA[DashboardService]
        DV[DetectionsView]
        IV[IncidentsView]
        RF[RiskView]
        RV[ResponseWorkflowManager]
    end

    DASH <--> SERVICE_LAYER
    DET <--> DV
    INC <--> IV
    RESP <--> RV
    RISK <--> RF
```

**Refresh model:**

- `refresh()` — full snapshot (navigation or manual refresh button)
- `refresh_live()` — incremental pull every 2 s on current page
- Timer is per-window, shared across all pages

---

## 8. One Observation — Complete Path

```mermaid
journey
    title A single network flow's journey through Aegis
    section Capture
      Npcap packet: 5: Operator
      Normalize to SecurityEvent: 4: NetworkSensor
      Aggregated to FlowRecord: 5: FlowAggregator
    section Analysis
      Submitted to Pipeline: 5: SensorPipeline
      Anomaly scored (ML): 3: MLModel
      Behavioral rules checked: 4: NetworkBehaviorAnalyzer
      IOC matched: 4: ThreatIntelService
    section Decision
      Detection finding emitted: 5: RuleEngine
      Risk assessment computed: 5: RiskEngine
      Incident correlated: 4: IncidentCorrelator
    section Response
      Draft Block-IP request: 3: IncidentsPage
      Dry run simulated: 4: DryRunEngine
      Human approves: 3: Operator
      Firewall rule applied: 2: Netsh (Admin required)
      Audit recorded: 5: AuditHistory
```

---

## 9. Encrypted TLS / SNI Inspection Pipeline

```mermaid
graph TD
    PKT["Raw Port 443 Packet (TCP Payload)"] --> REC{"TLS Record Layer\nContent-Type == 0x16?"}
    REC -- No --> DROP["Pass-through Normalization"]
    REC -- Yes --> HS{"Handshake Type == 0x01\n(ClientHello)?"}
    HS -- No --> DROP
    HS -- Yes --> EXT["Walk TLS Extensions"]
    EXT --> SNI{"Extension Type == 0x0000\n(server_name)?"}
    SNI -- Yes --> DEC["Decode Hostname (RFC 6066)"]
    DEC --> FLOW["FlowAggregator.observe()\n(Preserve without overwrite)"]
    FLOW --> EVT["SecurityEvent (NetworkContext.domain)"]
    EVT --> UI["Live Network Activity Table\n& Flow Inspector Dialog"]
    SNI -- No / ECH --> SAFE["Safe Fallback: Return None\n(Zero Crash Guarantee)"]
```

---

## 10. Subnet Rogue Device Scanner & MITM Defense (ARP Radar)

```mermaid
graph TD
    SUB["Local Subnet (/24)"] --> PROBE["Active Unicast Sweep\n(64 ThreadPoolExecutor workers)"]
    PROBE --> GW["Router Forwarding (Default Gateway)\nBypasses Wi-Fi AP Isolation"]
    GW --> END["Sleeping Phones & Wi-Fi Nodes\nWoken from 802.11 DTIM Sleep"]
    END --> OS["Windows Kernel ARP Cache\n(arp -a)"]
    OS --> RADAR["ArpRadarService\nHarvest Entries"]
    RADAR --> OUI["IEEE OUI Database Lookup\n(Huawei, Vivo Mobile, Samsung, Apple, Realtek)"]
    RADAR --> TRK["ArpTracker Engine"]
    TRK --> SPOOF{"Foreign MAC claiming\nGateway IP?"}
    SPOOF -- Yes --> MITM["🚨 Crimson Warning Banner\n(GATEWAY_SPOOFING Alert)"]
    SPOOF -- No --> VIEW["📡 ARP Radar Table Model\n(Display Role, Status, Vendor)"]
```

---

*Diagrams use **Mermaid** syntax — save this file and open in GitHub / VS Code (with **Markdown Preview Mermaid Support** extension) to render.*
