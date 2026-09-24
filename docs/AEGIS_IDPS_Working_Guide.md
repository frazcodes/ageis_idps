# AEGIS IDPS — Start to End Working Guide

> AI-Powered Hybrid Host & Network Intrusion Detection and Prevention System
> Version: 0.1.0 | Python 3.11+ | PySide6 Desktop Console

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture at a Glance](#2-architecture-at-a-glance)
3. [Environment Setup](#3-environment-setup)
4. [Application Startup Flow](#4-application-startup-flow)
5. [Dashboard Layout](#5-dashboard-layout)
6. [Monitoring Cycle — Every 2 Seconds](#6-monitoring-cycle--every-2-seconds)
7. [Packet Capture Pipeline](#7-packet-capture-pipeline)
8. [Detection Rules (12 Rules)](#8-detection-rules-12-rules)
9. [Risk Scoring Engine](#9-risk-scoring-engine)
10. [Response Workflow](#10-response-workflow)
11. [Desktop Console Pages](#11-desktop-console-pages)
12. [Configuration (.env)](#12-configuration-env)
13. [Safety Design Principles](#13-safety-design-principles)
14. [Package Structure](#14-package-structure)
15. [Test Coverage](#15-test-coverage)

---

## 1. Project Overview

Aegis IDPS is a **single-binary desktop application** that combines:

| Component | What It Does |
|---|---|
| **Host IDS (HIDS)** | Monitors processes, open ports, file integrity via psutil |
| **Network IDS (NIDS)** | Captures packets via scapy, normalizes headers, aggregates flows |
| **ML Anomaly Detection** | Isolation Forest on network flows + host behavior |
| **Risk Scoring** | Deterministic 0-100 score from detection findings |
| **Response Engine** | Policy-gated IPS actions (block IP, isolate host) with approval workflow |
| **SOC Console** | PySide6 dark-theme desktop UI with 11 pages |

### How It Differs from Industry Tools

| Feature | Snort/Suricata | Wazuh | Aegis IDPS |
|---|---|---|---|
| Network IDS | Yes | Yes | Yes |
| Host IDS | No (need OSSEC) | Yes | Yes |
| AI/ML Anomaly | No | Basic | Yes (Isolation Forest) |
| Risk Scoring | No | Basic | Yes (0-100 dynamic) |
| Response Engine | Manual | Basic | Yes (workflow + approval) |
| Desktop UI | CLI only | Web only | Yes (PySide6) |
| Single Binary | Complex setup | Agent+Server | One app, zero config |

---

## 2. Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DATA COLLECTION LAYER                        │
├─────────────────────────┬───────────────────────────────────────────┤
│                         │                                           │
│  HOST MONITORS          │  NETWORK SENSOR                           │
│  ┌─────────────────┐   │  ┌──────────────────────────────────┐    │
│  │ ProcessMonitor   │   │  │ PacketCapture (scapy)            │    │
│  │ PortMonitor      │   │  │   ↓ BPF Filter (driver-level)   │    │
│  │ FileIntegrityMon │   │  │   ↓ normalize_packet()           │    │
│  │                  │   │  │   ↓ PacketRecord (header only)   │    │
│  │ psutil-based     │   │  │   ↓ FlowAggregator               │    │
│  │ snapshot-diff    │   │  │   ↓ FlowRecord                   │    │
│  └────────┬─────────┘   │  └──────────────┬───────────────────┘    │
│           │              │                 │                        │
│  ProcessChanges          │                 │                        │
│  PortChanges             │                 │                        │
│  FileChanges             │                 │                        │
└───────────┼──────────────┼─────────────────┼───────────────────────┘
            │              │                 │
            ▼              ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    RUNTIME EVENT PIPELINE                           │
│              (bounded in-memory event buffer)                       │
│              Sequence-cursor based (never drains)                   │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      DETECTION ENGINE                               │
│                                                                     │
│  Per-Event Rules (6):                                               │
│    AEGIS-LISTEN-001  Unexpected listening port            MEDIUM   │
│    AEGIS-FILE-001    Sensitive file modified               HIGH    │
│    AEGIS-EXEC-001    Executable created                    MEDIUM  │
│    AEGIS-PROC-001    Suspicious process path               HIGH    │
│    AEGIS-NET-001     Suspicious network endpoint           HIGH    │
│    AEGIS-NET-002     High network volume                   MEDIUM  │
│                                                                     │
│  Behavioral Rules (4):                                              │
│    AEGIS-NET-003     Flow burst                            MEDIUM  │
│    AEGIS-NET-004     Repeated communication                 LOW   │
│    AEGIS-NET-005     Destination fanout                    MEDIUM  │
│    AEGIS-NET-006     Port breadth                          MEDIUM  │
│                                                                     │
│  Advanced Detection (2):                                            │
│    AEGIS-IOC-001     Threat Intel IOC match                         │
│    AEGIS-NET-007     Multi-signal communication                     │
│                                                                     │
│  Output: DetectionFinding objects                                   │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ML ANOMALY DETECTION                             │
│                                                                     │
│  NetworkFlows → Features → NetworkAnomalyModel (Isolation Forest)  │
│      → AnomalySignal (0.0 - 1.0)                                   │
│                                                                     │
│  HostTelemetry → Features → HostAnomalyModel (Isolation Forest)    │
│      → AnomalySignal (0.0 - 1.0)                                   │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    RISK ASSESSMENT                                  │
│                                                                     │
│  RiskEngine: deterministic, additive, bounded 0-100                │
│  Per-finding contribution: weight[severity] capped                 │
│  Total = clamp(sum(contributions), 0, 100)                         │
│  Level: CRITICAL (>=80) | HIGH (>=60) | MEDIUM (>=40) | LOW       │
│                                                                     │
│  Output: RiskAssessment { score, level, reasons, anomaly }        │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    CORRELATION LAYER                                │
│                                                                     │
│  IncidentCorrelator:    related findings → Incident                │
│  HostNetworkCorrelator: host evidence ↔ network evidence           │
│  IOCMatcher:            observables ↔ threat intel indicators      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    RESPONSE ENGINE (Policy-Gated)                   │
│                                                                     │
│  PolicyEngine → MONITOR or ENFORCE mode                            │
│  ResponseExecutor → executes approved actions                      │
│  FirewallDriver → Windows Firewall via netsh                       │
│  AuditTrail → every action logged                                  │
│                                                                     │
│  Actions: LOG_ONLY | NOTIFY | BLOCK_IP | UNBLOCK_IP |             │
│           BLOCK_PORT | QUARANTINE_FILE | KILL_PROCESS |            │
│           HOST_ISOLATE | HOST_RESTORE                              │
│                                                                     │
│  Safety: dry_run=True (default) → simulation only                  │
│          require_approval=True → analyst must approve              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Environment Setup

### Prerequisites

- **Python 3.11+** (tested on 3.14.3)
- **Npcap** (Windows packet capture driver)
- **Windows 10/11** (primary platform)

### Installation Steps

```bash
# 1. Clone the repository
cd D:\aegis-idps

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# 3. Install all dependencies
pip install -e ".[desktop,sensor,agent,ml,response,dev]"

# 4. Install Npcap (required for packet capture)
#    Download: https://npcap.com/#download
#    IMPORTANT: Check "WinPcap API-compatible Mode" during install

# 5. Verify installation
python -c "from aegis_desktop.app import run; print('OK')"
```

### Verify Npcap

```bash
# Check if Npcap is installed
python -c "
from aegis_network_sensor.capture import list_interfaces
print('Available interfaces:', list_interfaces())
"
```

---

## 4. Application Startup Flow

### Command to Start

```bash
cd D:\aegis-idps
.venv\Scripts\activate
python -m aegis_desktop
```

### What Happens (Step by Step)

```
python -m aegis_desktop
    │
    ├─ 1. QApplication create (PySide6)
    │     └─ app.setApplicationName("Aegis IDPS")
    │
    ├─ 2. apply_theme(app) → Dark SOC theme loads
    │     Background: #0d1117
    │     Accent: #00ff41 (green)
    │     Cards: #161b22
    │
    ├─ 3. SplashScreen appears (~2.8 seconds)
    │     "Initializing Aegis IDPS..."
    │     "Loading detection engine..."
    │     "Starting network sensors..."
    │
    └─ 4. MainWindow opens
          ├── Header: "Aegis IDPS" + "Start Monitoring" button
          ├── Sidebar: 11 navigation pages
          └── Dashboard: default page (all disabled)
```

---

## 5. Dashboard Layout

### When Monitoring is OFF

```
┌─────────────────────────────────────────────────────┐
│ Header: Aegis IDPS          [Start Monitoring]      │
│ Status: "Monitoring: disabled"                      │
├─────────┬───────────────────────────────────────────┤
│Sidebar  │  SYSTEM HEALTH BAR                        │
│         │  ● Core: NOT RUNNING                      │
│◉ Dash   │  ● Host: DISABLED                         │
│  Assets │  ● Network: DISABLED                      │
│  Proc   │  ● FIM: DISABLED                          │
│  Net    │  ● Detection: NOT RUNNING                 │
│  Files  │  ● Risk: NOT RUNNING                      │
│  Events │  ● Response: MONITOR (read-only)          │
│  Detec  │                                           │
│  Incid  │  SECURITY POSTURE                         │
│  Resp   │  ┌─────────┐ ┌─────────┐ ┌──────────┐   │
│  Risk   │  │ Risk: — │ │Threats:0│ │ Actions:0│   │
│  Settin │  │ No data │ │ 0 total │ │No pending│   │
│         │  └─────────┘ └─────────┘ └──────────┘   │
│         │                                           │
│         │  THREAT FEED: "No active threats"         │
│         │  NETWORK: (empty table)                   │
│         │  TELEMETRY: (flat graphs)                 │
└─────────┴───────────────────────────────────────────┘
```

### When Monitoring is ON

```
┌─────────────────────────────────────────────────────┐
│ Header: Aegis IDPS    Monitoring: active   [Stop]   │
├─────────┬───────────────────────────────────────────┤
│Sidebar  │  SYSTEM HEALTH BAR                        │
│         │  ● Core: ACTIVE  ● Host: ACTIVE           │
│◉ Dash   │  ● Network: ACTIVE  ● Detection: ACTIVE  │
│  Assets │  ● FIM: ACTIVE  ● Risk: ACTIVE           │
│  Proc   │  ● Response: MONITOR (read-only)          │
│  Net    │                                           │
│  Files  │  SECURITY POSTURE                         │
│  Events │  ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  Detec  │  │ Risk: 45 │ │Threats: 3│ │Actions: 2│  │
│  Incid  │  │ MEDIUM   │ │2 high    │ │[Review]  │  │
│  Resp   │  └──────────┘ └──────────┘ └──────────┘  │
│  Risk   │                                           │
│  Settin │  THREAT FEED                              │
│         │  ┌ MEDIUM │ Suspicious port 4444 open  ─┐ │
│         │  │        │ Host: ws-01 | PORT_LISTENING│ │
│         │  ├ HIGH   │ Sensitive file modified    ─┐│ │
│         │  │        │ Host: ws-01 | FILE_MODIFIED ││ │
│         │  └──────────────────────────────────────┘│
│         │                                           │
│         │  LIVE NETWORK ACTIVITY                    │
│         │  src→dst          Proto  Pkts   Bytes     │
│         │  10.0.0.1→8.8.8   TCP    142    84KB     │
│         │  10.0.0.1→1.1.1   TCP     28    12KB     │
│         │                                           │
│         │  NETWORK SUMMARY                          │
│         │  170 pkts │ 96KB │ 2 flows │ 2 active    │
│         │                                           │
│         │  CONTEXTUAL TELEMETRY                     │
│         │  [Network Throughput] [Security Events]   │
└─────────┴───────────────────────────────────────────┘
```

---

## 6. Monitoring Cycle — Every 2 Seconds

### Timer Configuration

| Setting | Value | Location |
|---|---|---|
| `poll_interval_ms` | 2000 | `services/monitoring.py` |
| `capture_timeout_seconds` | 0.15 | `.env` |
| `max_packets_per_run` | 50 | `.env` |
| `capture_filter` | BPF (6 ports dropped) | `config.py` |

### The 7-Phase Cycle

```
Timer fires (every 2000ms)
    │
    ▼
┌──────────────────────────────────────────────────────────┐
│  PHASE 1: HOST MONITORS                                  │
│                                                          │
│  ProcessMonitor.poll()                                   │
│    → psutil.process_iter() → current snapshot            │
│    → Diff with baseline → new_processes, stopped         │
│    → ProcessChanges{started=[...], stopped=[...]}        │
│    → SecurityEvents submitted to pipeline                │
│                                                          │
│  PortMonitor.poll()                                      │
│    → psutil.net_connections() → current snapshot         │
│    → Diff → new_ports, stopped_ports                     │
│    → PortChanges{started=[...], stopped=[...]}           │
│                                                          │
│  FileIntegrityMonitor.poll()                             │
│    → Scan configured paths → current snapshot            │
│    → SHA-256 hash compare → modified files               │
│    → FileChanges{created=[...], modified=[...], deleted} │
├──────────────────────────────────────────────────────────┤
│  PHASE 2: NETWORK CAPTURE                                │
│                                                          │
│  scapy.sniff(                                            │
│    iface = "Wi-Fi",                                      │
│    filter = "(ip or ip6)                                 │
│              and not port 5353     ← mDNS DROP           │
│              and not port 1900     ← SSDP DROP           │
│              and not arp           ← ARP DROP            │
│              and not port 5355     ← LLMNR DROP          │
│              and not port 137/138  ← NetBIOS DROP        │
│              and not port 427",    ← SAP DROP            │
│    count = 50,          ← max 50 packets                 │
│    timeout = 0.15,      ← 150ms max block                │
│    store = False        ← RAM mein store nahi            │
│  )                                                       │
│                                                          │
│  WiFi se aaye raw packets driver level pe filter hue     │
│  Ab sirf IP/IPv6 packets Python mein aaye                │
├──────────────────────────────────────────────────────────┤
│  PHASE 3: PACKET NORMALIZATION (har packet)              │
│                                                          │
│  normalize_packet(raw_packet)                            │
│    ├─ IP/IPv6 nahi hai? → SKIP                          │
│    ├─ Header extract:                                     │
│    │   src_ip, dst_ip, src_port, dst_port               │
│    │   protocol (TCP/UDP/ICMP), packet_length           │
│    │   direction (inbound/outbound)                      │
│    │   flow_id = "IPv4|TCP|10.0.0.1:443->8.8.8.8:443"  │
│    │                                                      │
│    │   ❌ PAYLOAD BILKUL NAHI PADHTE                     │
│    │   ❌ NO DATA COPIED TO MEMORY                       │
│    │                                                      │
│    └─ PacketRecord banta hai                             │
├──────────────────────────────────────────────────────────┤
│  PHASE 4: FLOW AGGREGATION                               │
│                                                          │
│  FlowAggregator.observe_many(packet_records)            │
│    ├─ Same src→dst ko group karta hai                   │
│    │   "IPv4|TCP|10.0.0.1:443->8.8.8.8:443"            │
│    │                                                      │
│    ├─ Counters update:                                    │
│    │   packet_count += 1                                 │
│    │   byte_count += packet_length                       │
│    │   last_seen = now                                   │
│    │                                                      │
│    └─ FlowRecord banta hai:                              │
│        flow_id, src_ip, dst_ip, ports                   │
│        packet_count, byte_count, duration                │
│                                                          │
│  Changed flows sirf emit hoti hain (drain_changed)      │
├──────────────────────────────────────────────────────────┤
│  PHASE 5: DETECTION ENGINE (12 rules)                    │
│                                                          │
│  Har event ke liye 12 rules evaluate hote hain          │
│  (See Section 8 for full rule details)                  │
│                                                          │
│  Output: Finding objects with rule_id, severity, title  │
├──────────────────────────────────────────────────────────┤
│  PHASE 6: RISK ASSESSMENT                                │
│                                                          │
│  RiskEngine.assess(event, findings)                     │
│  (See Section 9 for full scoring details)               │
│                                                          │
│  Output: RiskAssessment { score, level, reasons }       │
├──────────────────────────────────────────────────────────┤
│  PHASE 7: CORRELATION                                    │
│                                                          │
│  IncidentCorrelator:                                     │
│    Related findings → group into Incident                │
│    "3 findings from same host, risk=75"                 │
│                                                          │
│  HostNetworkCorrelator:                                  │
│    Host evidence (suspicious process)                    │
│    + Network evidence (connecting to C2)                 │
│    = Cross-domain correlation                            │
└──────────────────────────────────────────────────────────┘
```

---

## 7. Packet Capture Pipeline

### What Happens to Each Packet

```
WiFi Network Card
    │
    ▼
Npcap Driver (kernel level)
    │
    ├─ BPF Filter applied:
    │   DROP: ARP, mDNS (5353), SSDP (1900),
    │         LLMNR (5355), NetBIOS (137/138), SAP (427)
    │
    ├─ Only IP/IPv6 packets pass through
    │
    └─ Up to 50 packets per cycle, 0.15s max
         │
         ▼
Python (scapy)
    │
    ├─ normalize_packet() extracts:
    │   ✓ src_ip, dst_ip
    │   ✓ src_port, dst_port
    │   ✓ protocol (TCP/UDP/ICMP)
    │   ✓ packet_length
    │   ✓ direction (inbound/outbound)
    │   ✓ flow_id (unique identifier)
    │
    │   ❌ NO payload read
    │   ❌ NO application data
    │   ❌ NO credentials
    │   ❌ NO content stored
    │
    └─ PacketRecord created (frozen, immutable)
         │
         ▼
FlowAggregator
    │
    ├─ Groups packets by src→dst flow
    │   "10.0.0.1:443 → 8.8.8.8:443"
    │
    ├─ Aggregates counters:
    │   packet_count, byte_count, duration
    │
    └─ FlowRecord emitted only when changed
         │
         ▼
Detection Engine
    │
    └─ 12 rules evaluate the flow event
```

### PacketRecord Schema (What We Store)

```python
PacketRecord(
    timestamp: datetime,        # When observed
    interface: str,             # "Wi-Fi"
    ip_version: IPV4/IPV6,      # IP version
    src_ip: str,                # "10.0.0.1"
    dst_ip: str,                # "8.8.8.8"
    protocol: TCP/UDP/ICMP,     # Transport protocol
    src_port: int,              # 443
    dst_port: int,              # 52000
    packet_length: int,         # 1500 bytes
    direction: INBOUND/OUTBOUND,# Based on local IPs
    flow_id: str,               # "IPv4|TCP|10.0.0.1:443->8.8.8.8:443"
)
```

---

## 8. Detection Rules (12 Rules)

### Per-Event Rules (6)

| Rule ID | Name | Severity | Trigger | What It Detects |
|---|---|---|---|---|
| `AEGIS-LISTEN-001` | Unexpected listening port | MEDIUM | `PORT_LISTENING` | TCP port open that's not in allowed list |
| `AEGIS-FILE-001` | Sensitive file modified | HIGH | `FILE_MODIFIED` | Configured sensitive file changed |
| `AEGIS-EXEC-001` | Executable created | MEDIUM | `FILE_CREATED` | .exe file created in monitored path |
| `AEGIS-PROC-001` | Suspicious process path | HIGH | `PROCESS_STARTED` | Process from configured suspicious path |
| `AEGIS-NET-001` | Suspicious network endpoint | HIGH | `NETWORK_PACKET` | Communication with known bad IP/port |
| `AEGIS-NET-002` | High network volume | MEDIUM | `FLOW_SUMMARY` | Single flow exceeds volume threshold |

### Behavioral Rules (4)

| Rule ID | Name | Severity | Window Metric | Threshold |
|---|---|---|---|---|
| `AEGIS-NET-003` | Flow burst | MEDIUM | Distinct flows in window | 10+ flows / 10 sec |
| `AEGIS-NET-004` | Repeated communication | LOW | Same src→dst count | 5+ repeats |
| `AEGIS-NET-005` | Destination fanout | MEDIUM | Distinct destinations | 10+ from one source |
| `AEGIS-NET-006` | Port breadth | MEDIUM | Distinct ports | 10+ from one source |

### Advanced Rules (2)

| Rule ID | Name | Evaluated By |
|---|---|---|
| `AEGIS-IOC-001` | Threat Intel IOC match | `IOCMatcher` |
| `AEGIS-NET-007` | Multi-signal communication | `SuspiciousCommunicationAnalyzer` |

### Rule Output: DetectionFinding

```python
DetectionFinding(
    finding_id: str,        # "AEGIS-NET-001:Event-42"
    rule_id: str,           # "AEGIS-NET-001"
    title: str,             # "Suspicious network endpoint observed"
    severity: Severity,     # HIGH
    event_id: str,          # Reference to source event
    tags: tuple[str, ...],  # ("network", "endpoint")
    description: str,       # Human-readable explanation
    evidence: dict,         # Raw evidence for audit
)
```

---

## 9. Risk Scoring Engine

### Algorithm (Version 1)

```
Input: Event + List of DetectionFindings
    │
    ├─ Per-finding contribution:
    │   weight[LOW] = 5
    │   weight[MEDIUM] = 15
    │   weight[HIGH] = 30
    │   weight[CRITICAL] = 50
    │
    │   contribution = min(weight[severity], max_per_finding)
    │
    ├─ Total = sum(all contributions)
    │
    ├─ Clamp: max(0, min(100, total))
    │
    └─ Level mapping:
        score >= 80 → CRITICAL
        score >= 60 → HIGH
        score >= 40 → MEDIUM
        score >= 20 → LOW
        else       → INFORMATIONAL
```

### Example Calculations

| Findings | Calculation | Score | Level |
|---|---|---|---|
| 1 LOW | 5 | 5 | LOW |
| 2 MEDIUM | 15 + 15 | 30 | LOW |
| 3 MEDIUM | 15 + 15 + 15 | 45 | MEDIUM |
| 1 HIGH + 1 MEDIUM | 30 + 15 | 45 | MEDIUM |
| 2 HIGH | 30 + 30 | 60 | HIGH |
| 1 CRITICAL + 1 HIGH | 50 + 30 | 80 | CRITICAL |
| 3 HIGH + 2 MEDIUM | 30+30+30+15+15 | 100 | CRITICAL |

### RiskAssessment Output

```python
RiskAssessment(
    assessment_id: str,           # "risk-v1:Event-42"
    risk_score: int,              # 45
    risk_level: RiskLevel,        # MEDIUM
    severity: Severity,           # HIGH (max across findings)
    reasons: list[str],           # ["AEGIS-NET-001: +30", "AEGIS-LISTEN-001: +15"]
    finding_ids: tuple[str, ...], # ("AEGIS-NET-001:Event-42", ...)
    scoring_version: str,         # "1"
    timestamp: datetime,
    anomaly: AnomalySignal | None,# ML signal (if fitted)
)
```

---

## 10. Response Workflow

### Workflow States

```
create_request()
    │
    ▼
draft
    │
    ▼
dry_run_completed (simulation)
    │
    ▼
pending_approval
    │
    ├── APPROVE ──► execute() ──► executed
    │                           or execution_failed
    │
    └── REJECT ──► rejected (terminal)

cancel() available from any pre-approved state
```

### What Each State Means

| State | Meaning |
|---|---|
| `draft` | Request created, not yet simulated |
| `dry_run_completed` | Simulation done, safe to review |
| `pending_approval` | Waiting for analyst decision |
| `approved` | Analyst approved, ready to execute |
| `rejected` | Analyst rejected (with reason) |
| `cancelled` | Request cancelled |
| `executed` | Action successfully applied |
| `execution_failed` | Execution attempted but failed |

### Supported Actions

| Action | What It Does | Requires |
|---|---|---|
| `LOG_ONLY` | Log the event | Nothing |
| `NOTIFY` | Send notification | Alert service |
| `BLOCK_IP` | Block IP via firewall | `netsh advfirewall` |
| `UNBLOCK_IP` | Remove firewall rule | `netsh advfirewall` |
| `BLOCK_PORT` | Block port via firewall | `netsh advfirewall` |
| `QUARANTINE_FILE` | Move file to quarantine | File system access |
| `KILL_PROCESS` | Terminate process | `taskkill` |
| `HOST_ISOLATE` | Isolate host from network | Firewall rules |
| `HOST_RESTORE` | Restore network access | Remove isolation |

### Safety Mechanisms

```
default: dry_run = True       → Simulation only
default: require_approval = True → Analyst must approve
default: mode = MONITOR        → No enforcement

To enforce:
  1. Set mode = ENFORCE in settings
  2. Set dry_run = False
  3. Set require_approval = False (optional)
  4. Analyst clicks "Approve" in Response Center
```

---

## 11. Desktop Console Pages

### 11 Sidebar Pages

| # | Page Key | Title | Description |
|---|---|---|---|
| 1 | `dashboard` | Dashboard | Overview: health, posture, threats, network, graphs |
| 2 | `assets` | Assets | Asset inventory, services, peers, network identity |
| 3 | `processes` | Processes | Running process snapshot and changes |
| 4 | `network` | Network | Ports, flows, live network monitoring |
| 5 | `files` | File Integrity | FIM changes and configuration |
| 6 | `events` | Events | Security event feed from pipeline |
| 7 | `detections` | Detections | Findings, behavioral analysis, communication |
| 8 | `incidents` | Incidents | Correlated incidents from findings |
| 9 | `response` | Response Center | Response policy, workflow, audit trail |
| 10 | `risk` | Risk | Risk assessments and anomaly signals |
| 11 | `settings` | Settings | Configuration viewer |

### Page Navigation

```
Click sidebar item → page loads
Click finding card → navigates to Detections page
Click incident card → navigates to Incidents page
Click "Review Actions" → navigates to Response Center
```

---

## 12. Configuration (.env)

### Current .env File

```env
AEGIS_SENSOR_CAPTURE_ENABLED=true
AEGIS_SENSOR_INTERFACE=Wi-Fi
AEGIS_SENSOR_MAX_PACKETS_PER_RUN=50
AEGIS_SENSOR_CAPTURE_TIMEOUT_SECONDS=0.15
```

### All Configuration Options

| Variable | Default | Description |
|---|---|---|
| `AEGIS_SENSOR_CAPTURE_ENABLED` | `false` | Master switch for packet capture |
| `AEGIS_SENSOR_INTERFACE` | `""` | Network interface (e.g., "Wi-Fi", "eth0") |
| `AEGIS_SENSOR_MAX_PACKETS_PER_RUN` | `200` | Max packets per capture cycle |
| `AEGIS_SENSOR_CAPTURE_TIMEOUT_SECONDS` | `0.2` | Max seconds per capture (blocks UI) |
| `AEGIS_SENSOR_CAPTURE_FILTER` | BPF string | Kernel-level packet filter |
| `AEGIS_SENSOR_PROMISCUOUS` | `false` | Promiscuous mode (requires privileges) |
| `AEGIS_SENSOR_FLOW_WINDOW_SECONDS` | `10` | Flow aggregation window |
| `AEGIS_SENSOR_LOCAL_ADDRESSES` | `[]` | Local IPs for direction detection |

### BPF Filter (Default)

```
(ip or ip6) and not port 5353 and not port 1900 and not arp
and not port 5355 and not port 137 and not port 138
and not port 427
```

**Dropped traffic:**
- ARP (broadcast noise)
- mDNS (5353) — multicast DNS
- SSDP (1900) — UPnP discovery
- LLMNR (5355) — Link-local multicast
- NetBIOS (137/138) — Windows name resolution
- SAP (427) — Service Location Protocol

---

## 13. Safety Design Principles

| Principle | Implementation |
|---|---|
| **Off by default** | All monitors disabled, capture disabled, dry_run=True, mode=MONITOR |
| **Passive capture** | scapy sniff(store=False), payload never read, headers only |
| **Immutable events** | SecurityEvent frozen=True, extra="forbid" |
| **Single-threaded** | No daemons, no background threads, caller-driven lifecycle |
| **Bounded memory** | Capped pipeline buffers (max_events), max findings window |
| **Policy-gated** | All IPS actions require policy rules + approval |
| **Failure isolation** | Failing producer logged, never aborts the cycle |
| **Evidence language** | "modified" not "infected", "observed" not "attacked" |
| **Audit trail** | Every response action logged with full context |
| **Human-in-loop** | Analyst must approve before any enforcement action |

---

## 14. Package Structure

### 8 Packages in Monorepo

```
aegis-idps/
├── shared/aegis_shared/          # Foundation (45 files)
│   ├── enums.py                  # 18 StrEnum classes
│   ├── events.py                 # SecurityEvent model
│   ├── detection/                # Engine + 12 rules
│   ├── risk/                     # RiskEngine + scoring
│   ├── pipeline/                 # Event buffer
│   ├── correlation/              # Incident + HostNetwork
│   ├── assets/                   # Asset registry
│   ├── baseline/                 # Observation baseline
│   └── threat_intel/             # IOC matching
│
├── agent/aegis_agent/            # Host monitors (29 files)
│   ├── monitors/process/         # ProcessMonitor (psutil)
│   ├── monitors/port/            # PortMonitor (psutil)
│   ├── monitors/file_integrity/  # FileIntegrityMonitor (SHA-256)
│   └── inventory/                # SystemInventory
│
├── network-sensor/               # Packet capture (14 files)
│   ├── sensor.py                 # NetworkSensor (scapy)
│   ├── normalization.py          # Packet → PacketRecord
│   ├── flows/                    # FlowAggregator
│   └── capture/                  # PacketCapture wrapper
│
├── ml-engine/aegis_ml_engine/    # ML (9 files)
│   ├── features/                 # Feature extraction
│   └── anomaly/                  # Isolation Forest models
│
├── runtime/aegis_runtime/        # Orchestrator (4 files)
│   └── runtime.py                # AegisRuntime (1200+ lines)
│
├── response-engine/              # IPS actions (17 files)
│   ├── policy/                   # PolicyEngine
│   ├── firewall/                 # Windows Firewall driver
│   ├── executors/                # ResponseExecutor
│   └── audit/                    # Audit trail
│
├── desktop/aegis_desktop/        # PySide6 console (39 files)
│   ├── pages/                    # 11 page widgets
│   ├── services/                 # 19 service adapters
│   ├── window.py                 # Main window
│   ├── theme.py                  # Dark SOC theme
│   └── navigation.py             # Sidebar
│
└── backend/aegis_backend/        # FastAPI (16 files, scaffolded)
    └── api/v1/                   # REST API
```

### Dependency Graph

```
aegis_shared (foundation)
    │
    ├── aegis_agent (host monitors)
    ├── aegis_network_sensor (packet capture)
    ├── aegis_ml_engine (anomaly detection)
    ├── aegis_response_engine (IPS actions)
    │
    └── aegis_runtime (orchestrator)
            │
            └── aegis_desktop (PySide6 console)
```

---

## 15. Test Coverage

### Summary

| Metric | Count |
|---|---|
| Test files | 45 |
| Test cases | 901 |
| Python files | 220 |

### Test Files by Package

| Package | Test Files | Key Tests |
|---|---|---|
| shared | 12 | detection, risk, correlation, events, pipeline |
| agent | 5 | process_monitor, port_monitor, file_integrity, inventory |
| network-sensor | 4 | capture, normalization, flows, config |
| ml-engine | 3 | anomaly_model, flow_features, host_features |
| runtime | 2 | runtime_lifecycle, runtime_anomaly |
| response-engine | 4 | firewall, policy, workflow, audit |
| desktop | 14 | dashboard, all 11 pages, theme, soc_console |
| backend | 1 | health endpoint |

### Running Tests

```bash
# All tests
pytest tests/ -x -q

# Specific package
pytest tests/test_dashboard.py tests/test_network_sensor.py -x -q

# With verbose output
pytest tests/test_detection.py -v

# Skip slow tests
pytest tests/ -x -q -m "not integration"
```

---

## Quick Reference Card

```
┌──────────────────────────────────────────────────────┐
│  START:     python -m aegis_desktop                   │
│  STOP:      Click "Stop Monitoring" button            │
│  CONFIG:    .env file (capture settings)              │
│                                                       │
│  CYCLE:     Every 2 seconds                           │
│    1. Host monitors (process/port/file)              │
│    2. Network capture (50 pkts, 0.15s)               │
│    3. Normalize packets (headers only)                │
│    4. Aggregate flows                                 │
│    5. Detection (12 rules)                            │
│    6. Risk scoring (0-100)                            │
│    7. Correlation (incidents)                         │
│                                                       │
│  SAFETY:                                              │
│    - dry_run=True (simulation only)                   │
│    - require_approval=True (analyst approves)         │
│    - mode=MONITOR (no enforcement)                    │
│    - Payload never read                               │
│    - Single-threaded (no daemons)                     │
│                                                       │
│  TESTS:   901 test cases, 45 files                   │
│  PACKAGES: 8 (shared, agent, sensor, ml,             │
│              runtime, response, desktop, backend)     │
└──────────────────────────────────────────────────────┘
```
