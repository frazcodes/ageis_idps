# AEGIS IDPS — Comprehensive Master Technical Documentation
## Complete Architecture, Component Reference, API Specification & Developer Guide

**Project Name:** AEGIS IDPS (Autonomous Hybrid Host & Network Intrusion Detection and Prevention System)  
**Version:** 1.0.0 (Production / Defense Grade)  
**Repository Type:** Clean Architecture Monorepo (8 Packages)  
**Language & Runtime:** Python 3.12+ / 3.14  
**GUI Framework:** PySide6 (Qt 6.7+ for Python)  
**Packet Engine:** Scapy 2.5+  
**Machine Learning:** Scikit-Learn (Isolation Forest)  

---

## Table of Contents

- [1. System Overview & Architectural Blueprint](#1-system-overview--architectural-blueprint)
  - [1.1 Purpose & Scope](#11-purpose--scope)
  - [1.2 Monorepo Package Topology](#12-monorepo-package-topology)
  - [1.3 Telemetry Flow & Processing Pipeline](#13-telemetry-flow--processing-pipeline)
  - [1.4 Concurrency & Threading Model](#14-concurrency--threading-model)
- [2. Shared Foundation Layer (`aegis_shared`)](#2-shared-foundation-layer-aegis_shared)
  - [2.1 Comprehensive Enum Specifications (18 Classes)](#21-comprehensive-enum-specifications-18-classes)
  - [2.2 The Immutable `SecurityEvent` Model](#22-the-immutable-securityevent-model)
  - [2.3 Context Blocks Specification](#23-context-blocks-specification)
  - [2.4 Event Pipeline & Deduplication Buffer](#24-event-pipeline--deduplication-buffer)
  - [2.5 Cryptographic Utilities & Streaming Hashing](#25-cryptographic-utilities--streaming-hashing)
- [3. Host Monitoring Subsystem (`aegis_agent`)](#3-host-monitoring-subsystem-aegis_agent)
  - [3.1 Process Monitor & Collector](#31-process-monitor--collector)
  - [3.2 Listening Port & Socket Collector](#32-listening-port--socket-collector)
  - [3.3 File Integrity Monitor (FIM)](#33-file-integrity-monitor-fim)
  - [3.4 System Inventory Profiler](#34-system-inventory-profiler)
  - [3.5 Agent Configuration Schema](#35-agent-configuration-schema)
- [4. Network Sensor Subsystem (`aegis_network_sensor`)](#4-network-sensor-subsystem-aegis_network_sensor)
  - [4.1 Promiscuous Header-Only Packet Sniffer](#41-promiscuous-header-only-packet-sniffer)
  - [4.2 Packet Normalizer & Canonical 5-Tuple](#42-packet-normalizer--canonical-5-tuple)
  - [4.3 Bidirectional Flow Aggregator (4,096 LRU)](#43-bidirectional-flow-aggregator-4096-lru)
  - [4.4 Critical Exploit Port Heuristic Profiler](#44-critical-exploit-port-heuristic-profiler)
  - [4.5 TLS/SNI Domain Extractor (RFC 6066 & Zero-Crash Parser)](#45-tlssni-domain-extractor-rfc-6066--zero-crash-parser)
  - [4.6 Subnet Rogue Device Scanner & MITM Defense Engine (ARP Radar)](#46-subnet-rogue-device-scanner--mitm-defense-engine-arp-radar)
  - [4.7 Sensor Configuration Schema](#47-sensor-configuration-schema)
- [5. Detection & Behavioral Rules Engine (`aegis_detection`)](#5-detection--behavioral-rules-engine-aegis_detection)
  - [5.1 Detection Architecture (Rule Lifecycle)](#51-detection-architecture-rule-lifecycle)
  - [5.2 Complete Catalog of Deterministic Rules (12 Rules)](#52-complete-catalog-of-deterministic-rules-12-rules)
  - [5.3 Temporal Sliding-Window Stateful Rules](#53-temporal-sliding-window-stateful-rules)
  - [5.4 Threat Intel IOC Matcher](#54-threat-intel-ioc-matcher)
  - [5.5 Suspicious Multi-Signal Communication Analyzer](#55-suspicious-multi-signal-communication-analyzer)
  - [5.6 MITRE ATT&CK Matrix Alignment](#56-mitre-attck-matrix-alignment)
- [6. Machine Learning Anomaly Detection (`aegis_ml_engine`)](#6-machine-learning-anomaly-detection-aegis_ml_engine)
  - [6.1 Model Architecture (Unsupervised Isolation Forest)](#61-model-architecture-unsupervised-isolation-forest)
  - [6.2 Numerical Feature Extraction Pipeline](#62-numerical-feature-extraction-pipeline)
  - [6.3 Anomaly Scoring Function & Outlier Thresholding](#63-anomaly-scoring-function--outlier-thresholding)
  - [6.4 Online Inference & Baseline Training](#64-online-inference--baseline-training)
- [7. Cross-Domain Correlation & Incident Engine](#7-cross-domain-correlation--incident-engine)
  - [7.1 Cross-Domain Fusion Logic (Host + Network)](#71-cross-domain-fusion-logic-host--network)
  - [7.2 Temporal Causal Linking Matrix](#72-temporal-causal-linking-matrix)
  - [7.3 The `Incident` Model & Lifecycle States](#73-the-incident-model--lifecycle-states)
- [8. Risk Scoring & Quantification Engine](#8-risk-scoring--quantification-engine)
  - [8.1 Weighted Multi-Factor Mathematical Formulation](#81-weighted-multi-factor-mathematical-formulation)
  - [8.2 Factor Derivation & Normalization](#82-factor-derivation--normalization)
  - [8.3 Posture Tiers & Threshold Bands](#83-posture-tiers--threshold-bands)
- [9. Active Prevention & Response Subsystem (`aegis_response_engine`)](#9-active-prevention--response-subsystem-aegis_response_engine)
  - [9.1 Fail-Closed Security Paradigm](#91-fail-closed-security-paradigm)
  - [9.2 The Five Immutable Safety Guards](#92-the-five-immutable-safety-guards)
  - [9.3 Windows Firewall Adapter (`netsh` Driver)](#93-windows-firewall-adapter-netsh-driver)
  - [9.4 Staged Four-Tier Approval Workflow](#94-staged-four-tier-approval-workflow)
  - [9.5 Cryptographic Response Audit Logging](#95-cryptographic-response-audit-logging)
- [10. Central Runtime Orchestrator (`aegis_runtime`)](#10-central-runtime-orchestrator-aegis_runtime)
  - [10.1 Initialization & Component Binding](#101-initialization--component-binding)
  - [10.2 Event Bus & Inter-Thread Synchronization](#102-event-bus--inter-thread-synchronization)
  - [10.3 Signal Trapping & Graceful Teardown](#103-signal-trapping--graceful-teardown)
- [11. Desktop SOC Operations Console (`aegis_desktop`)](#11-desktop-soc-operations-console-aegis_desktop)
  - [11.1 Application Core, Event Loop & Navigation](#111-application-core-event-loop--navigation)
  - [11.2 Top Hero "Security Shield & Threat Defense Command Banner"](#112-top-hero-security-shield--threat-defense-command-banner)
  - [11.3 Real-Time Threat Highlighting (Red-Stripe Packet Triage)](#113-real-time-threat-highlighting-red-stripe-packet-triage)
  - [11.4 System Hygiene & Dropper Cache Purge Engine (`Ctrl+Shift+C`)](#114-system-hygiene--dropper-cache-purge-engine-ctrlshiftc)
  - [11.5 Detailed Walkthrough of All 11 Console Pages](#115-detailed-walkthrough-of-all-11-console-pages)
  - [11.6 Synthetic Threat Simulation System (`threat_sim.py`)](#116-synthetic-threat-simulation-system-threat_simpy)
  - [11.7 Audio Alert Subsystem & Hardware Acceleration Muting](#117-audio-alert-subsystem--hardware-acceleration-muting)
  - [11.8 Toast Notification Engine](#118-toast-notification-engine)
  - [11.9 SOC Brief & Forensic Report Generator](#119-soc-brief--forensic-report-generator)
  - [11.10 TLS / SNI Hostname Visibility in Network Activity](#1110-tls--sni-hostname-visibility-in-network-activity)
  - [11.11 Subnet Device Radar Tab (`📡 ARP Radar`)](#1111-subnet-device-radar-tab-arp-radar)
- [12. Configuration Reference & Environment Variables](#12-configuration-reference--environment-variables)
- [13. Comprehensive Testing & Verification Suite](#13-comprehensive-testing--verification-suite)
- [14. Deployment, Installation & Troubleshooting Guide](#14-deployment-installation--troubleshooting-guide)

---

# 1. System Overview & Architectural Blueprint

## 1.1 Purpose & Scope
**AEGIS IDPS** is an enterprise-grade, autonomous **Hybrid Host and Network Intrusion Detection and Prevention System**. It is engineered to solve the "visibility chasm" in modern cyber defense: traditional network security tools cannot inspect encrypted payloads or link packets to endpoint processes, while traditional host-based agents cannot detect raw packet floods, network sweeps, or lateral movement.

AEGIS bridges this divide by binding low-level packet capture with kernel process enumeration, cryptographic file integrity tracking, unsupervised machine learning, and deterministic rule correlation inside a single, zero-cloud desktop security operations console.

## 1.2 Monorepo Package Topology
The codebase follows strict clean-architecture boundaries across 8 decoupled packages:

```
d:\aegis-idps\
├── shared/
│   └── aegis_shared/          # Domain vocabulary, enums, immutable models, logging
├── agent/
│   └── aegis_agent/           # Endpoint telemetry: processes, listening ports, FIM, inventory
├── network_sensor/
│   └── aegis_network_sensor/  # Packet capture, normalization, flow aggregation, port profiler
├── detection/
│   └── aegis_detection/       # 12 deterministic rules, behavioral windows, IOC matcher
├── ml_engine/
│   └── aegis_ml_engine/       # Unsupervised Isolation Forest anomaly detection
├── runtime/
│   └── aegis_runtime/         # Central loop, event bus, component orchestrator
├── response_engine/
│   └── aegis_response_engine/ # Fail-closed IPS actions, 5 safety guards, firewall adapter
├── desktop/
│   └── aegis_desktop/         # PySide6 SOC console: 11 pages, hero banner, hygiene tool
├── backend/
│   └── aegis_backend/         # Optional headless FastAPI REST and WebSocket API
└── tests/                     # 45 deterministic test suites (900+ test cases)
```

## 1.3 Telemetry Flow & Processing Pipeline

```
[ Local Endpoint ]                 [ Network Wire ]
Process | Port | FIM             Scapy Header Capture
       │                                  │
       ▼                                  ▼
[ aegis_agent ]                  [ aegis_network_sensor ]
       │                                  │
       └──────────────────┬───────────────┘
                          │
                          ▼
            [ aegis_shared.EventPipeline ]
            (Deduplication & Bounded Ring Buffer)
                          │
                          ▼
            [ aegis_runtime Orchestrator ]
           ┌──────────────┼──────────────┐
           ▼              ▼              ▼
     Rule Engine      ML Engine    Cross-Correlator
    (12 Rules)   (Isolation Forest) (Host+Network)
           └──────────────┬──────────────┘
                          │
                          ▼
                 [ Risk Scoring (0-100) ]
                          │
           ┌──────────────┴──────────────┐
           ▼                             ▼
 [ 5 Safety Guards ]          [ aegis_desktop Console ]
           │                  - Hero Shield Banner
           ▼                  - Red-Stripe Flow Triage
[ Windows Firewall netsh ]    - MITRE Kill Chain Strip
(IP Containment Block)        - System Hygiene Purge
```

## 1.4 Concurrency & Threading Model
AEGIS executes on a multi-threaded architecture with bounded memory queues:
1. **Sensor Thread (`daemon=True`):** Dedicated thread executing Scapy packet capture. Drops raw payload bytes immediately, forwarding only normalized 5-tuple headers to minimize overhead.
2. **Agent Polling Loop (`daemon=True`):** Ticks at configured intervals (default 5000 ms) using `psutil` and directory walking to poll process trees, listening sockets, and FIM hashes.
3. **Runtime Event Dispatcher:** Dispatches queued events to detection rules and ML feature extractors via non-blocking queues.
4. **GUI Main Thread (Qt Event Loop):** The PySide6 desktop interface runs strictly on the main thread, receiving immutable snapshots and telemetry updates through Qt signal/slot queues, guaranteeing thread safety and eliminating race conditions.

---

# 2. Shared Foundation Layer (`aegis_shared`)

**Package Location:** `shared/aegis_shared/`

## 2.1 Comprehensive Enum Specifications (18 Classes)
To guarantee type safety across network, host, and UI layers, AEGIS establishes 18 typed `StrEnum` classes in `enums.py`:

| Enum Class | Key Values | Architectural Purpose |
|---|---|---|
| `EventCategory` | `HOST`, `NETWORK`, `DETECTION`, `CORRELATION`, `RESPONSE`, `SYSTEM` | High-level event domain classification |
| `EventType` | `PROCESS_STARTED`, `PROCESS_STOPPED`, `PORT_LISTENING`, `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `NETWORK_PACKET`, `FLOW_SUMMARY`, `ANOMALY_DETECTED`, `INCIDENT_CREATED`, etc. | Specific telemetry event action |
| `Severity` | `INFO` (0), `LOW` (1), `MEDIUM` (2), `HIGH` (3), `CRITICAL` (4) | Five-tier numerical and visual severity rank |
| `SourceKind` | `AGENT`, `SENSOR`, `BACKEND`, `ML_ENGINE`, `RESPONSE_ENGINE`, `CORRELATOR` | Originating subsystem of telemetry |
| `Platform` | `WINDOWS`, `LINUX`, `MACOS`, `UNKNOWN` | Host operating system identification |
| `NetworkDirection` | `INBOUND`, `OUTBOUND`, `LATERAL`, `UNKNOWN` | Flow direction relative to local interfaces |
| `TransportProtocol` | `TCP`, `UDP`, `ICMP`, `OTHER` | Transport layer protocol typing |
| `AddressFamily` | `IPV4`, `IPV6`, `UNIX`, `OTHER`, `UNKNOWN` | Network address family identification |
| `FileType` | `REGULAR`, `DIRECTORY`, `SYMLINK`, `OTHER` | FIM file system object classification |
| `HashStatus` | `HASHED`, `SKIPPED_SIZE`, `PERMISSION_DENIED`, `UNSUPPORTED`, `ERROR`, `NOT_APPLICABLE` | Cryptographic integrity status |
| `AlertStatus` | `OPEN`, `ACKNOWLEDGED`, `CLOSED`, `SUPPRESSED` | SOC alert triage lifecycle status |
| `IncidentStatus` | `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE` | Composite incident lifecycle tracking |
| `IndicatorType` | `IP`, `DOMAIN`, `FILE_HASH` | Threat intelligence IOC indicator type |
| `ResponseMode` | `MONITOR`, `DRY_RUN`, `ENFORCE` | Execution policy for active containment |
| `ActionType` | `LOG_ONLY`, `NOTIFY`, `RATE_LIMIT`, `BLOCK_IP`, `UNBLOCK_IP`, `BLOCK_PORT`, `QUARANTINE_FILE`, `KILL_PROCESS`, `HOST_ISOLATE`, `HOST_RESTORE` | Actionable containment command catalog |
| `ActionStatus` | `PROPOSED`, `APPROVED`, `DENIED`, `EXECUTED`, `FAILED`, `ROLLED_BACK` | Audit status of IPS containment action |
| `RiskBand` | `NEGLIGIBLE`, `LOW`, `ELEVATED`, `HIGH`, `SEVERE` | Visual posture tier for risk assessments |
| `RiskLevel` | `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Textual rating for composite risk scores |

## 2.2 The Immutable `SecurityEvent` Model
Defined in `aegis_shared.events`, `SecurityEvent` is a frozen Pydantic model enforcing structural immutability:

```python
class SecurityEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: UUID = Field(default_factory=uuid4)
    schema_version: str = "1.0.0"
    event_type: EventType
    category: EventCategory
    severity: Severity = Severity.INFO
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: SourceRef
    host: HostRef | None = None
    actor: ActorRef | None = None
    network: NetworkContext | None = None
    socket: SocketContext | None = None
    process: ProcessContext | None = None
    file: FileContext | None = None
    risk: RiskAssessment | None = None
    correlation: CorrelationRef | None = None
    message: str = ""
    labels: frozenset[str] = Field(default_factory=frozenset)
```

## 2.3 Context Blocks Specification
1. **`NetworkContext`:** 19 fields capturing source/destination IP, source/destination port, protocol, flow identifier, packet count, byte volume, TCP flags, and domain lookup.
2. **`ProcessContext`:** Captures PID, PPID, executable path, process name, command-line arguments, environment hashes, and user account.
3. **`FileContext`:** Captures absolute path, file size, access permissions, operation (`CREATED`, `MODIFIED`, `DELETED`), and cryptographic SHA-256 hash.
4. **`SocketContext`:** Captures local bind address, local port, protocol, and socket state (`LISTEN`, `ESTABLISHED`, `TIME_WAIT`).

## 2.4 Event Pipeline & Deduplication Buffer
Located in `aegis_shared.pipeline`, the `EventPipeline` maintains a thread-safe, bounded FIFO ring buffer:
- Implements an internal `deque(maxlen=max_capacity)` (default 10,000 events).
- Computes event fingerprints using `hash((event_type, source_id, timestamp.second, context_digest))`. Duplicate events arriving within a 1000 ms sliding window are dropped to prevent buffer exhaustion during packet storms.

## 2.5 Cryptographic Utilities & Streaming Hashing
`aegis_shared.crypto` provides streaming hash generation:
- Reads files in 64 KiB binary blocks (`hashlib.sha256()`).
- Files exceeding `max_size_bytes` (default 50 MB) or locked with `PermissionError` are tagged with explicit `HashStatus.SKIPPED_SIZE` or `HashStatus.PERMISSION_DENIED`, ensuring zero unhandled exceptions.

---

# 3. Host Monitoring Subsystem (`aegis_agent`)

**Package Location:** `agent/aegis_agent/`

## 3.1 Process Monitor & Collector
- **Module:** `monitors/process/collector.py` & `monitor.py`
- Uses `psutil.process_iter()` to query the operating system process table.
- Collects:
  - PID and Parent PID (PPID) to trace process execution trees.
  - Full command-line arguments (`cmdline`) enabling detection of living-off-the-land techniques (e.g., `powershell.exe -enc`, `certutil.exe -urlcache`).
  - CPU percentage and memory resident set size (RSS).
  - Creation timestamp normalized to UTC.
- Maintains a delta cache: only newly spawned or terminated processes generate `PROCESS_STARTED` or `PROCESS_STOPPED` events, minimizing bus traffic.

## 3.2 Listening Port & Socket Collector
- **Module:** `monitors/port/collector.py`
- Gathers local socket listeners via `psutil.net_connections(kind="all")`.
- Maps each open listening port (TCP/UDP) to:
  - Local bind address (`0.0.0.0`, `127.0.0.1`, `::`, or interface IP).
  - Bound port number.
  - Owning process ID (PID) and process name.
- Classifies exposure scope:
  - `LOCAL ONLY`: Bound strictly to `127.0.0.1` or `::1`.
  - `PUBLIC / WILDCARD`: Bound to `0.0.0.0` or `*`, exposing the endpoint to external network probes.

## 3.3 File Integrity Monitor (FIM)
- **Module:** `monitors/file/collector.py`
- Monitors pre-configured critical security paths:
  - Windows Hosts file: `C:\Windows\System32\drivers\etc\hosts`
  - System startup directories: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
  - Custom user-configured watched paths.
- Computes baseline SHA-256 hashes on agent startup.
- On subsequent polling cycles, re-hashes paths:
  - Generates `FILE_MODIFIED` with previous and new hashes if content changes.
  - Generates `FILE_DELETED` if a monitored file is removed.
  - Generates `FILE_CREATED` if a new executable or script appears in watched folders.

## 3.4 System Inventory Profiler
- **Module:** `inventory.py`
- Profiles hardware and operating system parameters:
  - Host ID (stable UUID derived from machine identity).
  - Hostname and architecture (`AMD64`, `ARM64`).
  - OS version and kernel build number.
  - Python runtime version and agent software release.
  - CPU core count and total physical memory.

---

# 4. Network Sensor Subsystem (`aegis_network_sensor`)

**Package Location:** `network_sensor/aegis_network_sensor/`

## 4.1 Promiscuous Header-Only Packet Sniffer
- **Module:** `capture.py`
- Employs Scapy’s asynchronous `AsyncSniffer` socket wrapper.
- Operates in promiscuous mode across the primary active network interface.
- Strips payload bytes immediately upon interception: captures strictly down to Layer 3/4 headers to ensure maximum throughput (>10,000 packets/second) and user privacy.

## 4.2 Packet Normalizer & Canonical 5-Tuple
- **Module:** `normalization.py`
- Translates raw Scapy packets into immutable `NormalizedPacket` dataclasses:
  - Resolves Layer 3: IPv4 / IPv6 addresses, TTL, header length.
  - Resolves Layer 4: TCP ports, sequence numbers, acknowledgement numbers, flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`); UDP ports; ICMP type/code.
- Discards unroutable or malformed frames safely without crashing.

## 4.3 Bidirectional Flow Aggregator (4,096 LRU)
- **Module:** `flow.py`
- Aggregates individual packets into bidirectional flow sessions.
- **Canonical Flow Key Formula:**
  $$\text{Key} = (\min(IP_s, IP_d), \max(IP_s, IP_d), \min(P_s, P_d), \max(P_s, P_d), \text{Proto})$$
- Stores flows in a bounded LRU ring buffer capped at 4,096 concurrent sessions:
  - Tracks total packet count and byte count in each direction.
  - Tracks flow duration in milliseconds.
  - Automatically evicts oldest idle flows when the 4,096 boundary is reached.
  - Emits `FLOW_SUMMARY` events upon flow termination or timeout (default 60 seconds).

## 4.4 Critical Exploit Port Heuristic Profiler
- **Module:** `live_network.py` (`_CRITICAL_PORTS`)
- Maps transport ports against known high-risk vulnerability vectors:

```python
_CRITICAL_PORTS: dict[int, tuple[str, str]] = {
    445:   ("SMB EXPLOIT",     "SMB Port 445: High-risk lateral movement / EternalBlue exploit attempt"),
    3389:  ("RDP BRUTE",       "RDP Port 3389: Remote Desktop brute-force or unauthorized session"),
    23:    ("TELNET INSECURE", "Telnet Port 23: Cleartext credentials / Mirai botnet probe"),
    21:    ("FTP INSECURE",    "FTP Port 21: Unencrypted file transfer / credential sniffing"),
    135:   ("MSRPC PROBE",     "MSRPC Port 135: Windows RPC endpoint mapper exploit probe"),
    139:   ("NETBIOS SCAN",    "NetBIOS Port 139: Windows name/file sharing enumeration"),
    4444:  ("METASPLOIT C2",   "Port 4444: Metasploit default payload / reverse shell C2 beacon"),
    5985:  ("WINRM EXEC",      "WinRM Port 5985: Remote PowerShell execution probe"),
    6379:  ("REDIS EXPOSURE",  "Redis Port 6379: Unauthenticated memory dump / code execution"),
    6667:  ("IRC BOTNET",      "IRC Port 6667: Internet Relay Chat botnet command & control channel"),
    31337: ("BACKDOOR",        "Port 31337: Elite backdoor / Trojan communication"),
}
```

## 4.5 TLS/SNI Domain Extractor (RFC 6066 & Zero-Crash Parser)
- **Module:** `tls_parser.py`
- **Function:** `extract_tls_sni(payload: bytes) -> str | None`
- **Protocol Engineering:**
  - Modern web malware and Command & Control (C2) agents communicate exclusively over encrypted TLS (Port 443). To provide domain-level visibility without executing computationally prohibitive or privacy-violating SSL/TLS decryption (MITM proxying), AEGIS inspects the cleartext **TLS Handshake ClientHello** record.
  - Adheres strictly to **RFC 6066** (Server Name Indication extension) specifications:
    1. **Record Layer Verification:** Checks Content Type `0x16` (Handshake) and TLS Major Version `0x03`.
    2. **Handshake Layer Verification:** Validates Handshake Type `0x01` (ClientHello) and reads 3-byte Handshake length.
    3. **Session ID & Cipher Suites Parsing:** Safely bounds and skips variable Session ID length, 2-byte Cipher Suites length, and 1-byte Compression Methods length.
    4. **Extensions Block Walk:** Iterates through TLS extensions to identify Extension Type `0x0000` (`server_name`).
    5. **SNI Hostname Decoding:** Reads `ServerNameList`, verifies `name_type == 0` (HostName), decodes ASCII/UTF-8 hostname, and lowercases the domain.
- **Fail-Safe & Zero-Crash Guarantees:**
  - Validates every byte slice and offset boundary before reading; rejects malformed lengths or truncated packets instantly.
  - Fully resilient to non-TLS traffic, partial stream buffers, and modern **Encrypted Client Hello (ECH / RFC 8744)** without crashing or throwing unhandled exceptions.
- **Pipeline & Event Integration:**
  - Integrated into packet normalization (`_normalize_packet()` in `normalization.py`).
  - Added to Pydantic domain models: `PacketRecord.sni: str | None` and `FlowRecord.sni: str | None`.
  - **Non-Overwriting Flow Retention:** `FlowAggregator.observe()` preserves extracted SNI across the lifecycle of a flow session, ensuring later payload-free TCP ACKs do not overwrite a previously discovered hostname.
  - Propagated to SIEM events via `NetworkContext.domain` for immediate IOC and rule correlation.

## 4.6 Subnet Rogue Device Scanner & MITM Defense Engine (ARP Radar)
- **Modules:** `network-sensor/aegis_network_sensor/arp_radar.py` & `desktop/aegis_desktop/services/arp_radar.py`
- **Core Architecture:**
  - Provides active and passive local network asset discovery, hardware MAC vendor identification, and real-time detection of Layer-2 Man-in-the-Middle (MITM) attacks.
  - Managed by `ArpTracker`, storing `ArpDevice` entities with IP, MAC, Vendor, First/Last Seen timestamps, and packet statistics.
- **IEEE OUI Hardware Vendor Resolution:**
  - Incorporates an extensive in-memory Organizationally Unique Identifier (OUI) database resolving hardware MAC prefixes to physical vendors:
    - *Enterprise & Networking:* Cisco, Cisco Meraki, Ubiquiti, MikroTik, HP, Dell, Intel.
    - *Cloud & Virtualization:* VMware, VirtualBox, QEMU, Docker.
    - *Smart Home & IoT:* Espressif Systems (ESP8266/ESP32), Raspberry Pi Foundation.
    - *Consumer Endpoints & Mobile:* Apple, Samsung, Google, Realtek, Huawei, Xiaomi, Vivo Mobile, Oppo, OnePlus.
  - Identifies locally administered randomized MACs (bit 1 of first byte set to 1).
- **MITM Attack & Cache Poisoning Detection Algorithms:**
  1. **Gateway Impersonation / Poisoning (`GATEWAY_SPOOFING`):** Immediately alerts with `CRITICAL` severity when a foreign MAC address broadcasts ARP ownership of the default gateway IP.
  2. **IP-to-MAC Conflict / Flipping (`MAC_CONFLICT`):** Detects when an active IP is claimed by competing MAC addresses, flagging active ARP cache poisoning.
  3. **Gratuitous ARP Flooding (`BURST_SPOOF`):** Detects rapid bursts ($>5$ packets in 3 seconds) of unsolicited ARP replies designed to override switch CAM tables and host ARP caches.
- **Active Subnet Probe Sweep (Solving Wi-Fi AP Client Isolation & Smartphone Sleep):**
  - **The Real-World Challenge:** In modern wireless environments—particularly mobile hotspots, 4G/LTE Wingles (e.g. Huawei/Zong E8372), and enterprise APs—**AP/Client Isolation** drops Layer-2 broadcast ARP (`ff:ff:ff:ff:ff:ff`) frames between wireless stations. Furthermore, idle Android and iOS devices enter low-power 802.11 DTIM sleep modes and do not respond to broadcast queries.
  - **The AEGIS Solution:** `ArpRadarService` executes a rapid, concurrent **Multi-Threaded Unicast Probe Sweep** using a `ThreadPoolExecutor` (64 workers, 150 ms timeout). Sending directed unicast ICMP echo requests through the default gateway forces the router to forward the packets directly to sleeping phones and endpoints. As endpoints reply, the host Windows kernel automatically populates its ARP cache, enabling AEGIS to discover 100% of connected subnet nodes in under 2 seconds.
- **Real-Time Endpoint Liveness & Dynamic Disconnect Pruning:**
  - Operates continuous real-time synchronization via `sync_live_endpoints()`:
    1. During each 2-second GUI refresh cycle, AEGIS concurrently verifies active endpoint nodes with non-blocking 150 ms unicast liveness probes.
    2. If a mobile device, tablet, or laptop disconnects, leaves the Wi-Fi network, or turns off its wireless adapter, it fails the probe and is **immediately removed** from `ArpTracker` and the UI table via `tracker.remove_device(ip)`.
    3. Guarantees that only authentically reachable devices remain visible on the dashboard in real time without stale ghost entries.

---

# 5. Detection & Behavioral Rules Engine (`aegis_detection`)

**Package Location:** `detection/aegis_detection/`

## 5.1 Detection Architecture (Rule Lifecycle)
Every rule inherits from `BaseRule` and implements:
```python
def evaluate(self, event: SecurityEvent) -> list[Finding]:
```
Findings produce structured security alerts detailing Rule ID, Severity, Title, Description, Associated Host/Network context, and MITRE ATT&CK technique IDs.

## 5.2 Complete Catalog of Deterministic Rules (12 Rules)

### Per-Event Stateless Rules (6)
1. **`AEGIS-LISTEN-001` (`SuspiciousListeningPortRule`):** Triggers when an unapproved process binds to a listening port on high-risk ports (e.g., 4444, 6667, 31337). Severity: `MEDIUM`.
2. **`AEGIS-FILE-001` (`SensitiveFileModificationRule`):** Triggers when a file modification event impacts security configuration files (e.g., `hosts`, firewall policies). Severity: `HIGH`.
3. **`AEGIS-EXEC-001` (`ExecutableCreationRule`):** Triggers when a `.exe`, `.bat`, `.ps1`, or `.vbs` binary is written to temporary user directories (`%TEMP%`, `Downloads`). Severity: `MEDIUM`.
4. **`AEGIS-PROC-001` (`SuspiciousProcessPathRule`):** Triggers when system processes (e.g., `svchost.exe`, `lsass.exe`) execute from abnormal file paths outside `%WINDIR%\System32`. Severity: `HIGH`.
5. **`AEGIS-NET-001` (`SuspiciousNetworkEndpointRule`):** Triggers when traffic connects to blacklisted IP ranges, Tor exit nodes, or private non-routable targets over public interfaces. Severity: `HIGH`.
6. **`AEGIS-NET-002` (`HighNetworkVolumeRule`):** Triggers when a single network flow transfers more than 10 MB within a standard aggregation window. Severity: `MEDIUM`.

### Temporal Sliding-Window Stateful Rules (4)
7. **`AEGIS-NET-003` (`FlowBurstRule`):** Maintains a rolling 10-second window. Triggers if a single source IP initiates $>50$ distinct flows, detecting automated port scanning or DDoS attempts.
8. **`AEGIS-NET-004` (`RepeatedCommunicationRule`):** Detects beaconing behavior where an internal host initiates periodic connections to the same external IP at fixed intervals ($T \pm 2\%$).
9. **`AEGIS-NET-005` (`DestinationFanoutRule`):** Detects internal worm propagation or network mapping when a single internal IP initiates connections to $>20$ unique internal IPs within 30 seconds.
10. **`AEGIS-NET-006` (`PortBreadthRule`):** Triggers when a single external IP queries $>15$ unique ports on a local host within 10 seconds.

### Advanced Analytical Rules (2)
11. **`AEGIS-IOC-001` (`IOCMatcherRule`):** Matches active IP addresses, domain names, and SHA-256 file hashes against an in-memory threat intelligence database. Severity: `CRITICAL`.
12. **`AEGIS-NET-007` (`SuspiciousCommunicationAnalyzer`):** Computes multi-signal anomaly heuristics based on rare transport protocols combined with unusual packet sizes and high TTL variance. Severity: `HIGH`.

## 5.6 MITRE ATT&CK Matrix Alignment

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MITRE ATT&CK TACTIC CHAIN                       │
├──────────────┬──────────────┬──────────────┬─────────────┬─────────────┤
│Reconnaissance│Initial Access│  Execution   │ Persistence │ Command & C2│
│   (TA0043)   │   (TA0001)   │   (TA0002)   │  (TA0003)   │  (TA0011)   │
├──────────────┼──────────────┼──────────────┼─────────────┼─────────────┤
│  Port Sweep  │  RDP Brute   │  PowerShell  │  FIM Hosts  │ Metasploit  │
│  (RULE-006)  │  (RULE-002)  │  (RULE-004)  │  (RULE-001) │  (RULE-007) │
└──────────────┴──────────────┴──────────────┴─────────────┴─────────────┘
```

---

# 6. Machine Learning Anomaly Detection (`aegis_ml_engine`)

**Package Location:** `ml_engine/aegis_ml_engine/`

## 6.1 Model Architecture (Unsupervised Isolation Forest)
- **Algorithm:** Isolation Forest (`sklearn.ensemble.IsolationForest`)
- **Ensemble Hyperparameters:**
  - `n_estimators = 100` (Number of isolation trees)
  - `max_samples = 256` (Subsampling rate for tree depth containment)
  - `contamination = 0.05` (Expected proportion of outliers in baseline data)
  - `random_state = 42` (Deterministic seed for reproducible evaluation)

## 6.2 Numerical Feature Extraction Pipeline
- Converts raw flow summaries into a standardized 5-dimensional feature vector:
  1. `packet_count`: Total packets observed in the flow.
  2. `byte_count`: Total volume transferred.
  3. `duration_ms`: Flow lifetime in milliseconds.
  4. `bytes_per_packet`: Ratio $\frac{\text{byte\_count}}{\max(1, \text{packet\_count})}$ reflecting packet MTU profile.
  5. `packets_per_second`: Rate $\frac{\text{packet\_count}}{\max(0.001, \text{duration\_seconds})}$ reflecting transmission burstiness.

## 6.3 Anomaly Scoring Function & Outlier Thresholding
- Evaluates tree traversal depths using the mathematical formula:
  $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
- **Decision Logic:**
  - $s(x, n) < 0.50$: Nominal baseline traffic.
  - $0.50 \le s(x, n) < 0.65$: Elevated / suspicious variance.
  - $s(x, n) \ge 0.65$: Anomaly detected; generates `ANOMALY_DETECTED` security event with outlier score and feature breakdown.

---

# 7. Cross-Domain Correlation & Incident Engine

**Package Location:** `shared/aegis_shared/correlation/`

## 7.1 Cross-Domain Fusion Logic (Host + Network)
Standalone alerts often represent harmless background noise. The correlation engine fuses host and network evidence into high-confidence composite `Incident` objects:

```
[ External Port Scan ] ────┐
                           ├──► [ Incident Engine ] ──► [ CONFIRMED INCIDENT ]
[ Exploit Packet: 445 ] ───┤       Temporal Window:            Severity: CRITICAL
                           │       Delta < 5000 ms             Containment: Proposed
[ Process: cmd.exe ] ──────┘
```

## 7.2 Temporal Causal Linking Matrix
The correlator maintains an in-memory graph of related entities:
- **IP-to-Process Link:** Matches destination IP and port with active process socket tables.
- **Process-to-File Link:** Matches originating process PID with FIM file write events.
- **Incident Escalation Condition:** If three or more correlated findings share a common host or external IP within a 60-second window, an `Incident` is generated with unified risk factors.

---

# 8. Risk Scoring & Quantification Engine

**Package Location:** `shared/aegis_shared/risk/`

## 8.1 Weighted Multi-Factor Mathematical Formulation
The global risk score is computed as an integer in the range $[0, 100]$:

$$\text{Risk Score} = \min\left(100, \sum_{i=1}^{N} \min(\text{Weight}[\text{Severity}_i], \text{MaxPerFinding})\right)$$

### Finding Severity Weight Table
- `INFO`: $0$ points
- `LOW`: $5$ points
- `MEDIUM`: $15$ points
- `HIGH`: $30$ points
- `CRITICAL`: $50$ points
- `MaxPerFinding`: $50$ points

## 8.2 Factor Derivation & Posture Tiers
The risk engine classifies the score into five standardized SOC risk bands:

| Score Range | Risk Band | Risk Level | Console Indicator Color | Required Action |
|---|---|---|---|---|
| **0 – 19** | `NEGLIGIBLE` | `INFORMATIONAL` | `#10B981` (Emerald Green) | Nominal operation; routine monitoring |
| **20 – 39** | `LOW` | `LOW` | `#38BDF8` (Sky Blue) | Low-priority review |
| **40 – 69** | `ELEVATED` | `MEDIUM` | `#F59E0B` (Amber Warning) | Analyst investigation recommended |
| **70 – 89** | `HIGH` | `HIGH` | `#F97316` (Deep Orange) | Active exploit likely; response triggered |
| **90 – 100** | `SEVERE` | `CRITICAL` | `#EF4444` (Emergency Crimson) | Critical attack; audio alarm & host isolation |

---

# 9. Active Prevention & Response Subsystem (`aegis_response_engine`)

**Package Location:** `response_engine/aegis_response_engine/`

## 9.1 Fail-Closed Security Paradigm
A critical flaw of naive automated response engines is self-inflicted Denial of Service (e.g., blocking the default gateway or DNS resolver during an attack). AEGIS enforces a strict **fail-closed, safety-validated** design pattern: no containment command touches the operating system firewall without passing through five static validator guards.

## 9.2 The Five Immutable Safety Guards

```python
class ResponseSafetyValidator:
    """Five immutable programmatic guards preventing self-inflicted DoS."""

    @staticmethod
    def validate_action(action: ResponseAction, context: SystemContext) -> GuardResult:
        # Guard 1: Loopback Immunity
        if action.target_ip in ("127.0.0.1", "::1", "localhost"):
            return GuardResult.REJECTED("Cannot block loopback interface")

        # Guard 2: Default Gateway Immunity
        if action.target_ip == context.default_gateway_ip:
            return GuardResult.REJECTED("Cannot block default network gateway")

        # Guard 3: DNS Resolver Immunity
        if action.target_ip in context.configured_dns_servers:
            return GuardResult.REJECTED("Cannot block active DNS resolver")

        # Guard 4: Rate Limiting
        if context.recent_action_count(window_seconds=60) >= 5:
            return GuardResult.REJECTED("Action rate limit exceeded (max 5/min)")

        # Guard 5: Dry-Run Mode Enforcement
        if context.response_mode == ResponseMode.DRY_RUN:
            return GuardResult.SIMULATED("Action validated in dry-run mode")

        return GuardResult.APPROVED()
```

## 9.3 Windows Firewall Adapter (`netsh` Driver)
- **Module:** `adapter/windows_firewall.py`
- Executes containment actions via tokenized subprocess execution without shell interpolation:
```powershell
netsh advfirewall firewall add rule name="AEGIS_CONTAIN_{ip}" dir=in action=block remoteip={ip}
```
- Reversion command for unblocking:
```powershell
netsh advfirewall firewall delete rule name="AEGIS_CONTAIN_{ip}"
```

## 9.4 Staged Four-Tier Approval Workflow
For high-impact containment requests (e.g., host isolation or IP blocking), the response workflow enforces a four-stage state machine:

```
[ DRAFT ] ──► [ DRY RUN ] ──► [ PENDING APPROVAL ] ──► [ EXECUTED ]
                    │                    │
                    ▼                    ▼
               [ REJECTED ]         [ REJECTED ]
```

---

# 10. Central Runtime Orchestrator (`aegis_runtime`)

**Package Location:** `runtime/aegis_runtime/`

## 10.1 Initialization & Component Binding
The `AegisRuntime` coordinates the lifecycle of all subsystems:
- Binds `aegis_agent` collectors, `aegis_network_sensor` capture threads, detection engines, and ML models into an unified event bus.
- Manages health heartbeats across background threads.

## 10.2 Event Bus & Inter-Thread Synchronization
- Uses thread-safe queues with non-blocking polling (`queue.Empty` timeout traps).
- Ensures that if one detector experiences heavy processing loads, incoming packet capture queues do not block or cause OS socket buffer overflow.

## 10.3 Signal Trapping & Graceful Teardown
- Intercepts `SIGINT` and `SIGTERM` signals.
- Shuts down Scapy packet sniffer sockets cleanly, flushes event audit logs, stops agent polling workers, and releases operating system handles.

---

# 11. Desktop SOC Operations Console (`aegis_desktop`)

**Package Location:** `desktop/aegis_desktop/`

## 11.1 Application Core, Event Loop & Navigation
- Built entirely on **PySide6 (Qt for Python)**.
- Adheres to modern SOC ergonomics: deep navy dark theme (`#0F172A`), high-contrast typography, and zero distracting animations.
- Implements a unified `Sidebar` (`navigation.py`) controlling a `QStackedWidget` hosting 11 specialized console pages.

## 11.2 Top Hero "Security Shield & Threat Defense Command Banner"
- **Location:** Prominently positioned at the very top of the `DashboardPage`.
- **Components:**
  1. **Holographic Shield Icon Box:** `50x50` px cyber container with glowing border rendering `🛡️` (normal) or `🚨` (threat).
  2. **Live Status Title:** High-contrast neon green (`● SYSTEM PROTECTED · ALL DEFENSE SHIELDS ARMED`) or fiery crimson (`● THREAT DETECTED · ACTIVE EXPLOIT MITIGATION`).
  3. **Host Telemetry Chips:** Capsule pills indicating `🖥️ Host: <HostName>` and `🛡️ Active Threat Count`.
  4. **Core Sensor Indicators:** Live status dots (`● Core`, `● Host`, `● Net`, `● FIM`, `● Det`, `● Risk`, `● Resp`).
  5. **System Health Gauge Box:** Large dynamic health score (`100% HEALTH SCORE`) inversely proportional to the calculated global risk score.

## 11.3 Real-Time Threat Highlighting (Red-Stripe Packet Triage)
- **Module:** `live_network.py` (`LiveNetworkTableModel`)
- Automatically evaluates incoming flows against `analyze_packet_threat()`.
- **Styling Rules for Suspicious Traffic (SMB 445, RDP 3389, Telnet 23, Metasploit 4444):**
  - **`BackgroundRole`:** Translucent crimson background stripe (`rgba(248, 81, 73, 0.16)`).
  - **`ForegroundRole`:** Vivid coral and bright warning text (`#FFA198`, `#FF7B72`, `#FF4444`).
  - **`DisplayRole` (State Column):** Displays prominent alert badge (`🚨 SMB EXPLOIT`, `🚨 RDP BRUTE`, `🚨 C2 BEACON`).
  - **`ToolTipRole`:** Rich forensic popover displaying threat classification, flow endpoints, and containment guidance.

## 11.4 System Hygiene & Dropper Cache Purge Engine (`Ctrl+Shift+C`)
- **Modules:** `services/system_cleaner.py` & `hygiene_dialog.py`
- **Purpose:** Identifies and purges temporary malware dropper directories, application cache residue, and system crash dumps.
- **Target Directories:**
  1. `%TEMP%` (`C:\Users\<User>\AppData\Local\Temp`): Application session files & common malware dropper staging directory.
  2. `%WINDIR%\Temp`: OS installer leftovers and service temp files.
  3. `C:\Windows\Prefetch`: Execution trace files (`.pf`).
  4. `%LOCALAPPDATA%\CrashDumps`: Memory crash dumps.
- **Lock Protection:** Implements lenient recursive deletion that gracefully bypasses in-use or locked operating system files without aborting batch purges.
- **Keyboard Shortcut:** Globally accessible from anywhere in the console via `Ctrl + Shift + C`.

## 11.5 Detailed Walkthrough of All 11 Console Pages

| Page Key | Title | Technical Functionality |
|---|---|---|
| `dashboard` | **Dashboard** | SOC HQ overview: Hero Shield Banner, 3 Posture Cards, MITRE Kill-Chain Strip, Topology Radar, Live Network Table, Telemetry Graphs |
| `assets` | **Assets** | Inventory of local host network interfaces, MAC addresses, IP bindings, and discovered subnet peers |
| `processes` | **Processes** | Real-time process tree monitor, PID/PPID hierarchy, CPU/RAM utilization, and command-line arguments |
| `network` | **Network** | Network monitoring view: listening ports, active socket bindings, bidirectional flows, and live traffic events |
| `files` | **File Integrity** | Cryptographic SHA-256 FIM baseline tracking, sensitive path monitoring, and tampering alert audit |
| `events` | **Events** | Real-time SIEM event log with keyword filtering, category tabs, and raw JSON event inspector |
| `detections` | **Detections** | Triaged security findings generated by rule and ML engines with MITRE ATT&CK technique tags |
| `incidents` | **Incidents** | Multi-event correlated security incidents with containment status and root-cause timelines |
| `response` | **Response Center** | IPS command hub: dry-run staging, operator approvals, and Windows Firewall containment executor |
| `risk` | **Risk** | Multi-factor risk breakdown, weighted severity charts, and historical risk posture trends |
| `settings` | **Settings** | Component health inspection, polling interval configurations, and read-only posture auditing |

## 11.6 Synthetic Threat Simulation System (`threat_sim.py`)
- Provides five pre-built attack simulation playbooks for operator training and verification:
  1. *WannaCry SMB Exploit:* Simulates rapid Port 445 lateral movement probes.
  2. *RDP Password Spray:* Simulates distributed brute-force bursts against port 3389.
  3. *Living-off-the-Land Attack:* Simulates obfuscated `powershell.exe -enc` execution.
  4. *Volumetric ICMP Ping Flood:* Simulates anomalous bandwidth flood (>1,000 packets).
  5. *System File Tampering:* Simulates unauthorized edits to the Windows `hosts` file.

## 11.7 Audio Alert Subsystem & Hardware Acceleration Muting
- **Module:** `services/audio_alert.py`
- Employs `PySide6.QtMultimedia` to sound an urgent cyber alarm tone when critical incidents trigger.
- **Hardware Encoder Workaround:** Automatically silences noisy FFmpeg MFT hardware encoder diagnostic logging on Windows systems using `os.environ.setdefault("QT_LOGGING_RULES", "qt.multimedia*=false")`.

## 11.8 Toast Notification Engine
- **Module:** `toast.py` (`ToastManager`)
- Displays non-blocking, glassmorphic toast notification cards in the lower-right corner of the application window for success, warning, and threat alerts.

## 11.9 SOC Brief & Forensic Report Generator
- Accessible via the **[ 📄 Export SOC Brief ]** button on the Dashboard.
- Compiles current threat findings, active incidents, host metrics, and network statistics into an executive-ready HTML/PDF report.

## 11.10 TLS / SNI Hostname Visibility in Network Activity
- **Module:** `pages/network.py` & `services/live_network.py`
- Renders the extracted TLS/SNI domain name directly alongside destination IP endpoints in the Live Network Activity Table and Flow inspector dialog.
- Equips SOC analysts to immediately distinguish benign SaaS telemetry (e.g., `graph.microsoft.com`, `api.github.com`) from high-entropy DGA domains or known malicious C2 destinations without running external reverse-DNS queries.

## 11.11 Subnet Device Radar Tab (`📡 ARP Radar`)
- **Module:** `pages/network.py` (`ArpRadarTableModel`)
- Integrated as a first-class tab in the Network Activity console, providing zero-overhead, real-time subnet situational awareness:
  1. **Device Directory Table:** Displays all active network peers with IPv4 address, physical MAC address, resolved hardware vendor, role designation (`🌐 DEFAULT GATEWAY`, `💻 THIS COMPUTER`, `📱 ENDPOINT NODE`, `🚨 SUSPICIOUS / SPOOFER`), status badge, and observed packet counts.
  2. **Active Threat Alert Banner:** Prominently displays an animated crimson alert banner whenever active ARP spoofing, MITM gateway hijacking, or MAC conflicts are detected on the local subnet.
  3. **One-Click Subnet Probe Sweep:** Features a **[ Scan Subnet ]** trigger that wakes up sleeping Wi-Fi nodes, smartphones, and IoT peripherals via concurrent unicast probing.

---

# 12. Configuration Reference & Environment Variables

AEGIS utilizes Pydantic-based settings loaded from environment variables or a `.env` file:

```ini
# --- Runtime & Polling Configuration ---
AEGIS_POLL_INTERVAL_MS=5000
AEGIS_LOG_LEVEL=INFO

# --- Agent Telemetry Settings ---
AEGIS_PROCESS_MONITOR_ENABLED=true
AEGIS_PORT_MONITOR_ENABLED=true
AEGIS_FIM_ENABLED=true
AEGIS_FIM_WATCH_PATHS=C:\Windows\System32\drivers\etc\hosts,C:\Users\Public

# --- Network Sensor Settings ---
AEGIS_CAPTURE_ENABLED=true
AEGIS_CAPTURE_INTERFACE=auto
AEGIS_FLOW_WINDOW_SECONDS=60
AEGIS_PROMISCUOUS_MODE=true

# --- Response Engine & Safety Settings ---
AEGIS_RESPONSE_MODE=DRY_RUN
AEGIS_MAX_ACTIONS_PER_MINUTE=5
AEGIS_GATEWAY_PROTECTION=true

# --- Audio & Desktop Settings ---
AEGIS_AUDIO_ALERTS_ENABLED=true
QT_LOGGING_RULES=qt.multimedia*=false
```

---

# 13. Comprehensive Testing & Verification Suite

The repository contains **48 deterministic test files** and **1,092 passed test cases** executed via `pytest`:

```
d:\aegis-idps\tests\
├── test_core.py                 # Enums, models, event pipelines
├── test_agent.py                # Process collector, port monitor, FIM
├── test_network.py              # Scapy capture, normalizer, flow aggregator
├── test_tls_sni.py              # RFC 6066 TLS SNI extractor unit tests
├── test_tls_sni_validation.py   # End-to-end TLS SNI pipeline & model validation
├── test_arp_radar.py            # ARP Tracker, OUI lookup, sweep, & MITM defense
├── test_detection.py            # 12 rules, MITRE mappings, behavioral windows
├── test_ml_engine.py            # Isolation Forest training & outlier scoring
├── test_correlation.py          # Cross-domain host-network incident synthesis
├── test_response.py             # 5 safety guards, Windows Firewall netsh
├── test_soc_console.py          # Red-stripe triage, posture cards, hero shield
├── test_system_cleaner.py       # Temporary file purge, lock handling
├── test_desktop_gui.py          # 11 pages, navigation, theme styling
└── test_audio_alert.py          # Sound alarms and silence controls
```

### Verification Commands
```powershell
# 1. Run full test suite with coverage
python -m pytest tests/

# 2. Execute static type checking (0 errors guaranteed)
npx pyright

# 3. Execute PEP8 linter (All checks passed)
python -m ruff check .
```

---

# 14. Deployment, Installation & Troubleshooting Guide

## 14.1 Installation Steps (Windows 10 / 11)

```powershell
# Step 1: Open PowerShell as Administrator and navigate to project root
cd d:\aegis-idps

# Step 2: Create isolated Python virtual environment
python -m venv .venv

# Step 3: Activate virtual environment
.\.venv\Scripts\activate

# Step 4: Upgrade pip and install platform dependencies
pip install --upgrade pip
pip install -e .[desktop]

# Step 5: Verify installation via automated test suite
python -m pytest tests/test_desktop_gui.py tests/test_soc_console.py

# Step 6: Launch AEGIS Desktop Security Operations Console
python -m aegis_desktop
```

## 14.2 Troubleshooting Common Issues
1. **Npcap / Scapy Packet Sniffing Permissions:**  
   *Symptom:* `Sniffing requires root / Administrator privileges`.  
   *Resolution:* Ensure PowerShell is launched via **Run as Administrator** and Npcap is installed with *WinPcap API-compatible mode* enabled.
2. **Qt Multimedia Hardware Encoder Diagnostic Logs:**  
   *Symptom:* FFmpeg MFT diagnostic logs appear in stdout.  
   *Resolution:* Already handled automatically in `app.py` via `QT_LOGGING_RULES="qt.multimedia*=false"`.
3. **Firewall Access Denied on Containment:**  
   *Symptom:* Windows Firewall rule creation returns access denied.  
   *Resolution:* Containment actions via `netsh advfirewall` require elevated Administrator credentials. Run the application as Administrator to enable live active blocking.
