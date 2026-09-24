# Aegis IDPS

AI-Powered Hybrid Host and Network Intrusion Detection and Prevention System.

Aegis combines endpoint telemetry and passive network monitoring, scores activity
with anomaly detection, correlates it into incidents, and can respond through a
strictly policy-gated response engine. This repository is a monorepo: every
component shares one event schema and one vocabulary.

> **Status: active development.** The security foundation (Steps 1-9), the native
> desktop console shell (GUI-1) and its read-only dashboard (GUI-2) are implemented
> and tested. ML, correlation and IPS/response remain intentionally **not
> implemented**, and every security-sensitive feature is disabled by default.

## Repository layout

```
aegis-idps/
├── desktop/          Native desktop administrator console (PySide6/Qt)
├── backend/          FastAPI service: ingestion, persistence, correlation, auth/RBAC
├── agent/            Endpoint agent: processes, ports, file integrity, YARA, inventory
├── network-sensor/   Passive NIDS: capture, packet normalization, telemetry events
├── ml-engine/        Feature extraction and anomaly/risk scoring
├── response-engine/  Policy-gated IPS actions (monitor-only by default)
├── shared/           Cross-component contracts: event schema, enums, config, logging
├── tests/            Cross-component test suite
├── docs/             Architecture and development documentation
├── scripts/          Bootstrap scripts
├── docker-compose.yml  Development PostgreSQL
└── pyproject.toml    Monorepo packaging, lint, type and test configuration
```

See [`docs/architecture.md`](docs/architecture.md) for component responsibilities
and the data flow.

## Quick start

```powershell
# Windows
./scripts/bootstrap.ps1
```

```bash
# Linux / macOS
./scripts/bootstrap.sh
```

Then:

```bash
docker compose up -d postgres           # optional: development database
uvicorn aegis_backend.main:app --reload # API on http://127.0.0.1:8000

# Native desktop administrator console
pip install -e ".[desktop]"
python -m aegis_desktop
```

Full instructions are in [`docs/development.md`](docs/development.md).

## The shared event contract

Every observation - a process starting on an endpoint, a flow summary from the
sensor, a risk score from the ML engine - is a
`aegis_shared.events.SecurityEvent`. It is immutable, its top-level fields are
closed (schema drift fails loudly), and its timestamps must be timezone-aware UTC.

```python
from aegis_shared import EventType, HostRef, SecurityEvent, Severity, SourceKind, SourceRef

event = SecurityEvent.create(
    event_type=EventType.PROCESS_STARTED,
    severity=Severity.INFO,
    source=SourceRef(kind=SourceKind.AGENT, id="agent-01"),
    host=HostRef(host_id="host-01", hostname="ws-01"),
)
```

## Safety defaults

Security software must fail safe. Nothing invasive happens unless explicitly
enabled:

| Component | Default |
| --- | --- |
| Desktop console | Read-only; starts no monitor and performs no response. |
| Endpoint agent | All monitors disabled. |
| Network sensor | Packet capture disabled. |
| Response engine | `monitor` mode, `dry_run=true`, approval required. |
| Backend | Authentication/RBAC not yet implemented; do not expose publicly. |

Never commit secrets. Copy `.env.example` to `.env` and populate it locally.

## Tooling

```bash
pytest
ruff check .
ruff format --check .
mypy
```

## License

Proprietary. See `pyproject.toml`.
