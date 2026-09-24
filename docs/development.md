# Development

## Prerequisites

* Python 3.11+ (3.12 recommended)
* PostgreSQL 15+ (or Docker for the bundled compose file)
* Git

## One-time setup

Windows (PowerShell):

```powershell
./scripts/bootstrap.ps1
```

Linux/macOS:

```bash
./scripts/bootstrap.sh
```

Both scripts create `.venv`, install the Python packages in editable mode, and
copy `.env.example` to `.env`.

## Manual setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
# POSIX:   source .venv/bin/activate

pip install -e ".[dev]"              # shared + tests + lint/type tooling
pip install -e ".[backend]"          # optional: FastAPI backend
pip install -e ".[agent]"            # optional: endpoint agent (psutil)
pip install -e ".[desktop]"          # optional: native desktop console (PySide6)

cp .env.example .env
```

## Running

```bash
# Backend API
uvicorn aegis_backend.main:app --reload

# Endpoint agent - status (default command)
python -m aegis_agent

# Endpoint agent - system inventory (read-only)
python -m aegis_agent inventory
python -m aegis_agent inventory --json

# Endpoint agent - one-shot read-only snapshots
python -m aegis_agent processes
python -m aegis_agent processes --json
python -m aegis_agent ports
python -m aegis_agent ports --json

# File integrity: inspect explicit paths only (nothing is scanned by default)
python -m aegis_agent files --path ./some/directory
python -m aegis_agent files --path ./some/directory --json

# Host event pipeline demonstration (deterministic, in-memory, no transmission)
python -m aegis_agent events
python -m aegis_agent events --json

# Deterministic detection engine over synthetic events (no capture/privileges)
python -m aegis_agent detect
python -m aegis_agent detect --json

# Explainable risk scoring over synthetic findings (no ML/privileges)
python -m aegis_agent risk
python -m aegis_agent risk --json

# Network sensor (passive, read-only)
python -m aegis_network_sensor                  # status
python -m aegis_network_sensor interfaces       # list capture interfaces (no privileges)
python -m aegis_network_sensor capture --count 5  # only if capture is explicitly enabled

# Native desktop administrator console (read-only)
python -m aegis_desktop
```

Start PostgreSQL (and nothing else) with:

```bash
docker compose up -d postgres
```

## Quality gates

```bash
pytest                # tests
ruff check .          # lint (includes bandit-style security rules)
ruff format --check . # formatting
mypy                  # type checking
```

## Conventions

* Python packages are named `aegis_<component>` and use `from __future__ import annotations`.
* Public functions and models carry type hints; docstrings explain *why*, not *what*.
* Configuration comes from `AEGIS_*` environment variables - never hardcode secrets or paths.
* New event types are appended to `aegis_shared.enums.EventType`; never rename existing values.
* `aegis_shared` must not import from any other Aegis package.
