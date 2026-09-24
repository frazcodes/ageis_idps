#!/usr/bin/env bash
# Bootstrap the Aegis IDPS development environment (Linux / macOS).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -e ".[dev,backend]"

if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "Created .env from .env.example (review it before running anything)."
fi

echo "Bootstrap complete. Activate with: source .venv/bin/activate"
echo "Desktop console: pip install -e '.[desktop]' then run: python -m aegis_desktop"
