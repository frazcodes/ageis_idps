#!/usr/bin/env pwsh
# Bootstrap the Aegis IDPS development environment (Windows / PowerShell).
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment (.venv)..."
    python -m venv .venv
}

$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
& $python -m pip install --upgrade pip
& $python -m pip install -e ".[dev,backend]"

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example (review it before running anything)."
}

Write-Host "Bootstrap complete. Activate with: .\.venv\Scripts\Activate.ps1"
Write-Host "Desktop console: pip install -e `".[desktop]`" then run: python -m aegis_desktop"
