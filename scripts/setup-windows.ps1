<#
.SYNOPSIS
  Bootstrap the M365 Red Team tool on a local Windows machine.
#>
[CmdletBinding()]
param(
    [switch]$SkipVenv
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "==> M365 Red Team — Windows setup" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3.11+ is required. Install from https://www.python.org/downloads/windows/ and re-run."
}

$pyVer = python --version
Write-Host "Found $pyVer"

if (-not $SkipVenv) {
    if (-not (Test-Path .\.venv)) {
        python -m venv .venv
    }
    & .\.venv\Scripts\Activate.ps1
}

python -m pip install --upgrade pip
pip install -r requirements.txt

if (-not (Test-Path .\config\config.yaml)) {
    Copy-Item .\config\config.example.yaml .\config\config.yaml
    Write-Host "Created config\config.yaml — edit tenant / client_id before live runs." -ForegroundColor Yellow
}

if (-not (Test-Path .\.env) -and (Test-Path .\.env.example)) {
    Copy-Item .\.env.example .\.env
}

New-Item -ItemType Directory -Force -Path .\output\reports | Out-Null

Write-Host ""
Write-Host "Setup complete. Launch with:" -ForegroundColor Green
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  streamlit run app\streamlit_app.py"
Write-Host ""
Write-Host "Authorized assessments only. Keep demo_mode: true until you have written approval." -ForegroundColor Yellow