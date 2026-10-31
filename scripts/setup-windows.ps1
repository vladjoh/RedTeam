#Requires -Version 5.1
<#
.SYNOPSIS
  Bootstrap the M365 Red Team tool on a local Windows machine.

.DESCRIPTION
  Creates a Python venv, installs dependencies, and copies example config.
  Run from the repo root in PowerShell:

    .\scripts\setup-windows.ps1

  Do NOT wrap with: powershell -File ...
  That can break encoding. Prefer running the script directly in pwsh or Windows PowerShell.
#>
[CmdletBinding()]
param(
    [switch]$SkipVenv
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host '==> M365 Red Team - Windows setup' -ForegroundColor Cyan

function Get-PythonCommand {
    foreach ($name in @('py', 'python', 'python3')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            if ($name -eq 'py') {
                & $cmd.Source -3 --version 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) { return @{ Exe = $cmd.Source; Args = @('-3') } }
            } else {
                & $cmd.Source --version 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) { return @{ Exe = $cmd.Source; Args = @() } }
            }
        } catch {
            continue
        }
    }
    return $null
}

$python = Get-PythonCommand
if (-not $python) {
    Write-Host 'ERROR: Python 3.11+ was not found on PATH.' -ForegroundColor Red
    Write-Host 'Install from https://www.python.org/downloads/windows/' -ForegroundColor Yellow
    Write-Host 'During setup, check "Add python.exe to PATH".' -ForegroundColor Yellow
    exit 1
}

$pyArgs = $python.Args
Write-Host ("Found: " + (& $python.Exe @pyArgs --version))

$venvPython = Join-Path $Root '.venv\Scripts\python.exe'
$venvActivate = Join-Path $Root '.venv\Scripts\Activate.ps1'

if (-not $SkipVenv) {
    if (-not (Test-Path $venvPython)) {
        Write-Host 'Creating virtual environment (.venv)...'
        & $python.Exe @pyArgs -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Failed to create .venv' }
    } else {
        Write-Host 'Using existing .venv'
    }
}

if (-not (Test-Path $venvPython)) {
    throw 'Missing .venv\Scripts\python.exe - re-run without -SkipVenv'
}

Write-Host 'Installing Python packages (this can take a minute)...'
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'pip upgrade failed' }
& $venvPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'pip install -r requirements.txt failed' }

# Confirm streamlit is available inside the venv
& $venvPython -m streamlit --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'streamlit did not install correctly'
}
Write-Host ('Streamlit OK: ' + (& $venvPython -m streamlit --version))

if (-not (Test-Path '.\config\config.yaml')) {
    Copy-Item '.\config\config.example.yaml' '.\config\config.yaml'
    Write-Host 'Created config\config.yaml - edit tenant / client_id before live runs.' -ForegroundColor Yellow
}

if ((-not (Test-Path '.\.env')) -and (Test-Path '.\.env.example')) {
    Copy-Item '.\.env.example' '.\.env'
}

New-Item -ItemType Directory -Force -Path '.\output\reports' | Out-Null

Write-Host ''
Write-Host 'Setup complete.' -ForegroundColor Green
Write-Host 'Next step - start the dashboard:'
Write-Host '  .\scripts\run-assessment.ps1'
Write-Host ''
Write-Host 'Authorized assessments only. Keep demo_mode: true until you have written approval.' -ForegroundColor Yellow