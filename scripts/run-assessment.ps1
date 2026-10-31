#Requires -Version 5.1
<#
.SYNOPSIS
  Launch the Streamlit dashboard on Windows using the local .venv.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$venvPython = Join-Path $Root '.venv\Scripts\python.exe'

if (-not (Test-Path $venvPython)) {
    Write-Host 'No virtual environment found.' -ForegroundColor Yellow
    Write-Host 'Run setup first:' -ForegroundColor Yellow
    Write-Host '  .\scripts\setup-windows.ps1'
    exit 1
}

Write-Host 'Starting M365 Red Team dashboard...' -ForegroundColor Cyan
Write-Host 'Browser should open at http://localhost:8501'
Write-Host 'Press Ctrl+C to stop.'
Write-Host ''

& $venvPython -m streamlit run (Join-Path $Root 'app\streamlit_app.py')
exit $LASTEXITCODE