#Requires -Version 5.1
<#
.SYNOPSIS
  Launch the Streamlit dashboard on Windows using the local .venv.
  Opens http://localhost:8501 automatically.
#>
[CmdletBinding()]
param(
    [int]$Port = 8501
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root

$venvPython = Join-Path $Root '.venv\Scripts\python.exe'
$appPath = Join-Path $Root 'app\streamlit_app.py'
$url = "http://localhost:$Port"

if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host 'No virtual environment found.' -ForegroundColor Yellow
    Write-Host 'Run setup first:' -ForegroundColor Yellow
    Write-Host '  .\scripts\setup-windows.ps1'
    exit 1
}

if (-not (Test-Path -LiteralPath $appPath)) {
    Write-Host ("Missing app file: " + $appPath) -ForegroundColor Red
    exit 1
}

# Skip Streamlit first-run email prompt.
$streamlitDir = Join-Path $Root '.streamlit'
$userStreamlit = Join-Path $env:USERPROFILE '.streamlit'
New-Item -ItemType Directory -Force -Path $streamlitDir | Out-Null
New-Item -ItemType Directory -Force -Path $userStreamlit | Out-Null

$credBody = "[general]`r`nemail = `"`"`r`n"
foreach ($credPath in @(
        (Join-Path $streamlitDir 'credentials.toml'),
        (Join-Path $userStreamlit 'credentials.toml')
    )) {
    if (-not (Test-Path -LiteralPath $credPath)) {
        Set-Content -LiteralPath $credPath -Value $credBody -Encoding Ascii
    }
}

$env:STREAMLIT_BROWSER_GATHER_USAGE_STATS = 'false'

# Open the browser once the port accepts connections (backup if Streamlit does not).
$opener = @"
`$url = '$url'
for (`$i = 0; `$i -lt 40; `$i++) {
  try {
    `$r = Invoke-WebRequest -Uri `$url -UseBasicParsing -TimeoutSec 2
    if (`$r.StatusCode -ge 200) { Start-Process `$url; break }
  } catch {
    Start-Sleep -Milliseconds 500
  }
}
"@
$openerPath = Join-Path $env:TEMP 'm365-redteam-open-browser.ps1'
Set-Content -LiteralPath $openerPath -Value $opener -Encoding Ascii
Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $openerPath) -WindowStyle Hidden

Write-Host 'Starting M365 Red Team dashboard...' -ForegroundColor Cyan
Write-Host ("Opening browser at {0} when ready." -f $url)
Write-Host 'Leave this window open. Press Ctrl+C to stop.'
Write-Host ''

& $venvPython -m streamlit run $appPath `
    --server.port $Port `
    --server.address localhost `
    --browser.gatherUsageStats false

$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    Write-Host ''
    Write-Host ("Streamlit exited with code {0}." -f $exitCode) -ForegroundColor Red
    Write-Host 'If the browser said connection refused, the server did not stay up.' -ForegroundColor Yellow
    Write-Host 'Re-run setup, then try again:  .\scripts\setup-windows.ps1' -ForegroundColor Yellow
}
exit $exitCode