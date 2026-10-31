#Requires -Version 5.1
<#
.SYNOPSIS
  Launch the Streamlit dashboard on Windows using the local .venv.
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

# Skip Streamlit first-run email prompt (this is what was killing the server).
$streamlitDir = Join-Path $Root '.streamlit'
$userStreamlit = Join-Path $env:USERPROFILE '.streamlit'
New-Item -ItemType Directory -Force -Path $streamlitDir | Out-Null
New-Item -ItemType Directory -Force -Path $userStreamlit | Out-Null

$credProject = Join-Path $streamlitDir 'credentials.toml'
$credUser = Join-Path $userStreamlit 'credentials.toml'
$credBody = "[general]`r`nemail = `"`"`r`n"
if (-not (Test-Path -LiteralPath $credProject)) {
    Set-Content -LiteralPath $credProject -Value $credBody -Encoding Ascii
}
if (-not (Test-Path -LiteralPath $credUser)) {
    Set-Content -LiteralPath $credUser -Value $credBody -Encoding Ascii
}

$configProject = Join-Path $streamlitDir 'config.toml'
if (-not (Test-Path -LiteralPath $configProject)) {
    $cfg = @(
        '[server]'
        'headless = true'
        ("port = {0}" -f $Port)
        'address = "localhost"'
        '[browser]'
        'gatherUsageStats = false'
    ) -join "`r`n"
    Set-Content -LiteralPath $configProject -Value $cfg -Encoding Ascii
}

$env:STREAMLIT_BROWSER_GATHER_USAGE_STATS = 'false'
$env:STREAMLIT_SERVER_HEADLESS = 'true'

Write-Host 'Starting M365 Red Team dashboard...' -ForegroundColor Cyan
Write-Host ("URL: http://localhost:{0}" -f $Port)
Write-Host 'Leave this window open. Press Ctrl+C to stop.'
Write-Host ''

& $venvPython -m streamlit run $appPath `
    --server.headless true `
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