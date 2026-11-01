<#
.SYNOPSIS
  Optional local helpers that complement the external Entra domain scan.

.DESCRIPTION
  Read-only Windows helpers. Does not modify tenant state.
  The product itself is external-only (domain scan via Streamlit).

.PARAMETER TenantDomain
  Target domain (e.g. contoso.com)

.EXAMPLE
  .\Invoke-M365ControlChecks.ps1 -TenantDomain contoso.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantDomain,

    [string]$OutputPath = '.\output\powershell-checks.json'
)

$ErrorActionPreference = 'Stop'
$results = @()

function Add-Result {
    param($Name, $Status, $Detail)
    $script:results += [pscustomobject]@{
        name     = $Name
        status   = $Status
        detail   = $Detail
        profile  = 'external'
        tenant   = $TenantDomain
        whenUtc  = (Get-Date).ToUniversalTime().ToString('o')
    }
}

Add-Result -Name 'ProductMode' -Status 'Info' -Detail 'External-only domain scan. Use .\scripts\run-assessment.ps1 for the UI.'
Add-Result -Name 'TargetDomain' -Status 'Info' -Detail $TenantDomain

# Lightweight public DNS hints (no Graph)
try {
    $mx = Resolve-DnsName -Name $TenantDomain -Type MX -ErrorAction Stop
    Add-Result -Name 'MX' -Status 'Ok' -Detail (($mx | ForEach-Object { $_.NameExchange }) -join ', ')
} catch {
    Add-Result -Name 'MX' -Status 'Warn' -Detail $_.Exception.Message
}

$dir = Split-Path -Parent $OutputPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$results | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Wrote $OutputPath ($($results.Count) checks)"
