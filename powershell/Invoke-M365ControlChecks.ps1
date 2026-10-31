<#
.SYNOPSIS
  Optional Microsoft 365 control checks that complement Graph-based modules.

.DESCRIPTION
  Read-only helpers for Windows local runs. Requires ExchangeOnlineManagement /
  Microsoft.Graph PowerShell modules where noted. Does not modify tenant state.

.PARAMETER TenantDomain
  Target tenant domain (e.g. contoso.onmicrosoft.com)

.PARAMETER Profile
  external | user | admin

.EXAMPLE
  .\Invoke-M365ControlChecks.ps1 -TenantDomain contoso.onmicrosoft.com -Profile external
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantDomain,

    [ValidateSet('external', 'user', 'admin')]
    [string]$Profile = 'external',

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
        profile  = $Profile
        tenant   = $TenantDomain
        whenUtc  = (Get-Date).ToUniversalTime().ToString('o')
    }
}

Write-Host "M365 Red Team — PowerShell control checks" -ForegroundColor Cyan
Write-Host "Tenant: $TenantDomain | Profile: $Profile" -ForegroundColor DarkCyan

# External: OpenID configuration probe (no auth)
try {
    $oidc = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantDomain/.well-known/openid-configuration" -TimeoutSec 20
    Add-Result -Name 'openid_configuration' -Status 'info' -Detail ("issuer=" + $oidc.issuer)
}
catch {
    Add-Result -Name 'openid_configuration' -Status 'error' -Detail $_.Exception.Message
}

# External: realm discovery sample
try {
    $realmUri = "https://login.microsoftonline.com/getuserrealm.srf?login=probe@$TenantDomain"
    $realm = Invoke-WebRequest -Uri $realmUri -TimeoutSec 20
    Add-Result -Name 'get_user_realm' -Status 'medium' -Detail ("HTTP " + $realm.StatusCode + "; body length " + $realm.Content.Length)
}
catch {
    Add-Result -Name 'get_user_realm' -Status 'error' -Detail $_.Exception.Message
}

if ($Profile -ne 'external') {
    Add-Result -Name 'graph_powershell_hint' -Status 'info' -Detail 'Connect with Connect-MgGraph -Scopes Policy.Read.All,Directory.Read.All for CA / role checks when authorized.'
}

$dir = Split-Path -Parent $OutputPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$results | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Wrote $OutputPath" -ForegroundColor Green
$results | Format-Table -AutoSize