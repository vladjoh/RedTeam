# M365 Red Team

**External Entra / Microsoft 365 domain scan** for authorized teams on Windows.

Enter a domain → get **High / Medium / Low** findings in a few seconds → see the **most likely bypass path** (and what is less likely) → download an HTML report.

> **Authorized use only.** Get written permission, tell the tenant owner before you scan, and verify findings before changing controls. Public signals are also visible to attackers.

**Docs:** https://vladjoh.github.io/RedTeam/

## Quick start (Windows)

```powershell
.\scripts\setup-windows.ps1
.\scripts\run-assessment.ps1
```

Browser opens `http://localhost:8501`. Full guide: [SETUP-WINDOWS.md](SETUP-WINDOWS.md).

## What it checks

Tenant fingerprint · federation / ADFS hints · GetCredentialType · SPF/DKIM/DMARC · SharePoint/EXO surfaces · MFA-gap classes (ROPC, device-code, Basic) · OAuth consent risk · Azure dangling CNAMEs · Power Pages OData probes.

## Safety

- Read-only public endpoints
- External-only product (no user/admin Graph modes in this build)
- Always verify on the target tenant