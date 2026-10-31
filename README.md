# M365 Red Team

Authorized **Microsoft 365 red team assessment** toolkit for Windows. Simulate how an attacker can compromise a Microsoft tenant, how far they can get, and which security barriers stop them.

> **Authorized use only.** Default config uses **demo mode** (no live tenant).

**Docs site:** https://vladjoh.github.io/RedTeam/

## Quick start (Windows)

Full guide: **[SETUP-WINDOWS.md](SETUP-WINDOWS.md)**

```powershell
# Open PowerShell inside the project folder, then:
.\scripts\setup-windows.ps1
.\scripts\run-assessment.ps1
```

Or double-click `scripts\setup-windows.cmd`, then `scripts\run-assessment.cmd`.

Dashboard: **http://localhost:8501**

## Attack profiles

| Profile | Access | Focus |
| --- | --- | --- |
| **External Attacker** | No login | Exposed services, identities, domains, entry paths |
| **Compromised User** | Standard user | Apps, data, groups, SharePoint, Teams, privilege escalation |
| **Compromised Admin** | Administrator | Privileges, app control, tenant config, blast radius |

## Test categories

- Attack surface discovery
- Identity security
- MFA / Conditional Access
- OAuth / Enterprise Applications
- Privilege escalation paths
- SharePoint / Exchange / Teams
- Lateral movement analysis
- Persistence risk assessment

## Architecture

- **Python** — assessment engine
- **Microsoft Graph API** — tenant data (user / admin)
- **MSAL** — authentication
- **PowerShell** — optional external probes
- **Streamlit** — local dashboard
- **OpenAI API** — optional attack-path narrative
- **HTML / PDF** — reports

Graph maps many controls; separate modules cover external/auth-flow checks Graph cannot exercise alone.

## Project layout

```
SETUP-WINDOWS.md     # start here on Windows
app/                 # Streamlit UI + assessment modules
config/              # example + local YAML config
docs/                # GitHub Pages site
powershell/          # optional Windows probes
scripts/             # setup-windows.ps1, run-assessment.ps1
tests/               # demo-mode smoke tests
```

## Development checks

```powershell
.\.venv\Scripts\python.exe -m pytest
```

## Safety defaults

- `read_only: true`
- `demo_mode: true`
- No destructive Graph writes

## License

Use for defensive security assessments under your organization’s policies and applicable law.