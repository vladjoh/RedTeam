# M365 Red Team

Authorized **Microsoft 365 red team assessment** toolkit for Windows. Simulate how an attacker can compromise a Microsoft tenant, how far they can get, and which security barriers stop them.

> **Authorized use only.** Run against tenants you own or have written permission to assess. Default configuration uses **demo mode** (no live tenant connection).

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
- **Microsoft Graph API** — tenant data mapping (user / admin)  
- **MSAL** — authentication  
- **PowerShell** — selected external / control probes  
- **Streamlit** — local dashboard  
- **OpenAI API** — optional attack-path narrative  
- **HTML / PDF** — reports  

Graph can map and validate many controls, but cannot alone exercise every real-world attack test. External and auth-flow modules cover those gaps with controlled, read-only probes.

## Quick start (Windows)

```powershell
git clone https://github.com/vladjoh/RedTeam.git
cd RedTeam
powershell -ExecutionPolicy Bypass -File .\scripts\setup-windows.ps1
.\scripts\run-assessment.ps1
```

1. Edit `config\config.yaml` (created from the example).  
2. Keep `demo_mode: true` until you are ready for a live authorized run.  
3. For live **User** / **Admin** profiles, register an Entra ID public client (or confidential app), set `client_id`, disable demo mode, and click **Authenticate (MSAL)** in the sidebar.  
4. Optional AI summaries: set `openai.enabled: true` and provide an API key.  

### PowerShell companion checks

```powershell
.\powershell\Invoke-M365ControlChecks.ps1 -TenantDomain contoso.onmicrosoft.com -Profile external
```

## Documentation site

Project overview and install instructions are published via GitHub Pages from the `docs/` folder:

**https://vladjoh.github.io/RedTeam/**

Enable Pages in the repository settings (Source: GitHub Actions) if the site is not live yet. The workflow is `.github/workflows/pages.yml`.

## Project layout

```
app/                 # Streamlit UI, modules, auth, AI, reports
config/              # Example + local YAML config
docs/                # GitHub Pages site
powershell/          # Optional Windows control probes
scripts/             # setup-windows.ps1, run-assessment.ps1
tests/               # Demo-mode smoke tests
```

## Development

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest
streamlit run app\streamlit_app.py
```

## Safety defaults

- `read_only: true` — modules perform read / discovery probes only  
- `demo_mode: true` — simulated findings until you opt into live Graph  
- No destructive Graph writes are included in this toolkit  

## License

Use for defensive security assessments under your organization’s policies and applicable law.