# Windows setup (start here)

Follow these steps in order. Takes a few minutes the first time.

## 1. Install Python (once)

1. Download Python 3.11+ from https://www.python.org/downloads/windows/
2. Run the installer
3. **Check** "Add python.exe to PATH"
4. Open a **new** PowerShell window and verify:

```powershell
py -3 --version
```

If that fails, try `python --version`.

## 2. Open the project folder

If you downloaded the ZIP: unzip it, then open the folder (example: `RedTeam-main`).

If you use Git:

```powershell
git clone https://github.com/vladjoh/RedTeam.git
cd RedTeam
```

In File Explorer: open the folder → right-click empty space → **Open in Terminal** (or run `pwsh` / PowerShell there).

## 3. Run setup

**Option A — PowerShell (recommended)**

```powershell
.\scripts\setup-windows.ps1
```

**Option B — double-click**

Double-click `scripts\setup-windows.cmd`

Wait until you see **Setup complete.**

### Important

- Prefer `.\scripts\setup-windows.ps1` inside the project folder.
- Avoid `powershell -File .\scripts\setup-windows.ps1` from older copies — use the latest scripts from this repo.
- If Windows blocks scripts, run once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then run setup again.

## 4. Start the dashboard

**Option A — PowerShell**

```powershell
.\scripts\run-assessment.ps1
```

**Option B — double-click**

Double-click `scripts\run-assessment.cmd`

Your browser should open **http://localhost:8501**.

You are in **demo mode** by default (no real tenant connection). Click **Start Red Team Assessment**.

## 5. Stop

Press `Ctrl+C` in the PowerShell window.

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `python` / `py` not found | Reinstall Python with "Add to PATH", open a **new** terminal |
| `Unexpected token '}'` | You are on an old script copy, or used `powershell -File`. Pull/download latest and run `.\scripts\setup-windows.ps1` directly |
| `streamlit` not recognized | Setup did not finish. Run `.\scripts\setup-windows.ps1` again, then `.\scripts\run-assessment.ps1` (do not call `streamlit` yourself) |
| Script blocked | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| OneDrive path issues | Move the folder to e.g. `C:\Dev\RedTeam` and retry |

## Optional: live tenant later

1. Edit `config\config.yaml`
2. Set your tenant domain and Entra app `client_id`
3. Set `demo_mode: false`
4. Restart the dashboard and use **Authenticate (MSAL)** for User/Admin profiles

Authorized assessments only.