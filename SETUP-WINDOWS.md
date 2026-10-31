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

**Keep that window open.** When it works you should see a line like `You can now view your Streamlit app in your browser` and the prompt should **not** return.

Then open **http://localhost:8501**.

You are in **demo mode** by default (no real tenant connection). Click **Start Red Team Assessment**.

## 5. Stop

Press `Ctrl+C` in the PowerShell window.

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `localhost refused to connect` / `ERR_CONNECTION_REFUSED` | The Streamlit window exited. Re-download latest scripts, run `.\scripts\setup-windows.ps1`, then `.\scripts\run-assessment.ps1` and **leave it open**. Do not press Enter at any email prompt. |
| Streamlit asks for Email and then quits | Fixed in latest scripts (credentials are auto-created). Update the repo and re-run setup + run. |
| `python` / `py` not found | Reinstall Python with "Add to PATH", open a **new** terminal |
| `Unexpected token '}'` | Old script copy. Download latest `main` and run `.\scripts\setup-windows.ps1` directly |
| `streamlit` not recognized | Use `.\scripts\run-assessment.ps1` (not a bare `streamlit` command) |
| Script blocked | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| OneDrive path issues | Move the folder to e.g. `C:\Dev\RedTeam` and retry |

## Optional: live tenant later

1. Edit `config\config.yaml`
2. Set your tenant domain and Entra app `client_id`
3. Set `demo_mode: false`
4. Restart the dashboard and use **Authenticate (MSAL)** for User/Admin profiles

Authorized assessments only.