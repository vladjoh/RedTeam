# Windows setup

## 1. Install Python 3.11+

https://www.python.org/downloads/windows/ — check **Add python.exe to PATH**.

## 2. Open the project folder in PowerShell

```powershell
git clone https://github.com/vladjoh/RedTeam.git
cd RedTeam
```

## 3. Setup and run

```powershell
.\scripts\setup-windows.ps1
.\scripts\run-assessment.ps1
```

Leave the window open. The browser should open **http://localhost:8501**.

## 4. Scan

1. Enter an **authorized** domain  
2. Click **Start external scan**  
3. Read **High / Medium / Low** and the **most likely bypass**  
4. Download the HTML report  

Tell the tenant owner you are scanning. Verify findings before remediating.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| Connection refused | Setup/run again; leave the PowerShell window open |
| Script blocked | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Python not found | Reinstall with PATH checked; new terminal |