@echo off
REM Double-click friendly launcher for setup (uses PowerShell in this folder).
cd /d "%~dp0\.."
echo Running setup-windows.ps1 ...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%cd%'; & '.\scripts\setup-windows.ps1'"
if errorlevel 1 (
  echo.
  echo Setup failed. Read SETUP-WINDOWS.md for help.
  pause
  exit /b 1
)
echo.
pause