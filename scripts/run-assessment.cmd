@echo off
REM Double-click friendly launcher for the dashboard.
cd /d "%~dp0\.."
if not exist ".venv\Scripts\python.exe" (
  echo No virtual environment found.
  echo Run scripts\setup-windows.cmd first.
  pause
  exit /b 1
)
echo Starting dashboard at http://localhost:8501
".venv\Scripts\python.exe" -m streamlit run "app\streamlit_app.py"
pause