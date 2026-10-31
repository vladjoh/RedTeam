@echo off
setlocal
cd /d "%~dp0\.."

if not exist ".venv\Scripts\python.exe" (
  echo No virtual environment found.
  echo Run scripts\setup-windows.cmd first.
  pause
  exit /b 1
)

if not exist ".streamlit" mkdir ".streamlit"
if not exist "%USERPROFILE%\.streamlit" mkdir "%USERPROFILE%\.streamlit"

if not exist ".streamlit\credentials.toml" (
  >".streamlit\credentials.toml" echo [general]
  >>".streamlit\credentials.toml" echo email = ""
)
if not exist "%USERPROFILE%\.streamlit\credentials.toml" (
  >"%USERPROFILE%\.streamlit\credentials.toml" echo [general]
  >>"%USERPROFILE%\.streamlit\credentials.toml" echo email = ""
)

set STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
set STREAMLIT_SERVER_HEADLESS=true

echo Starting dashboard at http://localhost:8501
echo Leave this window open. Press Ctrl+C to stop.
echo.

".venv\Scripts\python.exe" -m streamlit run "app\streamlit_app.py" --server.headless true --server.port 8501 --server.address localhost --browser.gatherUsageStats false
set ERR=%ERRORLEVEL%
if not "%ERR%"=="0" (
  echo.
  echo Streamlit exited with code %ERR%.
  echo Connection refused usually means the server stopped - scroll up for the error.
)
echo.
pause
exit /b %ERR%