<#
.SYNOPSIS
  Launch the Streamlit dashboard on Windows.
#>
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
if (Test-Path .\.venv\Scripts\Activate.ps1) {
    & .\.venv\Scripts\Activate.ps1
}
streamlit run app\streamlit_app.py