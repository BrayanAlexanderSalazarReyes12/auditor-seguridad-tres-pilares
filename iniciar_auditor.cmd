@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\pythonw.exe" (
  start "Auditor de Ciberseguridad" ".venv\Scripts\pythonw.exe" "interfaz_auditor.py"
) else (
  start "Auditor de Ciberseguridad" pyw -3.11 "interfaz_auditor.py"
)
endlocal

