@echo off
REM ============================================================
REM  M3 client (operator admin3, host_id lab-pc3)
REM  Runs from the repo root so data/log paths resolve.
REM ============================================================
cd /d "%~dp0.."

set "EXE=build\Release\auditforwarder-client.exe"
if not exist "%EXE%" set "EXE=build\auditforwarder-client.exe"
if not exist "%EXE%" (
  echo [ERROR] client exe not found. Build first or copy the build folder.
  pause
  exit /b 1
)

echo client : %EXE%
echo config : config\client_lab_peer3.yaml
echo data   : data\client3
echo proxy  : 127.0.0.1:8888

start "Client M3 (admin3)" /D "%CD%" cmd /k "chcp 65001>nul & %EXE% -c config\client_lab_peer3.yaml -d data\client3"
