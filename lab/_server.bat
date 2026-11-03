@echo off
REM ============================================================
REM  AuditForwarder Server (监管端 / 服务机)
REM  Listens on 0.0.0.0:8443 for all LAN interfaces.
REM ============================================================
cd /d "%~dp0.."

set "EXE=build\auditforwarder-server.exe"
if not exist "%EXE%" (
  echo [ERROR] server exe not found at %EXE%
  pause
  exit /b 1
)

echo server  : %EXE%
echo config  : config\server_windows.yaml
echo data    : data\server
echo listen  : 0.0.0.0:8443  (all interfaces)
echo.
echo LAN IPs for clients to connect to:
for /f "tokens=*" %%i in ('powershell -NoProfile -Command "Get-NetIPAddress -AddressFamily IPv4 ^| Where-Object { $_.IPAddress -notmatch '^127\.^|^169\.254' } ^| Select-Object -ExpandProperty IPAddress"') do echo   %%i
echo.
echo Login: admin / admin123
echo Press Ctrl+C to stop.
echo ============================================================
"%EXE%" -c config/server_windows.yaml -d data/server
pause
