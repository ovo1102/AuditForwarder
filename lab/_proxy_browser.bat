@echo off
chcp 65001 >nul
set PROXY=http://127.0.0.1:8888
set PROFILE=%TEMP%\af_proxy_profile

set CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe
if not exist "%CHROME%" set CHROME=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe
if not exist "%CHROME%" set CHROME=%LocalAppData%\Google\Chrome\Application\chrome.exe

if exist "%CHROME%" (
    echo [OK] Chrome: %CHROME%
    start "" "%CHROME%" --proxy-server=%PROXY% --user-data-dir="%PROFILE%" --new-window http://26.17.173.34:18080
    exit /b 0
)

set EDGE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe
if not exist "%EDGE%" set EDGE=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe
if exist "%EDGE%" (
    echo [OK] Edge: %EDGE%
    start "" "%EDGE%" --proxy-server=%PROXY% --user-data-dir="%PROFILE%" --new-window http://26.17.173.34:18080
    exit /b 0
)

echo [FAIL] 未找到 Chrome 或 Edge
pause
