@echo off
rem build.cmd - step179 cmd wrapper: forwards to build.ps1 (same args and exit codes).
rem Example: build.cmd -Version 1.0.0 -Products all
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%