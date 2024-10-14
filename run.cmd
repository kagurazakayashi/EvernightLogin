@echo off
rem run.cmd - run entry wrapper: forwards to run.ps1 (same args and exit codes).
rem Examples: run.cmd -List    run.cmd -Program login-server -- --version
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
