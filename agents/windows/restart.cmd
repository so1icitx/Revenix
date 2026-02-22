@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0control-agent.ps1" -Action restart %*
exit /b %ERRORLEVEL%
