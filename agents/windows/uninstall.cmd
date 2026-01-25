@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall-agent.ps1" %*
set "EC=%ERRORLEVEL%"

if not "%EC%"=="0" (
  echo Revenix agent uninstall failed. Exit code: %EC%
  exit /b %EC%
)

echo Revenix agent uninstall completed.
exit /b 0
