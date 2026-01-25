@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap-install.ps1" %*
set "EC=%ERRORLEVEL%"

if not "%EC%"=="0" (
  echo Revenix agent install failed. Exit code: %EC%
  exit /b %EC%
)

echo Revenix agent install completed.
exit /b 0
