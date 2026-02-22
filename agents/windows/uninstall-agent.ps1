param(
    [string]$InstallDir = "C:\ProgramData\RevenixAgent",
    [string]$TaskName = "RevenixCoreAgent",
    [string]$FirewallTaskName = "RevenixFirewallAgent"
)

$ErrorActionPreference = "Stop"

if (-not ([bool](net session 2>$null))) {
    throw "Run this script as Administrator."
}

schtasks /Query /TN $TaskName *> $null
if ($LASTEXITCODE -eq 0) {
    schtasks /End /TN $TaskName *> $null
    schtasks /Delete /TN $TaskName /F | Out-Null
}

schtasks /Query /TN $FirewallTaskName *> $null
if ($LASTEXITCODE -eq 0) {
    schtasks /End /TN $FirewallTaskName *> $null
    schtasks /Delete /TN $FirewallTaskName /F | Out-Null
}

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
}

Write-Host "Revenix Windows agent removed."
