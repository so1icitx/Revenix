param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [string]$ApiUrl = "http://localhost:8000",
    [string]$RedisUrl = "redis://localhost:6379",
    [string]$RedisPassword = "",
    [string]$NetworkInterface = "",
    [ValidateSet("true", "false")]
    [string]$PromiscuousMode = "true",
    [string]$InstallDir = "C:\ProgramData\RevenixAgent",
    [string]$TaskName = "RevenixCoreAgent"
)

$ErrorActionPreference = "Stop"

if (-not ([bool](net session 2>$null))) {
    throw "Run this script as Administrator."
}

if (-not (Test-Path $BinaryPath)) {
    throw "Binary not found: $BinaryPath"
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

$targetExe = Join-Path $InstallDir "revenix-core.exe"
Copy-Item -Path $BinaryPath -Destination $targetExe -Force

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$startScriptSrc = Join-Path $scriptDir "start-agent.ps1"
$startScriptDst = Join-Path $InstallDir "start-agent.ps1"
Copy-Item -Path $startScriptSrc -Destination $startScriptDst -Force

$envContent = @(
    "API_URL=$ApiUrl"
    "REDIS_URL=$RedisUrl"
    "REDIS_PASSWORD=$RedisPassword"
    "NETWORK_INTERFACE=$NetworkInterface"
    "PROMISCUOUS_MODE=$PromiscuousMode"
)
$envPath = Join-Path $InstallDir "agent.env"
$envContent | Set-Content -Path $envPath -Encoding ASCII

# Remove existing task if present.
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
}

$taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$startScriptDst`" -InstallDir `"$InstallDir`""
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgs
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Force `
    -ErrorAction Stop | Out-Null

Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop

Write-Host "Revenix Windows agent installed."
Write-Host "Install dir: $InstallDir"
Write-Host "Task name: $TaskName"
