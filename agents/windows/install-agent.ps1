param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [string]$ApiUrl = "http://localhost:8000",
    [string]$RedisUrl = "redis://localhost:6379",
    [string]$RedisPassword = "",
    [string]$InternalServiceToken = "",
    [string]$ApiBearerToken = "",
    [string]$NetworkInterface = "",
    [ValidateSet("true", "false")]
    [string]$PromiscuousMode = "true",
    [ValidateSet("true", "false")]
    [string]$FirewallSyncEnabled = "true",
    [int]$FirewallSyncInterval = 30,
    [string]$InstallDir = "C:\ProgramData\RevenixAgent",
    [string]$TaskName = "RevenixCoreAgent",
    [string]$FirewallTaskName = "RevenixFirewallAgent"
)

$ErrorActionPreference = "Stop"

function Test-IsTrue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return @("1", "true", "yes", "on") -contains $Value.Trim().ToLowerInvariant()
}

function Stop-AgentRuntime {
    param(
        [string]$CoreTaskName,
        [string]$FwTaskName
    )

    try {
        if (Get-ScheduledTask -TaskName $CoreTaskName -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName $CoreTaskName -ErrorAction SilentlyContinue
        }
    }
    catch {}

    try {
        if (Get-ScheduledTask -TaskName $FwTaskName -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName $FwTaskName -ErrorAction SilentlyContinue
        }
    }
    catch {}

    try {
        Get-Process -Name "revenix-core" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    catch {}

    Start-Sleep -Seconds 1
}

if (-not ([bool](net session 2>$null))) {
    throw "Run this script as Administrator."
}

if (-not (Test-Path $BinaryPath)) {
    throw "Binary not found: $BinaryPath"
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

Stop-AgentRuntime -CoreTaskName $TaskName -FwTaskName $FirewallTaskName

$targetExe = Join-Path $InstallDir "revenix-core.exe"
Copy-Item -Path $BinaryPath -Destination $targetExe -Force

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$startScriptSrc = Join-Path $scriptDir "start-agent.ps1"
$startScriptDst = Join-Path $InstallDir "start-agent.ps1"
$firewallScriptSrc = Join-Path $scriptDir "firewall-sync.ps1"
$firewallScriptDst = Join-Path $InstallDir "firewall-sync.ps1"
Copy-Item -Path $startScriptSrc -Destination $startScriptDst -Force
if (-not (Test-Path $firewallScriptSrc)) {
    throw "Missing firewall sync script: $firewallScriptSrc"
}
Copy-Item -Path $firewallScriptSrc -Destination $firewallScriptDst -Force

if ($FirewallSyncInterval -lt 5) {
    $FirewallSyncInterval = 5
}
if ($FirewallSyncInterval -gt 3600) {
    $FirewallSyncInterval = 3600
}

$envContent = @(
    "API_URL=$ApiUrl"
    "REDIS_URL=$RedisUrl"
    "REDIS_PASSWORD=$RedisPassword"
    "INTERNAL_SERVICE_TOKEN=$InternalServiceToken"
    "API_BEARER_TOKEN=$ApiBearerToken"
    "NETWORK_INTERFACE=$NetworkInterface"
    "PROMISCUOUS_MODE=$PromiscuousMode"
    "FIREWALL_SYNC_ENABLED=$FirewallSyncEnabled"
    "FIREWALL_SYNC_INTERVAL=$FirewallSyncInterval"
)
$envPath = Join-Path $InstallDir "agent.env"
$envContent | Set-Content -Path $envPath -Encoding ASCII

# Remove existing tasks if present.
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
}
$existingFirewallTask = Get-ScheduledTask -TaskName $FirewallTaskName -ErrorAction SilentlyContinue
if ($existingFirewallTask) {
    Unregister-ScheduledTask -TaskName $FirewallTaskName -Confirm:$false -ErrorAction Stop
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

if (Test-IsTrue -Value $FirewallSyncEnabled) {
    $firewallTaskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$firewallScriptDst`" -InstallDir `"$InstallDir`""
    $firewallAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $firewallTaskArgs
    $firewallTrigger = New-ScheduledTaskTrigger -AtStartup

    Register-ScheduledTask `
        -TaskName $FirewallTaskName `
        -Action $firewallAction `
        -Trigger $firewallTrigger `
        -Principal $principal `
        -Settings $settings `
        -Force `
        -ErrorAction Stop | Out-Null

    Start-ScheduledTask -TaskName $FirewallTaskName -ErrorAction Stop
}

Write-Host "Revenix Windows agent installed."
Write-Host "Install dir: $InstallDir"
Write-Host "Core task: $TaskName"
if (Test-IsTrue -Value $FirewallSyncEnabled) {
    Write-Host "Firewall task: $FirewallTaskName"
}
else {
    Write-Host "Firewall task: disabled (FIREWALL_SYNC_ENABLED=$FirewallSyncEnabled)"
}
