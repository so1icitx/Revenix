param(
    [ValidateSet("status", "start", "stop", "restart")]
    [string]$Action = "status",
    [string]$TaskName = "RevenixCoreAgent",
    [string]$FirewallTaskName = "RevenixFirewallAgent"
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-TaskSafe {
    param([string]$Name)
    return Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
}

function Start-TaskSafe {
    param([string]$Name)

    $task = Get-TaskSafe -Name $Name
    if (-not $task) {
        Write-Host "Task missing: $Name"
        return
    }

    Start-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    $info = Get-ScheduledTaskInfo -TaskName $Name -ErrorAction SilentlyContinue
    Write-Host "Started $Name (State=$($task.State) LastResult=$($info.LastTaskResult))"
}

function Stop-TaskSafe {
    param([string]$Name)

    $task = Get-TaskSafe -Name $Name
    if (-not $task) {
        Write-Host "Task missing: $Name"
        return
    }

    Stop-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "Stopped $Name"
}

function Print-TaskStatus {
    param([string]$Name)

    $task = Get-TaskSafe -Name $Name
    if (-not $task) {
        Write-Host "${Name}: missing"
        return
    }

    $info = Get-ScheduledTaskInfo -TaskName $Name -ErrorAction SilentlyContinue
    Write-Host ("{0}: State={1} LastRun={2} LastResult={3}" -f $Name, $task.State, $info.LastRunTime, $info.LastTaskResult)
}

if ($Action -ne "status" -and -not (Test-IsAdmin)) {
    throw "Run as Administrator for action '$Action'."
}

switch ($Action) {
    "status" {
        Print-TaskStatus -Name $TaskName
        Print-TaskStatus -Name $FirewallTaskName
        $coreProcs = @(Get-Process -Name "revenix-core" -ErrorAction SilentlyContinue)
        Write-Host ("revenix-core processes: {0}" -f $coreProcs.Count)
    }
    "start" {
        Start-TaskSafe -Name $TaskName
        Start-TaskSafe -Name $FirewallTaskName
        Print-TaskStatus -Name $TaskName
        Print-TaskStatus -Name $FirewallTaskName
    }
    "stop" {
        Stop-TaskSafe -Name $FirewallTaskName
        Stop-TaskSafe -Name $TaskName
        Get-Process -Name "revenix-core" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "Stopped orphan revenix-core processes (if any)."
        Print-TaskStatus -Name $TaskName
        Print-TaskStatus -Name $FirewallTaskName
    }
    "restart" {
        Stop-TaskSafe -Name $FirewallTaskName
        Stop-TaskSafe -Name $TaskName
        Get-Process -Name "revenix-core" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-TaskSafe -Name $TaskName
        Start-TaskSafe -Name $FirewallTaskName
        Print-TaskStatus -Name $TaskName
        Print-TaskStatus -Name $FirewallTaskName
    }
}
