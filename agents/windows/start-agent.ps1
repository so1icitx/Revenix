param(
    [string]$InstallDir = "C:\ProgramData\RevenixAgent"
)

$ErrorActionPreference = "Stop"

$envFile = Join-Path $InstallDir "agent.env"
$exePath = Join-Path $InstallDir "revenix-core.exe"

if (-not (Test-Path $exePath)) {
    Write-Error "Agent binary not found: $exePath"
}

if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        $parts = $line.Split("=", 2)
        if ($parts.Count -eq 2) {
            $name = $parts[0].Trim()
            $value = $parts[1].Trim()
            [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

# Ensure Npcap runtime DLLs are discoverable for SYSTEM/service contexts.
$npcapRuntimeDir = Join-Path $env:SystemRoot "System32\Npcap"
$npcapWpcap = Join-Path $npcapRuntimeDir "wpcap.dll"
if (Test-Path $npcapWpcap) {
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", "Process")
    $pathParts = @()
    if (-not [string]::IsNullOrWhiteSpace($currentPath)) {
        $pathParts = $currentPath.Split(";") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    $alreadyPresent = $false
    foreach ($p in $pathParts) {
        if ($p.TrimEnd("\").ToLowerInvariant() -eq $npcapRuntimeDir.TrimEnd("\").ToLowerInvariant()) {
            $alreadyPresent = $true
            break
        }
    }

    if (-not $alreadyPresent) {
        $newPath = "$npcapRuntimeDir;$currentPath"
        [System.Environment]::SetEnvironmentVariable("Path", $newPath, "Process")
    }
}

Write-Host "Starting Revenix agent from $exePath"
$logDir = Join-Path $InstallDir "logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$supervisorLog = Join-Path $logDir "agent-supervisor.log"

while ($true) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $stdoutLog = Join-Path $logDir "core-$stamp.stdout.log"
    $stderrLog = Join-Path $logDir "core-$stamp.stderr.log"
    $startedAt = Get-Date

    Add-Content -Path $supervisorLog -Value "[$startedAt] Starting revenix-core.exe"

    try {
        $proc = Start-Process `
            -FilePath $exePath `
            -NoNewWindow `
            -Wait `
            -PassThru `
            -RedirectStandardOutput $stdoutLog `
            -RedirectStandardError $stderrLog
        $exitCode = $proc.ExitCode
    }
    catch {
        $exitCode = -1
        Add-Content -Path $supervisorLog -Value "[$(Get-Date)] Failed to start core: $($_.Exception.Message)"
    }

    if ($exitCode -eq 0) {
        Add-Content -Path $supervisorLog -Value "[$(Get-Date)] Core exited with code 0. Restarting in 5s."
        Start-Sleep -Seconds 5
    }
    else {
        Add-Content -Path $supervisorLog -Value "[$(Get-Date)] Core exited with code $exitCode. Restarting in 10s. Logs: $stdoutLog ; $stderrLog"
        Start-Sleep -Seconds 10
    }
}
