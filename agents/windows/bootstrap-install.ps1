param(
    [string]$BinaryPath = ".\revenix-core.exe",
    [string]$ConfigPath = "",
    [string]$NpcapInstallerPath = "",
    [string]$VcRedistInstallerPath = "",
    [string]$InstallDir = "C:\ProgramData\RevenixAgent",
    [string]$TaskName = "RevenixCoreAgent",
    [string]$FirewallTaskName = "RevenixFirewallAgent",
    [string]$ApiUrl = "",
    [string]$RedisUrl = "",
    [string]$RedisPassword = "",
    [string]$InternalServiceToken = "",
    [string]$ApiBearerToken = "",
    [string]$NetworkInterface = "",
    [ValidateSet("", "true", "false")]
    [string]$PromiscuousMode = "",
    [ValidateSet("", "true", "false")]
    [string]$FirewallSyncEnabled = "",
    [int]$FirewallSyncInterval = 0,
    [switch]$SkipNpcapInstall,
    [switch]$SkipVcRedistInstall
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-ElevatedAndExit {
    param([hashtable]$BoundParams)

    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        throw "Cannot relaunch elevated: script path is not available."
    }

    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$scriptPath`""
    )

    foreach ($entry in $BoundParams.GetEnumerator()) {
        $key = $entry.Key
        $value = $entry.Value

        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) {
                $argList += "-$key"
            }
            continue
        }

        if ($null -eq $value) {
            continue
        }

        $escapedValue = ([string]$value).Replace('"', '`"')
        $argList += "-$key"
        $argList += "`"$escapedValue`""
    }

    Write-Host "Requesting Administrator elevation..."
    try {
        $proc = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList ($argList -join " ") -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            throw "Elevated bootstrap failed with exit code $($proc.ExitCode)."
        }
        exit $proc.ExitCode
    }
    catch {
        $msg = $_.Exception.Message
        throw "Elevation failed: $msg"
    }
}

function Resolve-LocalPath {
    param(
        [string]$PathValue,
        [string]$BaseDir
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $null
    }

    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return $PathValue
    }

    return (Join-Path $BaseDir $PathValue)
}

function Read-EnvFile {
    param([string]$PathValue)

    $map = @{}
    Get-Content -Path $PathValue | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) {
            return
        }

        $parts = $line.Split("=", 2)
        if ($parts.Count -ne 2) {
            return
        }

        $name = $parts[0].Trim()
        $value = $parts[1].Trim()
        if (
            ($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))
        ) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $map[$name] = $value
    }

    return $map
}

function Resolve-Setting {
    param(
        [string]$Key,
        [string]$Override,
        [hashtable]$Config,
        [string]$Default = ""
    )

    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        return $Override
    }
    if ($Config.ContainsKey($Key) -and -not [string]::IsNullOrWhiteSpace([string]$Config[$Key])) {
        return [string]$Config[$Key]
    }
    return $Default
}

function Test-Truthy {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return @("1", "true", "yes", "on") -contains $Value.Trim().ToLowerInvariant()
}

function Is-UnwantedInterface {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $true
    }

    $n = $Name.ToLowerInvariant()
    $patterns = @(
        "loopback",
        "npcap loopback",
        "bluetooth",
        "vethernet",
        "virtualbox",
        "vmware",
        "hyper-v",
        "tap-",
        "wintun",
        "wireguard",
        "isatap",
        "teredo"
    )

    foreach ($p in $patterns) {
        if ($n.Contains($p)) {
            return $true
        }
    }
    return $false
}

function Convert-ToPcapDeviceName {
    param($Adapter)

    if (-not $Adapter) {
        return ""
    }

    $guid = [string]$Adapter.InterfaceGuid
    if ([string]::IsNullOrWhiteSpace($guid)) {
        return ""
    }

    $guid = $guid.Trim("{}").ToUpperInvariant()
    return "\Device\NPF_{$guid}"
}

function Normalize-NetworkInterface {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }

    $trimmed = $Value.Trim()
    if ($trimmed.ToLowerInvariant().StartsWith("\device\npf_")) {
        return $trimmed
    }

    $adapter = Get-NetAdapter -Name $trimmed -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($adapter) {
        $pcapName = Convert-ToPcapDeviceName -Adapter $adapter
        if (-not [string]::IsNullOrWhiteSpace($pcapName)) {
            Write-Host "Mapped NETWORK_INTERFACE '$trimmed' to pcap device '$pcapName'"
            return $pcapName
        }
    }

    return $trimmed
}

function Get-AutoNetworkInterface {
    $defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne "Unreachable" } |
        Sort-Object -Property RouteMetric |
        Select-Object -First 1

    if ($defaultRoute) {
        $adapterByRoute = Get-NetAdapter -ifIndex $defaultRoute.ifIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq "Up" -and -not (Is-UnwantedInterface -Name $_.Name) } |
            Select-Object -First 1

        if ($adapterByRoute) {
            $pcapName = Convert-ToPcapDeviceName -Adapter $adapterByRoute
            if (-not [string]::IsNullOrWhiteSpace($pcapName)) {
                return $pcapName
            }
            return $adapterByRoute.Name
        }
    }

    $fallback = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Up" -and -not (Is-UnwantedInterface -Name $_.Name) } |
        Select-Object -First 1

    if ($fallback) {
        $pcapName = Convert-ToPcapDeviceName -Adapter $fallback
        if (-not [string]::IsNullOrWhiteSpace($pcapName)) {
            return $pcapName
        }
        return $fallback.Name
    }

    return ""
}

function Test-NpcapInstalled {
    $svc = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
    if ($svc) {
        return $true
    }

    if (Test-Path "$env:SystemRoot\System32\drivers\npcap.sys") {
        return $true
    }

    $registryKeys = @(
        "HKLM:\SOFTWARE\Npcap",
        "HKLM:\SOFTWARE\WOW6432Node\Npcap"
    )
    foreach ($key in $registryKeys) {
        if (Test-Path $key) {
            return $true
        }
    }

    return $false
}

function Install-Npcap {
    param([string]$InstallerPath)

    if (-not (Test-Path $InstallerPath)) {
        throw "Npcap installer not found: $InstallerPath"
    }

    $ext = [System.IO.Path]::GetExtension($InstallerPath).ToLowerInvariant()
    if ($ext -eq ".msi") {
        $args = "/i `"$InstallerPath`" /qn /norestart"
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
    }
    else {
        $proc = Start-Process -FilePath $InstallerPath -ArgumentList "/S /winpcap_mode=yes" -Wait -PassThru
    }

    if ($proc.ExitCode -ne 0) {
        throw "Npcap installer failed with exit code $($proc.ExitCode)."
    }

    Start-Sleep -Seconds 2
    if (-not (Test-NpcapInstalled)) {
        throw "Npcap install appears to have completed, but Npcap was not detected."
    }
}

function Test-VcRuntimeInstalled {
    $required = @(
        "$env:SystemRoot\System32\vcruntime140.dll",
        "$env:SystemRoot\System32\msvcp140.dll"
    )
    foreach ($f in $required) {
        if (-not (Test-Path $f)) {
            return $false
        }
    }
    return $true
}

function Resolve-VcRedistInstaller {
    param(
        [string]$BaseDir,
        [string]$OverridePath
    )

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($OverridePath)) {
        $candidates += Resolve-LocalPath -PathValue $OverridePath -BaseDir $BaseDir
    }
    $candidates += (Join-Path $BaseDir "dependencies\vc_redist.x64.exe")
    $candidates += (Join-Path $BaseDir "vc_redist.x64.exe")

    return $candidates |
        Where-Object { $_ -and (Test-Path $_) } |
        Select-Object -First 1
}

function Install-VcRedist {
    param([string]$InstallerPath)

    if (-not (Test-Path $InstallerPath)) {
        throw "VC++ Redistributable installer not found: $InstallerPath"
    }

    $proc = Start-Process -FilePath $InstallerPath -ArgumentList "/install /quiet /norestart" -Wait -PassThru
    if (@(0, 1638, 3010) -notcontains $proc.ExitCode) {
        throw "VC++ Redistributable installer failed with exit code $($proc.ExitCode)."
    }

    Start-Sleep -Seconds 2
    if (-not (Test-VcRuntimeInstalled)) {
        throw "VC++ runtime still not detected after install."
    }
}

if (-not (Test-IsAdmin)) {
    Restart-ElevatedAndExit -BoundParams $PSBoundParameters
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$resolvedBinaryPath = Resolve-LocalPath -PathValue $BinaryPath -BaseDir $scriptDir
if (-not (Test-Path $resolvedBinaryPath)) {
    throw "Agent binary not found: $resolvedBinaryPath"
}

$resolvedConfigPath = Resolve-LocalPath -PathValue $ConfigPath -BaseDir $scriptDir
if (-not $resolvedConfigPath) {
    $agentEnv = Join-Path $scriptDir "agent.env"
    $agentEnvExample = Join-Path $scriptDir "agent.env.example"
    if (Test-Path $agentEnv) {
        $resolvedConfigPath = $agentEnv
    }
    elseif (Test-Path $agentEnvExample) {
        $resolvedConfigPath = $agentEnvExample
    }
    else {
        throw "No config found. Put agent.env next to this script, or pass -ConfigPath."
    }
}

if (-not (Test-Path $resolvedConfigPath)) {
    throw "Config file not found: $resolvedConfigPath"
}

$config = Read-EnvFile -PathValue $resolvedConfigPath

$finalApiUrl = Resolve-Setting -Key "API_URL" -Override $ApiUrl -Config $config
$finalRedisUrl = Resolve-Setting -Key "REDIS_URL" -Override $RedisUrl -Config $config
$finalRedisPassword = Resolve-Setting -Key "REDIS_PASSWORD" -Override $RedisPassword -Config $config -Default ""
$finalInternalServiceToken = Resolve-Setting -Key "INTERNAL_SERVICE_TOKEN" -Override $InternalServiceToken -Config $config -Default ""
$finalApiBearerToken = Resolve-Setting -Key "API_BEARER_TOKEN" -Override $ApiBearerToken -Config $config -Default ""
$finalNetworkInterface = Resolve-Setting -Key "NETWORK_INTERFACE" -Override $NetworkInterface -Config $config -Default ""
$finalPromiscuousMode = Resolve-Setting -Key "PROMISCUOUS_MODE" -Override $PromiscuousMode -Config $config -Default "true"
$finalFirewallSyncEnabled = Resolve-Setting -Key "FIREWALL_SYNC_ENABLED" -Override $FirewallSyncEnabled -Config $config -Default "true"
$firewallSyncIntervalOverride = ""
if ($FirewallSyncInterval -gt 0) {
    $firewallSyncIntervalOverride = [string]$FirewallSyncInterval
}
$finalFirewallSyncInterval = Resolve-Setting -Key "FIREWALL_SYNC_INTERVAL" -Override $firewallSyncIntervalOverride -Config $config -Default "30"
$finalNetworkInterface = Normalize-NetworkInterface -Value $finalNetworkInterface

[int]$parsedFirewallSyncInterval = 30
if (-not [int]::TryParse([string]$finalFirewallSyncInterval, [ref]$parsedFirewallSyncInterval)) {
    $parsedFirewallSyncInterval = 30
}
if ($parsedFirewallSyncInterval -lt 5) { $parsedFirewallSyncInterval = 5 }
if ($parsedFirewallSyncInterval -gt 3600) { $parsedFirewallSyncInterval = 3600 }

if ([string]::IsNullOrWhiteSpace($finalApiUrl)) {
    throw "API_URL is required (set in agent.env or pass -ApiUrl)."
}
if ([string]::IsNullOrWhiteSpace($finalRedisUrl)) {
    throw "REDIS_URL is required (set in agent.env or pass -RedisUrl)."
}
if ($finalApiUrl -match "YOUR-MAIN-SERVER|YOUR-SERVER") {
    throw "API_URL still has placeholder value. Update agent.env or pass -ApiUrl."
}
if ($finalRedisUrl -match "YOUR-MAIN-SERVER|YOUR-SERVER") {
    throw "REDIS_URL still has placeholder value. Update agent.env or pass -RedisUrl."
}

if (-not (Test-NpcapInstalled)) {
    if ($SkipNpcapInstall) {
        throw "Npcap is not installed and -SkipNpcapInstall was specified."
    }

    $installerCandidates = @()
    if (-not [string]::IsNullOrWhiteSpace($NpcapInstallerPath)) {
        $installerCandidates += Resolve-LocalPath -PathValue $NpcapInstallerPath -BaseDir $scriptDir
    }
    $installerCandidates += (Join-Path $scriptDir "dependencies\npcap-installer.exe")
    $installerCandidates += (Join-Path $scriptDir "npcap-installer.exe")

    $resolvedInstallerPath = $installerCandidates |
        Where-Object { $_ -and (Test-Path $_) } |
        Select-Object -First 1

    if (-not $resolvedInstallerPath) {
        throw "Npcap is missing. Place installer at dependencies\npcap-installer.exe, pass -NpcapInstallerPath, or install Npcap manually."
    }

    Write-Host "Npcap not detected. Installing silently from: $resolvedInstallerPath"
    Install-Npcap -InstallerPath $resolvedInstallerPath
}
else {
    Write-Host "Npcap already installed."
}

if (-not (Test-VcRuntimeInstalled)) {
    if ($SkipVcRedistInstall) {
        throw "Visual C++ runtime is missing and -SkipVcRedistInstall was specified."
    }

    $resolvedVcInstaller = Resolve-VcRedistInstaller -BaseDir $scriptDir -OverridePath $VcRedistInstallerPath
    if (-not $resolvedVcInstaller) {
        $depsDir = Join-Path $scriptDir "dependencies"
        New-Item -ItemType Directory -Path $depsDir -Force | Out-Null
        $resolvedVcInstaller = Join-Path $depsDir "vc_redist.x64.exe"
        $vcDownloadUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        Write-Host "VC++ runtime missing. Downloading installer from: $vcDownloadUrl"
        try {
            Invoke-WebRequest -Uri $vcDownloadUrl -OutFile $resolvedVcInstaller -UseBasicParsing
        }
        catch {
            throw "Failed to download VC++ runtime installer. Place vc_redist.x64.exe in dependencies\\ and re-run."
        }
    }

    Write-Host "Installing VC++ runtime silently from: $resolvedVcInstaller"
    Install-VcRedist -InstallerPath $resolvedVcInstaller
}
else {
    Write-Host "Visual C++ runtime already installed."
}

if ([string]::IsNullOrWhiteSpace($finalNetworkInterface)) {
    $finalNetworkInterface = Get-AutoNetworkInterface
    if (-not [string]::IsNullOrWhiteSpace($finalNetworkInterface)) {
        Write-Host "Auto-selected pcap interface: $finalNetworkInterface"
    }
    else {
        Write-Warning "No suitable NIC found automatically. Revenix core will use its own fallback selection."
    }
}

$installScript = Join-Path $scriptDir "install-agent.ps1"
if (-not (Test-Path $installScript)) {
    throw "Missing install script: $installScript"
}

& $installScript `
    -BinaryPath $resolvedBinaryPath `
    -ApiUrl $finalApiUrl `
    -RedisUrl $finalRedisUrl `
    -RedisPassword $finalRedisPassword `
    -InternalServiceToken $finalInternalServiceToken `
    -ApiBearerToken $finalApiBearerToken `
    -NetworkInterface $finalNetworkInterface `
    -PromiscuousMode $finalPromiscuousMode `
    -FirewallSyncEnabled $finalFirewallSyncEnabled `
    -FirewallSyncInterval $parsedFirewallSyncInterval `
    -InstallDir $InstallDir `
    -TaskName $TaskName `
    -FirewallTaskName $FirewallTaskName

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    throw "Install finished, but scheduled task '$TaskName' was not found."
}

$taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
$firewallTask = Get-ScheduledTask -TaskName $FirewallTaskName -ErrorAction SilentlyContinue
$firewallTaskInfo = Get-ScheduledTaskInfo -TaskName $FirewallTaskName -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Bootstrap complete."
Write-Host "Config file: $resolvedConfigPath"
Write-Host "API_URL: $finalApiUrl"
Write-Host "REDIS_URL: $finalRedisUrl"
Write-Host "FIREWALL_SYNC_ENABLED: $finalFirewallSyncEnabled"
Write-Host "FIREWALL_SYNC_INTERVAL: $parsedFirewallSyncInterval"
if (-not [string]::IsNullOrWhiteSpace($finalNetworkInterface)) {
    Write-Host "NETWORK_INTERFACE: $finalNetworkInterface"
}
Write-Host "Core task state: $($task.State)"
if ($taskInfo) {
    Write-Host "Core task last run: $($taskInfo.LastRunTime)"
}
if (Test-Truthy -Value $finalFirewallSyncEnabled) {
    if (-not $firewallTask) {
        throw "Install finished, but firewall task '$FirewallTaskName' was not found."
    }
    Write-Host "Firewall task state: $($firewallTask.State)"
    if ($firewallTaskInfo) {
        Write-Host "Firewall task last run: $($firewallTaskInfo.LastRunTime)"
    }
}
