param(
    [string]$InstallDir = "C:\ProgramData\RevenixAgent",
    [switch]$RunOnce
)

$ErrorActionPreference = "Stop"

$envFile = Join-Path $InstallDir "agent.env"
$logDir = Join-Path $InstallDir "logs"
$logFile = Join-Path $logDir "firewall-sync.log"
$ruleGroup = "RevenixAgentFirewallSync"
$rulePrefix = "Revenix Sync Block"
$script:CurrentBlocked = New-Object 'System.Collections.Generic.HashSet[string]'

New-Item -ItemType Directory -Path $logDir -Force | Out-Null

function Write-Log {
    param([string]$Message)

    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

function Parse-Bool {
    param(
        [string]$Value,
        [bool]$Default = $true
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    $normalized = $Value.Trim().ToLowerInvariant()
    return @("1", "true", "yes", "on") -contains $normalized
}

function Parse-PositiveInt {
    param(
        [string]$Value,
        [int]$Default = 30,
        [int]$Minimum = 5,
        [int]$Maximum = 3600
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    $parsed = 0
    if (-not [int]::TryParse($Value.Trim(), [ref]$parsed)) {
        return $Default
    }

    if ($parsed -lt $Minimum) { return $Minimum }
    if ($parsed -gt $Maximum) { return $Maximum }
    return $parsed
}

function Read-EnvMap {
    param([string]$PathValue)

    $map = @{}
    if (-not (Test-Path $PathValue)) {
        return $map
    }

    Get-Content $PathValue | ForEach-Object {
        $rawLine = [string]$_
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) { return }

        $parts = $line.Split("=", 2)
        if ($parts.Count -eq 2) {
            $name = $parts[0].Trim()
            $value = $parts[1].Trim()
            $map[$name] = $value
        }
    }

    return $map
}

function Get-PropertyValue {
    param(
        [object]$Object,
        [string]$Name
    )

    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) {
        return $null
    }

    if ($Object -is [hashtable]) {
        if ($Object.ContainsKey($Name)) {
            return $Object[$Name]
        }
        return $null
    }

    $prop = $Object.PSObject.Properties[$Name]
    if ($null -ne $prop) {
        return $prop.Value
    }
    return $null
}

function Get-ApiHeaders {
    param([hashtable]$Config)

    $headers = @{
        "Accept" = "application/json"
    }

    if ($null -eq $Config) {
        return $headers
    }

    if ($Config.ContainsKey("INTERNAL_SERVICE_TOKEN") -and -not [string]::IsNullOrWhiteSpace([string]$Config["INTERNAL_SERVICE_TOKEN"])) {
        $headers["X-Internal-Token"] = [string]$Config["INTERNAL_SERVICE_TOKEN"]
    }
    elseif ($Config.ContainsKey("API_BEARER_TOKEN") -and -not [string]::IsNullOrWhiteSpace([string]$Config["API_BEARER_TOKEN"])) {
        $headers["Authorization"] = "Bearer $([string]$Config["API_BEARER_TOKEN"])"
    }

    return $headers
}

function Test-ValidIp {
    param([string]$Ip)

    $parsed = $null
    return [System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)
}

function Get-BlockedIpSet {
    param(
        [string]$ApiUrl,
        [hashtable]$Headers
    )

    try {
        $result = Invoke-RestMethod -Method Get -Uri "$ApiUrl/self-healing/blocked-ips" -Headers $Headers -TimeoutSec 15
    }
    catch {
        Write-Log "Failed to fetch blocked IPs: $($_.Exception.Message)"
        return $null
    }

    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $items = @()
    if ($null -eq $result) {
        return ,$set
    }

    if ($result -is [System.Array]) {
        $items = @($result)
    }
    else {
        # Defensive: tolerate multiple payload shapes.
        $blockedIps = Get-PropertyValue -Object $result -Name "blocked_ips"
        if ($null -ne $blockedIps) {
            if ($blockedIps -is [System.Array]) {
                $items = @($blockedIps)
            }
            else {
                $items = @($blockedIps)
            }
        }
        else {
            $valueProp = Get-PropertyValue -Object $result -Name "value"
            if ($null -ne $valueProp) {
                if ($valueProp -is [System.Array]) {
                    $items = @($valueProp)
                }
                else {
                    $items = @($valueProp)
                }
            }
            else {
                $items = @($result)
            }
        }
    }

    foreach ($item in $items) {
        if ($null -eq $item) { continue }

        $candidate = ""
        if ($item -is [string]) {
            $candidate = [string]$item
        }
        elseif ($item -is [hashtable]) {
            if ($item.ContainsKey("ip")) {
                $candidate = [string]$item["ip"]
            }
        }
        else {
            $ipProp = Get-PropertyValue -Object $item -Name "ip"
            if ($null -ne $ipProp) {
                $candidate = [string]$ipProp
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-ValidIp -Ip $candidate)) {
            $null = $set.Add($candidate)
        }
    }

    return ,$set
}

function Get-RuleName {
    param(
        [string]$Ip,
        [ValidateSet("IN", "OUT")]
        [string]$Direction
    )

    return "$rulePrefix $Ip $Direction"
}

function Ensure-BlockRules {
    param([string]$Ip)

    $inRule = Get-RuleName -Ip $Ip -Direction IN
    $outRule = Get-RuleName -Ip $Ip -Direction OUT

    if (-not (Get-NetFirewallRule -DisplayName $inRule -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule `
            -DisplayName $inRule `
            -Direction Inbound `
            -RemoteAddress $Ip `
            -Action Block `
            -Profile Any `
            -Enabled True `
            -Group $ruleGroup | Out-Null
    }

    if (-not (Get-NetFirewallRule -DisplayName $outRule -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule `
            -DisplayName $outRule `
            -Direction Outbound `
            -RemoteAddress $Ip `
            -Action Block `
            -Profile Any `
            -Enabled True `
            -Group $ruleGroup | Out-Null
    }

    $inExists = Get-NetFirewallRule -DisplayName $inRule -ErrorAction SilentlyContinue
    $outExists = Get-NetFirewallRule -DisplayName $outRule -ErrorAction SilentlyContinue
    return ($null -ne $inExists -and $null -ne $outExists)
}

function Remove-BlockRules {
    param([string]$Ip)

    $inRule = Get-RuleName -Ip $Ip -Direction IN
    $outRule = Get-RuleName -Ip $Ip -Direction OUT

    Remove-NetFirewallRule -DisplayName $inRule -ErrorAction SilentlyContinue | Out-Null
    Remove-NetFirewallRule -DisplayName $outRule -ErrorAction SilentlyContinue | Out-Null

    $inExists = Get-NetFirewallRule -DisplayName $inRule -ErrorAction SilentlyContinue
    $outExists = Get-NetFirewallRule -DisplayName $outRule -ErrorAction SilentlyContinue
    return ($null -eq $inExists -and $null -eq $outExists)
}

function Get-CurrentBlockedFromFirewall {
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $existing = Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue
    if (-not $existing) {
        return ,$set
    }

    foreach ($rule in @($existing)) {
        if ($null -eq $rule) { continue }

        $displayName = [string](Get-PropertyValue -Object $rule -Name "DisplayName")
        if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

        if ($displayName -match "^Revenix Sync Block (.+) (IN|OUT)$") {
            $ip = $matches[1]
            if (-not [string]::IsNullOrWhiteSpace($ip)) {
                $null = $set.Add($ip)
            }
        }
    }

    return ,$set
}

function Initialize-CurrentStateFromFirewall {
    $script:CurrentBlocked = Get-CurrentBlockedFromFirewall
}

function Sync-FirewallState {
    param([object]$DesiredBlocked)

    $desiredSet = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($DesiredBlocked -is [System.Collections.Generic.HashSet[string]]) {
        $desiredSet = $DesiredBlocked
    }
    elseif ($null -ne $DesiredBlocked) {
        foreach ($entry in @($DesiredBlocked)) {
            if ($null -eq $entry) { continue }
            $candidate = [string]$entry
            if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-ValidIp -Ip $candidate)) {
                $null = $desiredSet.Add($candidate)
            }
        }
    }

    # Recompute from actual firewall each cycle to avoid state drift.
    $currentBlocked = Get-CurrentBlockedFromFirewall
    if ($null -eq $currentBlocked) {
        $currentBlocked = New-Object 'System.Collections.Generic.HashSet[string]'
    }

    $toBlock = New-Object System.Collections.Generic.List[string]
    $toUnblock = New-Object System.Collections.Generic.List[string]

    foreach ($ip in $desiredSet) {
        if (-not $currentBlocked.Contains($ip)) {
            [void]$toBlock.Add($ip)
        }
    }

    foreach ($ip in $currentBlocked) {
        if (-not $desiredSet.Contains($ip)) {
            [void]$toUnblock.Add($ip)
        }
    }

    if ($RunOnce) {
        Write-Log ("Sync snapshot. Desired={0} Current={1} ToBlock={2} ToUnblock={3}" -f $desiredSet.Count, $currentBlocked.Count, $toBlock.Count, $toUnblock.Count)
    }

    $addedCount = 0
    $removedCount = 0

    foreach ($ip in $toBlock) {
        if (Ensure-BlockRules -Ip $ip) {
            $addedCount += 1
        }
        else {
            Write-Log "Failed to add one or more firewall rules for $ip"
        }
    }

    foreach ($ip in $toUnblock) {
        if (Remove-BlockRules -Ip $ip) {
            $removedCount += 1
        }
        else {
            Write-Log "Failed to remove one or more firewall rules for $ip"
        }
    }

    # Refresh from actual firewall after applying changes.
    $script:CurrentBlocked = Get-CurrentBlockedFromFirewall

    if ($toBlock.Count -gt 0 -or $toUnblock.Count -gt 0 -or $addedCount -ne 0 -or $removedCount -ne 0) {
        Write-Log ("Firewall sync updated. Added={0}, Removed={1}, Total={2}" -f $addedCount, $removedCount, $script:CurrentBlocked.Count)
    }
}

if (-not (Test-Path $envFile)) {
    throw "Missing agent env file: $envFile"
}

$config = Read-EnvMap -PathValue $envFile
$apiUrl = [string]$config["API_URL"]
if ([string]::IsNullOrWhiteSpace($apiUrl)) {
    throw "API_URL is missing in $envFile"
}
$apiUrl = $apiUrl.TrimEnd("/")

$syncEnabled = Parse-Bool -Value ([string]$config["FIREWALL_SYNC_ENABLED"]) -Default $true
if (-not $syncEnabled) {
    Write-Log "FIREWALL_SYNC_ENABLED=false, firewall sync task exiting."
    exit 0
}

$syncInterval = Parse-PositiveInt -Value ([string]$config["FIREWALL_SYNC_INTERVAL"]) -Default 30 -Minimum 5 -Maximum 3600
$headers = Get-ApiHeaders -Config $config

Initialize-CurrentStateFromFirewall

Write-Log "Starting firewall sync loop. API=$apiUrl Interval=${syncInterval}s CurrentRules=$($script:CurrentBlocked.Count) RunOnce=$RunOnce"

while ($true) {
    try {
        $desiredBlocked = Get-BlockedIpSet -ApiUrl $apiUrl -Headers $headers
        if ($null -ne $desiredBlocked) {
            Sync-FirewallState -DesiredBlocked $desiredBlocked
        }
    }
    catch {
        $position = $_.InvocationInfo.PositionMessage
        $stack = $_.ScriptStackTrace
        if ([string]::IsNullOrWhiteSpace($stack)) {
            $stack = ($_ | Out-String).Trim()
        }
        Write-Log "Firewall sync iteration failed: $($_.Exception.Message) | Position: $position | Stack: $stack"
    }

    if ($RunOnce) {
        Write-Log "RunOnce=true, exiting after single synchronization pass."
        break
    }

    Start-Sleep -Seconds $syncInterval
}
