param(
    [ValidateSet("x64")]
    [string]$Arch = "x64",
    [switch]$SkipNpcapSdkDownload
)

$ErrorActionPreference = "Stop"

$target = "x86_64-pc-windows-msvc"
if ($Arch -ne "x64") {
    throw "Only x64 is currently supported."
}
$coreRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoRoot = (Resolve-Path (Join-Path $coreRoot "..")).Path

function Resolve-ToolPath {
    param(
        [string]$ToolName
    )

    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    $candidate = Join-Path $cargoBin $ToolName
    if (Test-Path $candidate) {
        return $candidate
    }

    if (Test-Path "$candidate.exe") {
        return "$candidate.exe"
    }

    throw "$ToolName was not found. Install Rustup and ensure .cargo\bin is available."
}

function Import-BatchEnvironment {
    param(
        [string]$BatchFile,
        [string]$Arguments = ""
    )

    $cmdLine = "`"$BatchFile`" $Arguments >nul && set"
    cmd.exe /s /c $cmdLine | ForEach-Object {
        if ($_ -match "^(.*?)=(.*)$") {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
}

function Resolve-VsDevCmdPath {
    $candidates = @(
        "$env:ProgramFiles\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
    )

    foreach ($path in $candidates) {
        if (Test-Path $path) {
            return $path
        }
    }

    return $null
}

function Resolve-WpcapLibDir {
    $candidates = @(
        "C:\Program Files\Npcap\Lib\x64",
        "C:\Program Files (x86)\Npcap\Lib\x64",
        "C:\WpdPack\Lib\x64"
    )

    foreach ($dir in $candidates) {
        if (Test-Path (Join-Path $dir "wpcap.lib")) {
            return $dir
        }
    }

    return $null
}

function Get-LatestNpcapSdkUrl {
    $archiveUrl = "https://npcap.com/dist/"
    $response = Invoke-WebRequest -Uri $archiveUrl -UseBasicParsing
    $matches = [regex]::Matches($response.Content, "npcap-sdk-([0-9\.]+)\.zip")
    if ($matches.Count -eq 0) {
        return $null
    }

    $versions = @()
    foreach ($m in $matches) {
        $v = $m.Groups[1].Value
        try {
            $versions += [PSCustomObject]@{
                Version = [version]$v
                Value = $v
            }
        }
        catch {
            continue
        }
    }

    if ($versions.Count -eq 0) {
        return $null
    }

    $latest = $versions | Sort-Object -Property Version -Descending | Select-Object -First 1
    return "https://npcap.com/dist/npcap-sdk-$($latest.Value).zip"
}

function Install-NpcapSdkLib {
    param([string]$CacheDir)

    New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null

    $sdkUrl = Get-LatestNpcapSdkUrl
    if (-not $sdkUrl) {
        throw "Could not discover Npcap SDK download URL from https://npcap.com/dist/."
    }

    $zipPath = Join-Path $CacheDir "npcap-sdk.zip"
    $extractPath = Join-Path $CacheDir "npcap-sdk"
    if (Test-Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force
    }

    Write-Host "Downloading Npcap SDK: $sdkUrl"
    Invoke-WebRequest -Uri $sdkUrl -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

    $lib = Get-ChildItem -Path $extractPath -Recurse -Filter "wpcap.lib" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\Lib\\x64\\wpcap\.lib$" } |
        Select-Object -First 1

    if (-not $lib) {
        throw "Downloaded Npcap SDK did not contain Lib\\x64\\wpcap.lib."
    }

    return $lib.Directory.FullName
}

$rustupPath = Resolve-ToolPath -ToolName "rustup"
$cargoPath = Resolve-ToolPath -ToolName "cargo"

Write-Host "Installing Rust target: $target"
& $rustupPath target add $target
if ($LASTEXITCODE -ne 0) {
    throw "rustup target add failed with exit code $LASTEXITCODE."
}

$linker = Get-Command "link.exe" -ErrorAction SilentlyContinue
if (-not $linker) {
    $vsDevCmd = Resolve-VsDevCmdPath
    if ($vsDevCmd) {
        Write-Host "MSVC linker not in PATH, loading VS toolchain environment..."
        Import-BatchEnvironment -BatchFile $vsDevCmd -Arguments "-arch=x64 -host_arch=x64"
        $linker = Get-Command "link.exe" -ErrorAction SilentlyContinue
    }
}

if (-not $linker) {
    throw "MSVC linker not found (link.exe). Install/modify Visual Studio Build Tools with workload 'Desktop development with C++' (Microsoft.VisualStudio.Workload.VCTools), then reopen PowerShell."
}

$wpcapLibDir = Resolve-WpcapLibDir
if (-not $wpcapLibDir) {
    if ($SkipNpcapSdkDownload) {
        throw "wpcap.lib not found and -SkipNpcapSdkDownload is set. Install Npcap SDK so wpcap.lib exists under Npcap\\Lib\\x64, then rerun."
    }

    $cacheDir = Join-Path $coreRoot ".build-cache"
    $wpcapLibDir = Install-NpcapSdkLib -CacheDir $cacheDir
    Write-Host "Using downloaded wpcap.lib from: $wpcapLibDir"
}
$env:LIB = "$wpcapLibDir;$env:LIB"

Write-Host "Building Revenix Core for Windows..."
& $cargoPath build --manifest-path (Join-Path $coreRoot "Cargo.toml") --release --target $target
if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed with exit code $LASTEXITCODE."
}

$outDir = Join-Path $coreRoot "dist\windows-agent"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$binary = Join-Path $coreRoot "target\$target\release\revenix-core.exe"
if (-not (Test-Path $binary)) {
    throw "Build finished without expected binary: $binary"
}
Copy-Item $binary (Join-Path $outDir "revenix-core.exe") -Force
Copy-Item (Join-Path $repoRoot "agents\windows\bootstrap-install.ps1") (Join-Path $outDir "bootstrap-install.ps1") -Force
Copy-Item (Join-Path $repoRoot "agents\windows\install.cmd") (Join-Path $outDir "install.cmd") -Force
Copy-Item (Join-Path $repoRoot "agents\windows\install-agent.ps1") (Join-Path $outDir "install-agent.ps1") -Force
Copy-Item (Join-Path $repoRoot "agents\windows\uninstall.cmd") (Join-Path $outDir "uninstall.cmd") -Force
Copy-Item (Join-Path $repoRoot "agents\windows\uninstall-agent.ps1") (Join-Path $outDir "uninstall-agent.ps1") -Force
Copy-Item (Join-Path $repoRoot "agents\windows\start-agent.ps1") (Join-Path $outDir "start-agent.ps1") -Force
Copy-Item (Join-Path $repoRoot "agents\windows\agent.env.example") (Join-Path $outDir "agent.env.example") -Force
Copy-Item (Join-Path $repoRoot "agents\windows\README.md") (Join-Path $outDir "README.md") -Force

$depsSrc = Join-Path $repoRoot "agents\windows\dependencies"
if (Test-Path $depsSrc) {
    $depsDst = Join-Path $outDir "dependencies"
    New-Item -ItemType Directory -Path $depsDst -Force | Out-Null
    Get-ChildItem -Path $depsSrc -Force | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $depsDst -Recurse -Force
    }
}

Write-Host "Windows agent bundle created at: $outDir"
