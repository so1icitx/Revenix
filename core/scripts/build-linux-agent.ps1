param(
    [ValidateSet("amd64")]
    [string]$Arch = "amd64",
    [string]$ImageName = "revenix-core-agent:linux-amd64",
    [switch]$SkipImageBuild
)

$ErrorActionPreference = "Stop"

$coreRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoRoot = (Resolve-Path (Join-Path $coreRoot "..")).Path
$linuxAgentRoot = Join-Path $repoRoot "agents\linux"
$outDir = Join-Path $coreRoot "dist\linux-agent"

$docker = Get-Command "docker" -ErrorAction SilentlyContinue
if (-not $docker) {
    throw "docker was not found. Install Docker Desktop/Engine and rerun."
}

if (-not (Test-Path $linuxAgentRoot)) {
    throw "Linux agent templates missing: $linuxAgentRoot"
}

New-Item -ItemType Directory -Path $outDir -Force | Out-Null

if (-not $SkipImageBuild) {
    Write-Host "Building Revenix Core Linux image (linux/$Arch)..."
    & $docker.Source build --platform "linux/$Arch" -t $ImageName $coreRoot
    if ($LASTEXITCODE -ne 0) {
        throw "docker build failed with exit code $LASTEXITCODE."
    }
}
else {
    Write-Host "Skipping docker build. Existing local image must exist: $ImageName"
}

$imageTar = Join-Path $outDir "revenix-core-image.tar"
Write-Host "Exporting image tar: $imageTar"
& $docker.Source save -o $imageTar $ImageName
if ($LASTEXITCODE -ne 0) {
    throw "docker save failed with exit code $LASTEXITCODE."
}

Copy-Item (Join-Path $linuxAgentRoot "install.sh") (Join-Path $outDir "install.sh") -Force
Copy-Item (Join-Path $linuxAgentRoot "start-agent.sh") (Join-Path $outDir "start-agent.sh") -Force
Copy-Item (Join-Path $linuxAgentRoot "uninstall.sh") (Join-Path $outDir "uninstall.sh") -Force
Copy-Item (Join-Path $linuxAgentRoot "agent.env.example") (Join-Path $outDir "agent.env.example") -Force
Copy-Item (Join-Path $linuxAgentRoot "README.md") (Join-Path $outDir "README.md") -Force

$archive = Join-Path $coreRoot "dist\revenix-linux-agent-$Arch.tar.gz"
if (Test-Path $archive) {
    Remove-Item $archive -Force
}

if (Get-Command "tar" -ErrorAction SilentlyContinue) {
    & tar -C $outDir -czf $archive .
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Compressed bundle created: $archive"
    }
    else {
        Write-Warning "tar failed (exit $LASTEXITCODE). Folder bundle is still available at $outDir"
    }
}
else {
    Write-Warning "tar command not found. Folder bundle is available at $outDir"
}

Write-Host "Linux agent bundle created at: $outDir"
Write-Host "Image tag inside bundle: $ImageName"
