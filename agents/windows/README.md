# Revenix Windows Agent

This folder contains the Windows deployment wrapper for `revenix-core.exe`.

## What this does

- Reads endpoint config from `agent.env`
- Checks whether Npcap is installed
- Silently installs Npcap from bundled installer when needed
- Auto-selects the active NIC if `NETWORK_INTERFACE` is blank
- Installs/starts the startup scheduled task (`RevenixCoreAgent`)

## Prerequisites

- Windows Server 2019+ or Windows 10/11
- Administrator PowerShell
- `revenix-core.exe` built for Windows (`x86_64-pc-windows-msvc`)

## Package layout

Expected files in one folder:

- `revenix-core.exe`
- `install.cmd`
- `bootstrap-install.ps1`
- `install-agent.ps1`
- `uninstall.cmd`
- `start-agent.ps1`
- `uninstall-agent.ps1`
- `agent.env` (copy from `agent.env.example`)
- Optional offline installer: `dependencies\npcap-installer.exe`
- Optional offline installer: `dependencies\vc_redist.x64.exe`

## One-command install (recommended)

1. Copy `agent.env.example` to `agent.env` and set:
   - `API_URL=http://YOUR-MAIN-SERVER:8000`
   - `REDIS_URL=redis://YOUR-MAIN-SERVER:6379`
2. (Optional but recommended) Place Npcap installer at:
   - `dependencies\npcap-installer.exe`
3. (Optional) Place VC++ runtime installer at:
   - `dependencies\vc_redist.x64.exe`
   - If missing, bootstrap tries to download it from Microsoft.
4. Run as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install.cmd
```

Optional overrides:

```powershell
.\install.cmd `
  -ApiUrl "http://YOUR-MAIN-SERVER:8000" `
  -RedisUrl "redis://YOUR-MAIN-SERVER:6379" `
  -NetworkInterface "Ethernet" `
  -NpcapInstallerPath ".\dependencies\npcap-installer.exe"
```

## Manual install (advanced)

If you already have Npcap installed:

```powershell
.\install-agent.ps1 `
  -BinaryPath ".\revenix-core.exe" `
  -ApiUrl "http://YOUR-MAIN-SERVER:8000" `
  -RedisUrl "redis://YOUR-MAIN-SERVER:6379"
```

## Files created

- `C:\ProgramData\RevenixAgent\revenix-core.exe`
- `C:\ProgramData\RevenixAgent\start-agent.ps1`
- `C:\ProgramData\RevenixAgent\agent.env`
- Scheduled task: `RevenixCoreAgent`

## Uninstall

```powershell
.\uninstall.cmd
```
