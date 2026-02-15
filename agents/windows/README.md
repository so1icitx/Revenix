# Revenix Windows Agent

> Recommended install path: run `install.cmd` (bootstrap) as Administrator. It handles prerequisites and task setup automatically.

## What Bootstrap Handles

- Reads config from `agent.env`
- Verifies Administrator context (and requests elevation)
- Installs Npcap silently if missing (from bundled installer)
- Installs VC++ runtime if missing (bundled or auto-download)
- Auto-selects a capture interface when `NETWORK_INTERFACE` is empty
- Installs and starts scheduled task `RevenixCoreAgent`

## Package Contents

Expected files in one folder:

- `revenix-core.exe`
- `install.cmd`
- `bootstrap-install.ps1`
- `install-agent.ps1`
- `start-agent.ps1`
- `uninstall.cmd`
- `uninstall-agent.ps1`
- `agent.env` (create from `agent.env.example`)
- Optional: `dependencies\npcap-installer.exe`
- Optional: `dependencies\vc_redist.x64.exe`

## Configure `agent.env`

1. Copy `agent.env.example` to `agent.env`.
2. Set at minimum:
- `API_URL=http://YOUR-MAIN-SERVER:8000`
- `REDIS_URL=redis://YOUR-MAIN-SERVER:6379`

> Leave `NETWORK_INTERFACE=` empty unless you must pin one NIC.

## Install (Recommended)

Open an **Administrator PowerShell** in this folder, then run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install.cmd
```

Direct equivalent:

```powershell
.\bootstrap-install.ps1
```

## Verify Agent Health

```powershell
Get-ScheduledTask -TaskName RevenixCoreAgent
Get-ScheduledTaskInfo -TaskName RevenixCoreAgent
Get-Content "C:\ProgramData\RevenixAgent\logs\agent-supervisor.log" -Tail 50
```

Expected:

- Task exists as `RevenixCoreAgent`
- Last task result is `0`
- Supervisor log shows `Starting revenix-core.exe`

> `Task Manager` is not the source of truth for startup services. Use scheduled task status and logs.

## Update / Reinstall

Run install again with the new bundle:

```powershell
.\install.cmd
```

The installer replaces files and re-registers the task.

## Uninstall

```powershell
.\uninstall.cmd
```

## Common Issues

- `Run this script as Administrator.`
  - Re-open PowerShell with `Run as administrator`.
- `Elevation was canceled or failed.`
  - Accept UAC prompt, then rerun.
- `Npcap is missing...`
  - Put installer at `dependencies\npcap-installer.exe` for fully offline install.

More diagnostics: `docs/troubleshooting.md`.
