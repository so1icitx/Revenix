# Revenix Windows Agent

> Recommended install path: run `install.cmd` (bootstrap) as Administrator. It handles prerequisites and task setup automatically.

## What Bootstrap Handles

- Reads config from `agent.env`
- Verifies Administrator context (and requests elevation)
- Installs Npcap silently if missing (from bundled installer)
- Installs VC++ runtime if missing (bundled or auto-download)
- Auto-selects a capture interface when `NETWORK_INTERFACE` is empty
- Installs and starts scheduled tasks `RevenixCoreAgent` and `RevenixFirewallAgent` (unless firewall sync is disabled)

## Package Contents

Expected files in one folder:

- `revenix-core.exe`
- `install.cmd`
- `bootstrap-install.ps1`
- `install-agent.ps1`
- `control-agent.ps1`
- `start.cmd`
- `stop.cmd`
- `restart.cmd`
- `status.cmd`
- `start-agent.ps1`
- `firewall-sync.ps1`
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
- `INTERNAL_SERVICE_TOKEN=<same token as API>` (required when API internal auth is enabled)

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
Get-ScheduledTask -TaskName RevenixFirewallAgent
Get-ScheduledTaskInfo -TaskName RevenixCoreAgent
Get-ScheduledTaskInfo -TaskName RevenixFirewallAgent
Get-Content "C:\ProgramData\RevenixAgent\logs\agent-supervisor.log" -Tail 50
Get-Content "C:\ProgramData\RevenixAgent\logs\firewall-sync.log" -Tail 50
```

Expected:

- Task exists as `RevenixCoreAgent`
- Firewall task exists as `RevenixFirewallAgent` (unless `FIREWALL_SYNC_ENABLED=false`)
- Last task result is `0`
- Supervisor log shows `Starting revenix-core.exe`

> `Task Manager` is not the source of truth for startup services. Use scheduled task status and logs.

## One-Click Task Control

Use these in **Administrator PowerShell**:

```powershell
.\status.cmd
.\stop.cmd
.\start.cmd
.\restart.cmd
```

These control scheduled tasks `RevenixCoreAgent` and `RevenixFirewallAgent`.

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
