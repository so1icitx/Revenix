# Windows Agent

> Production recommendation: use the bootstrap flow (`install.cmd`) only. Do not require users to run manual prerequisite steps.

## Build Bundle

From the repository `core` folder:

```powershell
.\scripts\build-windows-agent.ps1
```

Output:

- `core\dist\windows-agent`

## Endpoint Install Steps

1. Copy bundle folder to target Windows machine.
2. Create `agent.env` from `agent.env.example`.
3. Set:
- `API_URL=http://<main-server>:8000`
- `REDIS_URL=redis://<main-server>:6379`
4. In Administrator PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install.cmd
```

## Validate

```powershell
Get-ScheduledTask -TaskName RevenixCoreAgent
Get-ScheduledTaskInfo -TaskName RevenixCoreAgent
Get-Content "C:\ProgramData\RevenixAgent\logs\agent-supervisor.log" -Tail 50
```

## Behavior Notes

- If `NETWORK_INTERFACE` is empty, bootstrap auto-selects a usable NIC.
- Task state can be `Ready` between runs; use task info and logs to confirm health.
- For full network-wide visibility, place capture where aggregate traffic is visible (edge/SPAN), not only on a single endpoint.
