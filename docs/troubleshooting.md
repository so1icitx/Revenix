# Troubleshooting

> Start with evidence, not guesses: scheduled task state, core/firewall logs, API reachability, and Redis reachability.

## 1) No Flows Appearing

Checks:

```powershell
Get-ScheduledTask -TaskName RevenixCoreAgent
Get-ScheduledTask -TaskName RevenixFirewallAgent
Get-ScheduledTaskInfo -TaskName RevenixCoreAgent
Get-ScheduledTaskInfo -TaskName RevenixFirewallAgent
Get-Content "C:\ProgramData\RevenixAgent\logs\agent-supervisor.log" -Tail 100
Get-Content "C:\ProgramData\RevenixAgent\logs\firewall-sync.log" -Tail 100
```

What to confirm:

- `LastTaskResult` is `0`
- `agent-supervisor.log` shows repeated start attempts without fatal errors
- `firewall-sync.log` shows periodic sync attempts (if firewall sync is enabled)
- `agent.env` points to correct `API_URL` and `REDIS_URL`

## 2) Task Shows `Ready` Instead of `Running`

`Ready` is not automatically a failure. The startup trigger may have completed and waiting state can be normal.

Use:

```powershell
Get-ScheduledTaskInfo -TaskName RevenixCoreAgent
```

If `LastTaskResult` is non-zero, inspect logs in:

- `C:\ProgramData\RevenixAgent\logs\core-*.stderr.log`
- `C:\ProgramData\RevenixAgent\logs\agent-supervisor.log`

## 3) Only Local/Private IPs in Some Views

> Endpoint capture shows that endpoint's traffic perspective. It does not replace network-edge monitoring.

If you need broader public/external peer visibility across many hosts:

- Deploy sensor capture on Linux at gateway/edge
- Or capture from a SPAN/mirror port

## 4) High False Positives

Tune operationally:

- Raise alert threshold
- Require higher model agreement before blocking
- Run longer benign training window per environment

Then re-check alert quality after enough new traffic.

## 5) Bootstrap Fails Due to Privileges

Errors like `Run this script as Administrator` or `Elevation was canceled` mean install did not run elevated.

Fix:

- Open a fresh Administrator PowerShell
- Re-run `install.cmd`

## 6) Npcap Missing

For fully offline installs, include:

- `dependencies\npcap-installer.exe`

Bootstrap will install it silently when missing.
