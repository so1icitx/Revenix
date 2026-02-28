# Revenix Management Guide


## 0) One-Time Rules (Prevents Most Issues)

- Run only one agent instance per machine.
- On Windows, run install/control commands in **Administrator PowerShell**.
- Client `agent.env` must point to the **main host IP**, not `localhost`.

## 1) Main Host Start/Stop

### Windows Main Host

```powershell
cd C:\path\to\revenix-public
python3 start-revenix.py
```

This starts the Docker control plane (`postgres`, `redis`, `api`, `brain`, `dashboard`) and starts Windows scheduled tasks for the native agent.

Stop control plane:

```powershell
docker-compose down
```

### Linux Main Host

```bash
cd /path/to/revenix-public
docker-compose up -d --build
```

Stop:

```bash
docker-compose down
```

## 2) Build Client Bundles

### Windows Bundle

```powershell
cd core
.\scripts\build-windows-agent.ps1
```
> VS build tools needed

Output: `core\dist\windows-agent\`

### Linux Bundle

```powershell
cd core
.\scripts\build-linux-agent.ps1
```

Output: `core\dist\linux-agent\` (plus `.tar.gz`)

## 3) Windows Client Agent (Install/Start/Stop/Reinstall)

1. Copy `core\dist\windows-agent` to the client machine.
2. Create `agent.env` from `agent.env.example`:

```env
API_URL=http://<MAIN_HOST_IP>:8000
REDIS_URL=redis://:<REDIS_PASSWORD>@<MAIN_HOST_IP>:6379
REDIS_PASSWORD=<REDIS_PASSWORD>
INTERNAL_SERVICE_TOKEN=<INTERNAL_SERVICE_TOKEN>
FIREWALL_SYNC_ENABLED=true
```

3. Install:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install.cmd
```

4. Control:

```powershell
.\status.cmd
.\stop.cmd
.\start.cmd
.\restart.cmd
```

5. Full clean reinstall (if old broken instance exists):

```powershell
.\stop.cmd
.\uninstall.cmd
Get-Process revenix-core -ErrorAction SilentlyContinue | Stop-Process -Force
.\install.cmd
```

## 4) Linux Client Agent (Install/Start/Stop/Reinstall)

1. Copy `core/dist/linux-agent` to the client machine.
2. Create `agent.env` from `agent.env.example` with the same values as above.
3. Install:

```bash
sudo chmod +x install.sh start-agent.sh uninstall.sh
sudo ./install.sh
```

4. Stop:

```bash
sudo docker rm -f revenix-firewall-agent revenix-core-agent
```

5. Start again:

```bash
sudo /opt/revenix-agent/start-agent.sh
```

6. Reinstall clean:

```bash
sudo ./uninstall.sh --purge-files --remove-image
sudo ./install.sh
```

## 5) "No Flows" Quick Fix Checklist

1. Start learning/active mode in Dashboard (`Endpoints` tab).
2. Verify agent is running.

Windows:

```powershell
.\status.cmd
Get-Content "C:\ProgramData\RevenixAgent\logs\agent-supervisor.log" -Tail 80
```

Linux:

```bash
docker ps --filter name=revenix-core-agent
docker logs --tail 80 revenix-core-agent
```

3. Verify client connectivity to main host ports `8000` and `6379`.
4. Verify `REDIS_PASSWORD` and `INTERNAL_SERVICE_TOKEN` in client `agent.env` match main host exactly.
5. Generate traffic from client (`ping`, `curl`, browsing) and watch the dashboard.

 
