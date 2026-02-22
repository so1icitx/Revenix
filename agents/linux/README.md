# Revenix Linux Agent

> Goal: distribute a small client bundle so endpoints do not clone the full repository.

## Bundle Contents

- `install.sh` (one-click installer)
- `start-agent.sh`
- `uninstall.sh`
- `agent.env.example`
- `revenix-core-image.tar` (produced by build script)
- `revenix-firewall-image.tar` (firewall sync sidecar image)

## Build Bundle (operator side)

From repository `core` folder on your build machine:

```powershell
.\scripts\build-linux-agent.ps1
```

Output:

- `core/dist/linux-agent/`
- `core/dist/revenix-linux-agent-amd64.tar.gz`

## Endpoint Install (client side)

1. Extract the bundle on the Linux endpoint.
2. Copy `agent.env.example` to `agent.env`.
3. Set:
- `API_URL=http://<main-server>:8000`
- `REDIS_URL=redis://<main-server>:6379`
- `INTERNAL_SERVICE_TOKEN=<same token as server>` (required when API internal auth is enabled)
4. Run:

```bash
sudo chmod +x install.sh start-agent.sh uninstall.sh
sudo ./install.sh
```

> If `NETWORK_INTERFACE` is blank, installer auto-selects the default route interface.

## Verify

```bash
docker ps --filter name=revenix-core-agent
docker logs -f revenix-core-agent
docker ps --filter name=revenix-firewall-agent
docker logs -f revenix-firewall-agent
```

## Update

Drop in new bundle files and run:

```bash
sudo ./install.sh
```

## Uninstall

```bash
sudo ./uninstall.sh --purge-files
```
