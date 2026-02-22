#!/usr/bin/env python3
import argparse
import os
import platform
import shutil
import subprocess
import sys


WINDOWS_BASE_SERVICES = ["postgres", "redis", "api", "brain", "dashboard"]
WINDOWS_SKIPPED_SERVICES = ["core", "prometheus", "grafana"]


def run(cmd, cwd):
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def get_task_status(task_name):
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", task_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 0:
        return "exists"

    msg = f"{result.stdout}\n{result.stderr}".lower()
    if "access is denied" in msg:
        return "access_denied"
    if "cannot find" in msg or "system cannot find the file specified" in msg:
        return "missing"
    return "missing"


def sync_windows_agent_bundle(repo_root):
    """
    Keep dist/windows-agent scripts synced with repo templates.
    """
    bundle_dir = os.path.join(repo_root, "core", "dist", "windows-agent")
    src_dir = os.path.join(repo_root, "agents", "windows")
    if not os.path.isdir(bundle_dir) or not os.path.isdir(src_dir):
        return

    files_to_sync = [
        "bootstrap-install.ps1",
        "install-agent.ps1",
        "start-agent.ps1",
        "firewall-sync.ps1",
        "uninstall-agent.ps1",
        "install.cmd",
        "uninstall.cmd",
        "agent.env.example",
        "README.md",
    ]

    for filename in files_to_sync:
        src = os.path.join(src_dir, filename)
        dst = os.path.join(bundle_dir, filename)
        if os.path.isfile(src):
            shutil.copyfile(src, dst)


def update_env_with_defaults(env_path):
    if not os.path.isfile(env_path):
        return False

    with open(env_path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    kv = {}
    for line in lines:
        if not line or line.strip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        kv[key.strip()] = value.strip()

    changed = False
    if "INTERNAL_SERVICE_TOKEN" not in kv:
        kv["INTERNAL_SERVICE_TOKEN"] = "CHANGE_ME_INTERNAL_TOKEN"
        changed = True
    if "API_BEARER_TOKEN" not in kv:
        kv["API_BEARER_TOKEN"] = ""
        changed = True
    if "FIREWALL_SYNC_ENABLED" not in kv:
        kv["FIREWALL_SYNC_ENABLED"] = "true"
        changed = True
    if "FIREWALL_SYNC_INTERVAL" not in kv:
        kv["FIREWALL_SYNC_INTERVAL"] = "30"
        changed = True
    if kv.get("REDIS_PASSWORD", "") == "":
        kv["REDIS_PASSWORD"] = "CHANGE_ME_REDIS_PASSWORD"
        changed = True
    if kv.get("REDIS_URL", "").strip() == "redis://localhost:6379":
        kv["REDIS_URL"] = "redis://:CHANGE_ME_REDIS_PASSWORD@localhost:6379"
        changed = True

    if not changed:
        return False

    key_order = [
        "API_URL",
        "REDIS_URL",
        "REDIS_PASSWORD",
        "INTERNAL_SERVICE_TOKEN",
        "API_BEARER_TOKEN",
        "NETWORK_INTERFACE",
        "PROMISCUOUS_MODE",
        "FIREWALL_SYNC_ENABLED",
        "FIREWALL_SYNC_INTERVAL",
    ]
    out_lines = []
    for key in key_order:
        if key in kv:
            out_lines.append(f"{key}={kv[key]}")
    for key, value in kv.items():
        if key not in key_order:
            out_lines.append(f"{key}={value}")

    with open(env_path, "w", encoding="ascii") as f:
        f.write("\n".join(out_lines) + "\n")
    return True


def ensure_windows_agent_env(repo_root):
    bundle_env = os.path.join(repo_root, "core", "dist", "windows-agent", "agent.env")
    if update_env_with_defaults(bundle_env):
        print("[info] Updated core/dist/windows-agent/agent.env with missing auth/firewall defaults.")

    installed_env = os.path.join("C:\\ProgramData", "RevenixAgent", "agent.env")
    if update_env_with_defaults(installed_env):
        print("[info] Updated C:\\ProgramData\\RevenixAgent\\agent.env with missing auth/firewall defaults.")


def ensure_windows_agent_installed(core_task_name, repo_root):
    status = get_task_status(core_task_name)
    if status == "exists":
        return True
    if status == "access_denied":
        print(
            f"[warn] Cannot query scheduled task '{core_task_name}' without Administrator rights. "
            "Skipping auto-install."
        )
        return False

    bundle_dir = os.path.join(repo_root, "core", "dist", "windows-agent")
    install_cmd = os.path.join(bundle_dir, "install.cmd")
    env_file = os.path.join(bundle_dir, "agent.env")
    env_example = os.path.join(bundle_dir, "agent.env.example")

    if not os.path.isfile(install_cmd):
        print(
            f"[warn] Scheduled task '{core_task_name}' was not found. "
            "Windows agent bundle is missing."
        )
        print("[hint] Build it with: cd core && .\\scripts\\build-windows-agent.ps1")
        return False

    if not os.path.isfile(env_file) and os.path.isfile(env_example):
        shutil.copyfile(env_example, env_file)
        print(
            "[warn] Created agent.env from template in core/dist/windows-agent. "
            "Update API_URL/REDIS_URL if placeholders are still present."
        )
        ensure_windows_agent_env(repo_root)

    print("[info] Scheduled task missing. Attempting Windows agent install...")
    result = subprocess.run(["cmd", "/c", "install.cmd"], cwd=bundle_dir)
    if result.returncode != 0:
        print("[warn] Agent install failed. Run this manually in Administrator PowerShell:")
        print(f"       cd {bundle_dir}")
        print("       Set-ExecutionPolicy -Scope Process Bypass -Force")
        print("       .\\install.cmd")
        return False

    return get_task_status(core_task_name) == "exists"


def start_windows_task(task_name):
    status = get_task_status(task_name)
    if status == "missing":
        print(f"[info] Scheduled task '{task_name}' not found.")
        return
    if status == "access_denied":
        print(
            f"[warn] Access denied while checking/running '{task_name}'. "
            "Open terminal as Administrator to manage scheduled tasks."
        )
        return

    result = subprocess.run(["schtasks", "/Run", "/TN", task_name])
    if result.returncode == 0:
        print(f"[ok] Started Windows agent task: {task_name}")
    else:
        print(
            f"[warn] Could not start scheduled task '{task_name}'. "
            "Try running terminal as Administrator."
        )


def start_windows_agent(core_task_name, firewall_task_name, repo_root):
    if not ensure_windows_agent_installed(core_task_name, repo_root):
        return

    start_windows_task(core_task_name)
    start_windows_task(firewall_task_name)


def print_windows_hints():
    print(
        "[hint] Core captures traffic only in learning/active phase.\n"
        "       Start learning from Dashboard -> Endpoints tab."
    )
    print(
        "[hint] If no flows appear, verify these in C:\\ProgramData\\RevenixAgent\\agent.env:\n"
        "       REDIS_URL=redis://:<password>@localhost:6379\n"
        "       REDIS_PASSWORD=<same password>\n"
        "       INTERNAL_SERVICE_TOKEN=<same token as API>"
    )


def main():
    parser = argparse.ArgumentParser(description="Start Revenix with OS-aware defaults.")
    parser.add_argument(
        "--task-name",
        default="RevenixCoreAgent",
        help="Windows scheduled task name for endpoint agent.",
    )
    parser.add_argument(
        "--firewall-task-name",
        default="RevenixFirewallAgent",
        help="Windows scheduled task name for firewall sync agent.",
    )
    parser.add_argument(
        "--windows-include-stats",
        action="store_true",
        help="On Windows, also start prometheus and grafana.",
    )
    args = parser.parse_args()

    if not shutil.which("docker"):
        print("docker command not found. Install/start Docker first.")
        raise SystemExit(1)

    repo_root = os.path.dirname(os.path.abspath(__file__))
    compose_file = os.path.join(repo_root, "docker-compose.yml")
    if not os.path.isfile(compose_file):
        print(f"docker-compose.yml not found in: {repo_root}")
        raise SystemExit(1)

    is_windows = platform.system().lower() == "windows"

    if is_windows:
        print(
            "Windows detected: starting docker services without core/stats, "
            "then starting Windows agent task."
        )
        sync_windows_agent_bundle(repo_root)
        ensure_windows_agent_env(repo_root)

        services = list(WINDOWS_BASE_SERVICES)
        if args.windows_include_stats:
            services.extend(["prometheus", "grafana"])

        run(["docker", "compose", "up", "-d", "--build", *services], cwd=repo_root)
        run(["docker", "compose", "stop", *WINDOWS_SKIPPED_SERVICES], cwd=repo_root)
        start_windows_agent(args.task_name, args.firewall_task_name, repo_root)
        print_windows_hints()
    else:
        print("Linux/Unix detected: starting full stack (including core).")
        run(["docker", "compose", "up", "-d", "--build"], cwd=repo_root)

    print("")
    print("Revenix start sequence complete.")
    print("Dashboard: http://localhost:3000")
    print("API docs:  http://localhost:8000/docs")


if __name__ == "__main__":
    sys.exit(main())
