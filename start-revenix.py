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


def task_exists(task_name):
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", task_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def ensure_windows_agent_installed(task_name, repo_root):
    if task_exists(task_name):
        return True

    bundle_dir = os.path.join(repo_root, "core", "dist", "windows-agent")
    install_cmd = os.path.join(bundle_dir, "install.cmd")
    env_file = os.path.join(bundle_dir, "agent.env")
    env_example = os.path.join(bundle_dir, "agent.env.example")

    if not os.path.isfile(install_cmd):
        print(
            f"[warn] Scheduled task '{task_name}' was not found. "
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

    print("[info] Scheduled task missing. Attempting Windows agent install...")
    result = subprocess.run(["cmd", "/c", "install.cmd"], cwd=bundle_dir)
    if result.returncode != 0:
        print(
            "[warn] Agent install failed. Run this manually in Administrator PowerShell:"
        )
        print(f"       cd {bundle_dir}")
        print("       Set-ExecutionPolicy -Scope Process Bypass -Force")
        print("       .\\install.cmd")
        return False

    return task_exists(task_name)


def start_windows_agent(task_name, repo_root):
    if not ensure_windows_agent_installed(task_name, repo_root):
        return

    result = subprocess.run(["schtasks", "/Run", "/TN", task_name])
    if result.returncode == 0:
        print(f"[ok] Started Windows agent task: {task_name}")
    else:
        print(
            f"[warn] Could not start scheduled task '{task_name}'. "
            "Try running terminal as Administrator."
        )


def main():
    parser = argparse.ArgumentParser(
        description="Start Revenix with OS-aware defaults."
    )
    parser.add_argument(
        "--task-name",
        default="RevenixCoreAgent",
        help="Windows scheduled task name for endpoint agent.",
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
        services = list(WINDOWS_BASE_SERVICES)
        if args.windows_include_stats:
            services.extend(["prometheus", "grafana"])

        run(["docker", "compose", "up", "-d", "--build", *services], cwd=repo_root)
        run(["docker", "compose", "stop", *WINDOWS_SKIPPED_SERVICES], cwd=repo_root)
        start_windows_agent(args.task_name, repo_root)
    else:
        print("Linux/Unix detected: starting full stack (including core).")
        run(["docker", "compose", "up", "-d", "--build"], cwd=repo_root)

    print("")
    print("Revenix start sequence complete.")
    print("Dashboard: http://localhost:3000")
    print("API docs:  http://localhost:8000/docs")


if __name__ == "__main__":
    sys.exit(main())
