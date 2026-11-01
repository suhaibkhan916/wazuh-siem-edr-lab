#!/usr/bin/env python3
"""Orchestrates the Wazuh SIEM + EDR lab.

    python lab.py up         clone upstream, generate certs/config, start Wazuh, enrol the Linux agent
    python lab.py attack     run the attack scenario against the agent
    python lab.py evidence   export alerts and response evidence to evidence/
    python lab.py down       stop everything (add --volumes to also delete all stored data)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
UPSTREAM_REPO = "https://github.com/wazuh/wazuh-docker"
WAZUH_VERSION = "4.14.9"
UPSTREAM = ROOT / "upstream"
SINGLE_NODE = UPSTREAM / "single-node"
BUILD = ROOT / "build"
EVIDENCE = ROOT / "evidence"
AGENT_NAME = "lab-agent-01"

SIEM = ["docker", "compose", "-p", "single-node",
        "-f", str(SINGLE_NODE / "docker-compose.yml"), "-f", str(ROOT / "compose" / "override.yml")]
LAB = ["docker", "compose", "-f", str(ROOT / "compose" / "lab.yml")]
ENV = {**os.environ, "LAB_ROOT": ROOT.as_posix()}


def run(cmd: list[str], check: bool = True, cwd: Path | None = None, capture: bool = False) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, cwd=cwd, env=ENV, text=True, capture_output=capture)
    if check and proc.returncode != 0:
        detail = (proc.stdout or "") + (proc.stderr or "")
        sys.exit(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{detail[-1500:]}")
    return proc


def manager() -> str:
    out = run(["docker", "ps", "-q", "--filter", "label=com.docker.compose.project=single-node",
               "--filter", "label=com.docker.compose.service=wazuh.manager"], capture=True).stdout.split()
    if not out:
        sys.exit("the Wazuh manager container is not running; run `python lab.py up` first")
    return out[0]


def mexec(*cmd: str, user: str = "root", check: bool = True) -> subprocess.CompletedProcess:
    return run(["docker", "exec", "-u", user, manager(), *cmd], check=check, capture=True)


def wait_for(description: str, probe, timeout: int = 300, interval: int = 5) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if probe():
                print(f"  ready: {description}")
                return
        except SystemExit:
            pass
        time.sleep(interval)
    sys.exit(f"timed out waiting for {description}")


def manager_ready() -> bool:
    status = mexec("/var/ossec/bin/wazuh-control", "status", check=False).stdout
    return all(f"{d} is running" in status for d in ("wazuh-analysisd", "wazuh-remoted", "wazuh-authd"))


def agent_active() -> bool:
    listing = mexec("/var/ossec/bin/agent_control", "-l", check=False).stdout
    return any(AGENT_NAME in line and "Active" in line for line in listing.splitlines())


def prepare_upstream() -> None:
    if not UPSTREAM.exists():
        print(f"cloning wazuh-docker {WAZUH_VERSION}")
        run(["git", "clone", "-q", "--depth", "1", "--branch", f"v{WAZUH_VERSION}", UPSTREAM_REPO, str(UPSTREAM)])
    if not (SINGLE_NODE / "config" / "wazuh_indexer_ssl_certs" / "wazuh.manager.pem").exists():
        print("generating TLS certificates")
        run(["docker", "compose", "-f", "generate-indexer-certs.yml", "run", "--rm", "generator"], cwd=SINGLE_NODE)

    # Insert the active-response policy after upstream's commented placeholder.
    conf = (SINGLE_NODE / "config" / "wazuh_cluster" / "wazuh_manager.conf").read_text(encoding="utf-8")
    marker = "  -->\n\n  <!-- Log analysis -->"
    conf = conf.replace("\r\n", "\n")
    if marker not in conf:
        sys.exit("upstream manager config changed shape; update the marker in lab.py")
    block = (ROOT / "config" / "active-response.xml").read_text(encoding="utf-8").replace("\r\n", "\n")
    BUILD.mkdir(exist_ok=True)
    with open(BUILD / "wazuh_manager.conf", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(conf.replace(marker, "  -->\n\n" + block + "\n  <!-- Log analysis -->", 1))


def push_policy() -> None:
    mgr = manager()
    for src, dest in (("local_rules.xml", "/var/ossec/etc/rules/local_rules.xml"),
                      ("agent.conf", "/var/ossec/etc/shared/default/agent.conf")):
        run(["docker", "cp", str(ROOT / "config" / src), f"{mgr}:{dest}"])
        mexec("chown", "wazuh:wazuh", dest)
        mexec("chmod", "660", dest)
    check = mexec("/var/ossec/bin/wazuh-analysisd", "-t", check=False)
    if check.returncode != 0:
        sys.exit("manager rejected the configuration:\n" + (check.stdout + check.stderr)[-1500:])
    print("  config + local rules validated; restarting manager to load them")
    run(["docker", "restart", mgr], capture=True)


def forget_agent() -> None:
    """Remove a stale registration so a rebuilt agent can enrol under the same name."""
    listing = mexec("/var/ossec/bin/agent_control", "-l", check=False).stdout
    for line in listing.splitlines():
        if f"Name: {AGENT_NAME}" in line:
            agent_id = line.split("ID:")[1].split(",")[0].strip()
            mexec("/var/ossec/bin/manage_agents", "-r", agent_id, check=False)
            print(f"  removed stale registration for {AGENT_NAME} (id {agent_id})")


def cmd_up(_: argparse.Namespace) -> None:
    prepare_upstream()
    print("starting Wazuh manager, indexer and dashboard (first start pulls ~3 GB)")
    run([*SIEM, "up", "-d"])
    wait_for("manager services", manager_ready)
    push_policy()
    wait_for("manager services after restart", manager_ready)
    print("building and starting the Linux agent and attacker")
    forget_agent()
    run([*LAB, "up", "-d", "--build", "--force-recreate"])
    wait_for(f"agent {AGENT_NAME} Active", agent_active, timeout=240)
    out = mexec("filebeat", "test", "output", check=False)
    print("  filebeat -> indexer:", "OK" if out.returncode == 0 else "NOT OK\n" + out.stdout[-400:])
    print("\nDashboard: https://localhost:8443 (self-signed certificate; credentials are in upstream's README)")


def in_agent(script: str) -> subprocess.CompletedProcess:
    return run(["docker", "exec", "lab-agent", "bash", f"/attacks/{script}"], capture=True, check=False)


def cmd_attack(_: argparse.Namespace) -> None:
    print("1/3 SSH brute force from the attacker container")
    print(run(["docker", "exec", "lab-attacker", "bash", "/attacks/01_ssh_bruteforce.sh"], capture=True, check=False).stdout)
    time.sleep(15)
    print("2/3 persistence on the agent (new account, cron job, file tamper)")
    result = in_agent("02_persistence.sh")
    print(result.stdout, result.stderr)
    time.sleep(15)
    print("3/3 is the attacker blocked? (nc to lab-agent:22 should time out)")
    probe = run(["docker", "exec", "lab-attacker", "nc", "-zv", "-w", "4", "lab-agent", "22"], capture=True, check=False)
    print("  attacker can reach sshd:", "YES (not blocked)" if probe.returncode == 0 else "NO (blocked)")
    print("  agent iptables INPUT:")
    print(run(["docker", "exec", "lab-agent", "iptables", "-S", "INPUT"], capture=True, check=False).stdout)


def load_alerts() -> list[dict]:
    raw = mexec("cat", "/var/ossec/logs/alerts/alerts.json").stdout
    alerts = []
    for line in raw.splitlines():
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return [a for a in alerts if a.get("agent", {}).get("name") == AGENT_NAME]


def cmd_evidence(_: argparse.Namespace) -> None:
    EVIDENCE.mkdir(exist_ok=True)
    alerts = load_alerts()
    if not alerts:
        sys.exit("no alerts for the lab agent yet; run `python lab.py attack` first")

    rules: OrderedDict[str, dict] = OrderedDict()
    for a in alerts:
        r = a["rule"]
        row = rules.setdefault(r["id"], {"level": r["level"], "description": r["description"], "count": 0,
                                         "first": a["timestamp"], "mitre": ", ".join(r.get("mitre", {}).get("id", [])),
                                         "example": a})
        row["count"] += 1

    lines = ["# Alerts raised for lab-agent-01", "",
             f"{len(alerts)} alerts across {len(rules)} rules, from the manager's `alerts.json`.", "",
             "| Rule | Level | Alerts | ATT&CK | Description |", "|---:|---:|---:|---|---|"]
    for rid, row in sorted(rules.items(), key=lambda kv: (-kv[1]["level"], kv[0])):
        lines.append(f"| {rid} | {row['level']} | {row['count']} | {row['mitre'] or '-'} | {row['description']} |")
    (EVIDENCE / "alerts-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    keep = ("timestamp", "rule", "agent", "data", "syscheck", "location")
    excerpt = [{k: row["example"][k] for k in keep if k in row["example"]} for row in rules.values()]
    (EVIDENCE / "alerts-examples.json").write_text(json.dumps(excerpt, indent=2) + "\n", encoding="utf-8")

    def save(name: str, cmd: list[str]) -> None:
        out = run(cmd, capture=True, check=False)
        (EVIDENCE / name).write_text((out.stdout + out.stderr).strip() + "\n", encoding="utf-8")

    save("agents.txt", ["docker", "exec", manager(), "/var/ossec/bin/agent_control", "-l"])
    save("active-responses.log", ["docker", "exec", "lab-agent", "cat", "/var/ossec/logs/active-responses.log"])
    save("agent-iptables.txt", ["docker", "exec", "lab-agent", "iptables", "-S", "INPUT"])
    print(f"wrote evidence for {len(alerts)} alerts / {len(rules)} rules to {EVIDENCE}")
    print("\n".join(lines[5:]))


def cmd_down(args: argparse.Namespace) -> None:
    flags = ["-v"] if args.volumes else []
    run([*LAB, "down", *flags])
    run([*SIEM, "down", *flags])


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("up").set_defaults(fn=cmd_up)
    sub.add_parser("attack").set_defaults(fn=cmd_attack)
    sub.add_parser("evidence").set_defaults(fn=cmd_evidence)
    d = sub.add_parser("down")
    d.add_argument("--volumes", action="store_true", help="also delete indexed data and generated state")
    d.set_defaults(fn=cmd_down)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
