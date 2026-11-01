# wazuh-siem-edr-lab

A containerised SOC lab: a **SIEM** (Wazuh manager, indexer and dashboard), an **endpoint agent** doing EDR-style detection and response on a Linux host, and an **attacker container**. One script builds it, runs two attacks, and exports the evidence.

```bash
python lab.py up         # build the stack and enrol the agent
python lab.py attack     # SSH brute force, then persistence
python lab.py evidence   # export alerts and response evidence to evidence/
python lab.py down --volumes
```

## What it demonstrates

The run in [`evidence/`](evidence) caught both attacks, and the brute force was blocked automatically.

| Attack | ATT&CK | What fired | Response |
|---|---|---|---|
| SSH password guessing, 20 attempts with hydra | T1110.001 | Rule 5760 (x7), 5763 brute force (level 10), 2502 | `firewall-drop` added `-A INPUT -s 172.19.0.6/32 -j DROP`; a later connection to port 22 timed out |
| New local account `svc_backup` | T1136 | Rules 5902, 5901 (level 8) | - |
| File dropped in `/etc/cron.d` | T1053.003 | **Custom rule 100100** (level 12) | - |
| Change to a file in a monitored directory | - | Rules 554, 550 from real-time file integrity monitoring | - |

From the first failed-login alert (16:26:12) to the firewall action (16:26:16) was about four seconds. A ticket-style write-up of the run is in [`docs/investigation.md`](docs/investigation.md).

## Architecture

```
attacker (hydra) ---ssh---> lab-agent-01 (sshd, rsyslog, Wazuh agent, iptables)
                                 |  events: auth.log, file integrity
                                 v
                           wazuh.manager  --alerts--> Filebeat --> wazuh.indexer --> wazuh.dashboard
                                 |
                                 +--- active response: firewall-drop on the agent
```

- **SIEM:** the official [wazuh-docker](https://github.com/wazuh/wazuh-docker) single-node stack, pinned to release 4.14.9 and cloned at run time rather than copied into this repo. A compose override publishes ports on `127.0.0.1` only.
- **Endpoint:** an Ubuntu 22.04 container running sshd, rsyslog and the Wazuh agent (same version as the manager).
- **Policy:** [`config/active-response.xml`](config/active-response.xml) blocks a brute-force source for 180 s; [`config/local_rules.xml`](config/local_rules.xml) adds the cron-persistence rules; [`config/agent.conf`](config/agent.conf) is pushed centrally to collect `auth.log` and monitor directories in real time.

## Requirements

Docker with Compose v2.24+, Python 3.10+, Git, roughly 8 GB of free disk and 6 GB of RAM for Docker. The first `up` pulls several GB of images.

The dashboard is at `https://localhost:8443` (self-signed certificate). Its login credentials are the upstream defaults documented in `upstream/single-node/README.md`. **Never expose this stack beyond your own machine**: it uses those default credentials.

## Problems hit while building it

The first run detected nothing about SSH, and the active response never fired. Tracing it back found three causes, now fixed in the repo:

1. **The packaged Linux agent does not collect `/var/log/auth.log`.** Its default config reads only command output and `dpkg.log`, so no sshd or `useradd` event ever reached the manager. The collection is now enabled through `agent.conf`.
2. **rsyslog could not write the log.** Ubuntu's rsyslog drops privileges to the `syslog` user, but the entrypoint had created `auth.log` as root. Log lines were silently discarded. The file is now created with the right owner.
3. **Rebuilding the agent hung on enrolment.** The manager still held the old registration under the same name. `lab.py up` now removes the stale registration first.

Also changed from upstream: its compose file publishes every port on all network interfaces; the override restricts them to loopback.

## Limits

- **Linux only, containers only.** There are no Windows endpoints, Sysmon or Event IDs in this lab.
- **Wazuh is not a full commercial EDR.** What is shown here is log-based detection, file integrity monitoring and scripted response. There is no process-tree or memory telemetry.
- **The SIEM leg is only partly verified.** The manager wrote the alerts and Filebeat's TLS connection to the indexer tested OK, but I did not log in to the dashboard to confirm the alerts are searchable there. Check it yourself: open the dashboard and filter on agent `lab-agent-01`.
- The attacks are scripted and simple (a 20-word list, one run). A tuned brute-force rule would need a threshold review against real traffic.
- The 180-second block is a demonstration value. Production blocks belong at a network boundary.

## Layout

```
lab.py            orchestrator (up / attack / evidence / down)
agent/            Ubuntu endpoint image (sshd, rsyslog, Wazuh agent)
attacker/         hydra image
attacks/          the attack scripts and wordlist
config/           active response, local rules, central agent config
compose/          overrides on top of upstream wazuh-docker
evidence/         alerts and response output from the run above
docs/             investigation.md
```

## License

MIT for this repo's files. The cloned `wazuh-docker` code is GPLv2 and is not redistributed here.
